// Package sshx tests SSH connectivity/auth in-process and launches real
// sessions. Host keys are pinned on first successful contact (TOFU); a later
// mismatch is surfaced as a loud, typed error rather than a silent reconnect.
package sshx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/armtch-dev/clavis/internal/profile"
	"golang.org/x/crypto/ssh"
)

// Stage identifies how far a connection test got before failing.
type Stage string

const (
	StageDial      Stage = "dial"      // TCP unreachable
	StageHostKey   Stage = "hostkey"   // pinned fingerprint mismatch (possible MITM)
	StageHandshake Stage = "handshake" // SSH protocol failure
	StageAuth      Stage = "auth"      // credentials rejected
	StageExec      Stage = "exec"      // auth OK but command failed
	StageOK        Stage = "ok"
)

type Credentials struct {
	Password   string
	PrivateKey []byte // PEM, decrypted from the vault
	Passphrase string // optional passphrase for PrivateKey
}

type TestResult struct {
	Stage       Stage
	OK          bool
	Latency     time.Duration
	HostKeyFP   string // SHA256:… fingerprint observed during the handshake
	HostKeyLine string // full public key, authorized_keys format (for pinning)
	Err         error
	Reason      string // one-line human explanation for the wizard UI
}

// ErrHostKeyChanged is wrapped into TestResult.Err when the pinned
// fingerprint no longer matches — the "someone may be intercepting" case.
var ErrHostKeyChanged = errors.New("host key changed since it was pinned")

// HostKeyFingerprint validates either stored pin representation and returns its
// effective fingerprint. Trust-review callers share the authenticator's rules.
func HostKeyFingerprint(p profile.Profile) (string, error) { return pinnedFingerprint(p) }

// Existing profiles may carry either representation of a pin. Never treat a
// full-key-only profile as unpinned when routing it to the shared authenticator.
func pinnedFingerprint(p profile.Profile) (string, error) {
	if p.HostKey == "" {
		return p.HostKeyFP, nil
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(p.HostKey))
	if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return "", errors.New("invalid stored host public key")
	}
	fp := ssh.FingerprintSHA256(key)
	if p.HostKeyFP != "" && p.HostKeyFP != fp {
		return "", errors.New("pinned host key and fingerprint disagree")
	}
	return fp, nil
}

// hostKeyRecorder pins on first use and screams on mismatch. observedLine
// receives the full public key in authorized_keys format so callers can
// persist it for strict known_hosts pinning of external sessions.
func hostKeyRecorder(pinned string, observed, observedLine *string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		*observed = fp
		if observedLine != nil {
			*observedLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		}
		if pinned != "" && pinned != fp {
			return fmt.Errorf("%w: pinned %s, server now presents %s", ErrHostKeyChanged, pinned, fp)
		}
		return nil
	}
}

// AuthMethods builds ssh.AuthMethod list from vault credentials.
func AuthMethods(creds Credentials) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if len(creds.PrivateKey) > 0 {
		signer, err := parseKey(creds.PrivateKey, creds.Passphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if creds.Password != "" {
		methods = append(methods, ssh.Password(creds.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("no credentials available for this profile")
	}
	return methods, nil
}

func parseKey(pem []byte, passphrase string) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pem)
	if err == nil {
		return signer, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == "" {
			return nil, fmt.Errorf("private key is passphrase-protected but no passphrase is stored")
		}
		return ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase))
	}
	return nil, fmt.Errorf("private key won't parse: %w", err)
}

// Test dials, handshakes, authenticates, and runs `echo` on the target.
// ProxyJump is not applied here (direct dial); the wizard says so when a
// profile has one configured.
func Test(p profile.Profile, creds Credentials, timeout time.Duration) TestResult {
	return TestContext(context.Background(), p, creds, timeout)
}

// TestContext bounds the entire dial/auth/session/exec/output lifecycle. The
// timeout is one total budget, not a fresh budget for each protocol step.
func TestContext(ctx context.Context, p profile.Profile, creds Credentials, timeout time.Duration) TestResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pinned, err := pinnedFingerprint(p)
	if err != nil {
		return TestResult{Stage: StageHostKey, Err: err, Reason: err.Error()}
	}
	methods, err := AuthMethods(creds)
	if err != nil {
		return TestResult{Stage: StageAuth, Err: err, Reason: err.Error()}
	}
	var observed, observedLine string
	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            methods,
		HostKeyCallback: hostKeyRecorder(pinned, &observed, &observedLine),
		Timeout:         timeout,
	}

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.Addr())
	if err != nil {
		return TestResult{Stage: StageDial, Err: err, Reason: dialReason(err)}
	}
	dialLatency := time.Since(start)
	defer conn.Close()
	stop := closeOnCancel(ctx, conn)
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return TestResult{Stage: StageHandshake, Err: err, Reason: err.Error()}
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, p.Addr(), cfg)
	if err != nil {
		conn.Close()
		res := TestResult{HostKeyFP: observed, HostKeyLine: observedLine, Latency: dialLatency, Err: err}
		switch {
		case errors.Is(err, ErrHostKeyChanged):
			res.Stage = StageHostKey
			res.Reason = "HOST KEY CHANGED — possible interception. Verify the server before trusting it again."
		case strings.Contains(err.Error(), "unable to authenticate"):
			res.Stage = StageAuth
			res.Reason = "server rejected the credentials (wrong password/key, or user not allowed)"
		default:
			res.Stage = StageHandshake
			res.Reason = "SSH handshake failed: " + err.Error()
		}
		return res
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return TestResult{Stage: StageExec, HostKeyFP: observed, HostKeyLine: observedLine, Latency: dialLatency, Err: err, Reason: "authenticated, but opening a session failed: " + err.Error()}
	}
	defer sess.Close()
	var out cappedOutput
	sess.Stdout, sess.Stderr = &out, io.Discard
	err = sess.Run("echo clavis-ok")
	if err == nil && !strings.Contains(string(out), "clavis-ok") {
		err = errors.New("test command did not return clavis-ok")
	}
	if err != nil {
		return TestResult{Stage: StageExec, HostKeyFP: observed, HostKeyLine: observedLine, Latency: dialLatency, Err: err, Reason: "authenticated, but running a command failed"}
	}
	return TestResult{Stage: StageOK, OK: true, HostKeyFP: observed, HostKeyLine: observedLine, Latency: dialLatency, Reason: fmt.Sprintf("connected and authenticated as %s", p.User)}
}

// Preflight verifies addr accepts TCP and answers with an SSH banner, without
// spending an auth attempt. The TUI runs this before handing the terminal to
// a real session, so a dead or rate-limited host fails fast inside the UI
// instead of leaving the user staring at a suspended screen while ssh times
// out. The client banner is sent first (as real clients do) so the server
// never logs the scanner-signature "did not receive identification string".
func Preflight(addr string, timeout time.Duration) error {
	return PreflightContext(context.Background(), addr, timeout)
}

func PreflightContext(ctx context.Context, addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return errors.New(dialReason(err))
	}
	defer conn.Close()
	stop := closeOnCancel(ctx, conn)
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	if _, err := fmt.Fprintf(conn, "SSH-2.0-clavis\r\n"); err != nil {
		return fmt.Errorf("connection dropped during banner exchange: %w", err)
	}
	// RFC 4253 §4.2 allows pre-banner lines that don't start with "SSH-".
	r := bufio.NewReader(io.LimitReader(conn, 8192))
	for i := 0; i < 20; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return errors.New("connected, but no SSH banner — service may be rate-limiting or not SSH")
		}
		if strings.HasPrefix(line, "SSH-") {
			return nil
		}
	}
	return errors.New("connected, but the service did not identify as SSH")
}

// cappedOutput retains only a small diagnostic response and rejects a flood.
type cappedOutput []byte

func (b *cappedOutput) Write(p []byte) (int, error) {
	if len(*b)+len(p) > 4096 {
		return 0, errors.New("SSH test output exceeds 4096 bytes")
	}
	*b = append(*b, p...)
	return len(p), nil
}

// Cancellation closes the transport, unblocking SSH mux requests as well as
// socket reads. The release joins a running callback before returning.
func closeOnCancel(ctx context.Context, c io.Closer) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.Close(); close(done) })
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}

// openClient leaves the setup deadline active: callers clear it only after
// NewSession and Start/Shell/PTY requests have all succeeded.
func openClient(ctx context.Context, p profile.Profile, creds Credentials, timeout time.Duration) (*ssh.Client, net.Conn, string, string, func(), error) {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	pinned, err := pinnedFingerprint(p)
	if err != nil {
		return nil, nil, "", "", nil, err
	}
	methods, err := AuthMethods(creds)
	if err != nil {
		return nil, nil, "", "", nil, err
	}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", p.Addr())
	if err != nil {
		return nil, nil, "", "", nil, err
	}
	stop := closeOnCancel(ctx, conn)
	cleanup := func() { conn.Close(); stop() }
	if err := conn.SetDeadline(deadline); err != nil {
		cleanup()
		return nil, nil, "", "", nil, err
	}
	var fp, line string
	c, chans, reqs, err := ssh.NewClientConn(conn, p.Addr(), &ssh.ClientConfig{
		User: p.User, Auth: methods, HostKeyCallback: hostKeyRecorder(pinned, &fp, &line),
	})
	if err != nil {
		cleanup()
		if strings.Contains(err.Error(), "unable to authenticate") {
			err = fmt.Errorf("server rejected the credentials: %w", err)
		}
		return nil, nil, fp, line, nil, err
	}
	return ssh.NewClient(c, chans, reqs), conn, fp, line, cleanup, nil
}

func dialReason(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS lookup failed for the host"
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "connection timed out (host down or firewalled?)"
	}
	if strings.Contains(err.Error(), "refused") {
		return "connection refused (host up, SSH port closed)"
	}
	return err.Error()
}
