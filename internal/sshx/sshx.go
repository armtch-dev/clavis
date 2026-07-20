// Package sshx tests SSH connectivity/auth in-process and launches real
// sessions. Host keys are pinned on first successful contact (TOFU); a later
// mismatch is surfaced as a loud, typed error rather than a silent reconnect.
package sshx

import (
	"errors"
	"fmt"
	"net"
	"strings"
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
	methods, err := AuthMethods(creds)
	if err != nil {
		return TestResult{Stage: StageAuth, Err: err, Reason: err.Error()}
	}
	var observed, observedLine string
	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            methods,
		HostKeyCallback: hostKeyRecorder(p.HostKeyFP, &observed, &observedLine),
		Timeout:         timeout,
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", p.Addr(), timeout)
	if err != nil {
		return TestResult{Stage: StageDial, Err: err, Reason: dialReason(err)}
	}
	dialLatency := time.Since(start)
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
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
	conn.SetDeadline(time.Time{}) // hand a clean conn to the mux
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return TestResult{Stage: StageExec, HostKeyFP: observed, HostKeyLine: observedLine, Latency: dialLatency, Err: err, Reason: "authenticated, but opening a session failed: " + err.Error()}
	}
	defer sess.Close()
	out, err := sess.Output("echo clavis-ok")
	if err != nil || !strings.Contains(string(out), "clavis-ok") {
		return TestResult{Stage: StageExec, HostKeyFP: observed, HostKeyLine: observedLine, Latency: dialLatency, Err: err, Reason: "authenticated, but running a command failed"}
	}
	return TestResult{Stage: StageOK, OK: true, HostKeyFP: observed, HostKeyLine: observedLine, Latency: dialLatency, Reason: fmt.Sprintf("connected and authenticated as %s", p.User)}
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
