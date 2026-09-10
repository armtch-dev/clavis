package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/muesli/cancelreader"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ExternalCommand builds the system-ssh invocation for a key-auth session.
// The decrypted key is materialized into a 0600 file inside a private 0700
// temp dir; call cleanup (idempotent) the moment the session ends — it
// best-effort overwrites the key bytes before unlinking. The caller owns
// cleanup on completion/cancellation; this helper does not intercept signals.
//
// When the profile has a pinned host key, the session is locked to it via a
// generated known_hosts file + StrictHostKeyChecking=yes, so the TOFU pin
// protects real sessions, not just tests. Unpinned profiles fall back to
// OpenSSH's own known_hosts prompting.
// The returned StderrTail holds the last of ssh's diagnostic output; when the
// session ends badly the TUI's redraw wipes whatever ssh printed, so the tail
// is the only place the real reason ("Permission denied", "Connection timed
// out"…) survives to be shown in the status bar.
func ExternalCommand(p profile.Profile, keyPEM []byte) (cmd *exec.Cmd, tail *StderrTail, cleanup func(), err error) {
	if _, err := pinnedFingerprint(p); err != nil {
		return nil, nil, nil, err
	}
	dir, err := os.MkdirTemp("", "clavis-*")
	if err != nil {
		return nil, nil, nil, err
	}
	keyPath := filepath.Join(dir, "id")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, nil, nil, err
	}

	// Process signals belong to the application. Intercepting them here can
	// swallow quit (or re-sending can kill the app on an ordinary remote ^C).
	// The context-owning caller performs cleanup on cancellation and completion.
	var once sync.Once
	cleanup = func() {
		once.Do(func() {
			if raw, err := os.ReadFile(keyPath); err == nil {
				zero := make([]byte, len(raw))
				os.WriteFile(keyPath, zero, 0o600)
			}
			os.RemoveAll(dir)
		})
	}

	args := []string{
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		// The TUI preflights reachability before handing over the terminal;
		// a stall past that point should fail fast, not hang the user on a
		// blank screen for the OS's multi-minute TCP timeout.
		"-o", "ConnectTimeout=10",
		"-p", fmt.Sprintf("%d", p.Port),
	}
	if p.HostKey != "" {
		khPath := filepath.Join(dir, "known_hosts")
		if err := os.WriteFile(khPath, []byte(knownHostsLine(p)+"\n"), 0o600); err != nil {
			cleanup()
			return nil, nil, nil, err
		}
		args = append(args,
			"-o", "UserKnownHostsFile="+khPath,
			"-o", "StrictHostKeyChecking=yes",
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "KnownHostsCommand=none",
			"-o", "NoHostAuthenticationForLocalhost=no",
			"-o", "VerifyHostKeyDNS=no",
			"-o", "UpdateHostKeys=no",
			"-o", "ControlMaster=no", "-o", "ControlPath=none")
	}
	if p.ProxyJump != "" {
		args = append(args, "-J", p.ProxyJump)
	}
	args = append(args, fmt.Sprintf("%s@%s", p.User, p.Host))

	cmd = exec.Command("ssh", args...)
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "CLAVIS_") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	tail = &StderrTail{}
	cmd.Stdin, cmd.Stdout = os.Stdin, os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, tail)
	return cmd, tail, cleanup, nil
}

// StderrTail is an io.Writer that retains the last ~2KB written to it.
// Safe for concurrent use (the exec pipe writes from another goroutine).
type StderrTail struct {
	mu  sync.Mutex
	buf []byte
}

const stderrTailCap = 2048

func (t *StderrTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > stderrTailCap {
		t.buf = t.buf[len(t.buf)-stderrTailCap:]
	}
	t.mu.Unlock()
	return len(p), nil
}

// LastLine returns the final non-empty line seen, stripped of the "ssh: "
// prefix — a one-line reason suitable for a status bar.
func (t *StderrTail) LastLine() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := strings.Split(string(t.buf), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			return strings.TrimPrefix(s, "ssh: ")
		}
	}
	return ""
}

// knownHostsLine formats the pinned key the way sshd's known_hosts expects:
// bare host for port 22, [host]:port otherwise.
func knownHostsLine(p profile.Profile) string {
	host := p.Host
	if p.Port != 22 {
		host = fmt.Sprintf("[%s]:%d", p.Host, p.Port)
	}
	return host + " " + p.HostKey
}

// RunPasswordSession opens a fully interactive in-process session for
// password-auth profiles (system ssh can't take a password non-interactively
// without sshpass). Returns the observed host key fingerprint and full key
// line for TOFU pinning by the caller.
func RunPasswordSession(p profile.Profile, password string) (hostKeyFP, hostKeyLine string, err error) {
	return RunSessionContext(context.Background(), p, Credentials{Password: password}, 10*time.Second)
}

// RunSessionContext uses exactly the same credentials and pin callback as tests
// and scripts. timeout bounds setup through PTY/Shell; ctx controls shell runtime.
func RunSessionContext(ctx context.Context, p profile.Profile, creds Credentials, timeout time.Duration) (hostKeyFP, hostKeyLine string, err error) {
	if p.ProxyJump != "" {
		return "", "", errors.New("in-process auth through a ProxyJump is not supported — use key-only OpenSSH sessions")
	}
	client, conn, observed, observedLine, cleanup, err := openClient(ctx, p, creds, timeout)
	if err != nil {
		return observed, observedLine, err
	}
	defer cleanup()
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return observed, observedLine, err
	}
	defer sess.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return observed, observedLine, fmt.Errorf("cannot enter raw mode: %w", err)
	}
	defer term.Restore(fd, oldState)

	w, h, err := term.GetSize(fd)
	if err != nil {
		w, h = 80, 24
	}
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}
	// Own the input pump rather than Session.Stdin: ssh.Wait cannot interrupt
	// an os.Stdin read when the remote closes its shell.
	in, err := cancelreader.NewReader(os.Stdin)
	if err != nil {
		return observed, observedLine, err
	}
	defer in.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return observed, observedLine, err
	}
	sess.Stdout, sess.Stderr = os.Stdout, os.Stderr
	if err := startPTY(sess, termType, h, w); err != nil {
		return observed, observedLine, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return observed, observedLine, err
	}
	inputDone := make(chan struct{})
	go func() { defer close(inputDone); io.Copy(stdin, in); stdin.Close() }()
	defer func() { in.Cancel(); client.Close(); <-inputDone }()

	// Track terminal resizes for the remote PTY.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	done := make(chan struct{})
	watchDone := make(chan struct{})
	defer func() { signal.Stop(winch); close(done); client.Close(); <-watchDone }()
	go func() {
		defer close(watchDone)
		for {
			select {
			case <-winch:
				if nw, nh, err := term.GetSize(fd); err == nil {
					sess.WindowChange(nh, nw)
				}
			case <-done:
				return
			}
		}
	}()

	err = sess.Wait()
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		err = nil // remote shell exited non-zero; that's a normal logout, not our error
	}
	return observed, observedLine, err
}

func startPTY(sess *ssh.Session, termType string, h, w int) error {
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty(termType, h, w, modes); err != nil {
		return err
	}
	return sess.Shell()
}
