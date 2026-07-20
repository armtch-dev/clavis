package sshx

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/armtch-dev/clavis/internal/profile"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ExternalCommand builds the system-ssh invocation for a key-auth session.
// The decrypted key is materialized into a 0600 file inside a private 0700
// temp dir; call cleanup (idempotent) the moment the session ends — it
// best-effort overwrites the key bytes before unlinking. Cleanup also runs
// on SIGINT/SIGTERM/SIGHUP so a killed clavis doesn't strand the key
// (SIGKILL cannot be caught; documented in SECURITY.md).
//
// When the profile has a pinned host key, the session is locked to it via a
// generated known_hosts file + StrictHostKeyChecking=yes, so the TOFU pin
// protects real sessions, not just tests. Unpinned profiles fall back to
// OpenSSH's own known_hosts prompting.
func ExternalCommand(p profile.Profile, keyPEM []byte) (cmd *exec.Cmd, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "clavis-*")
	if err != nil {
		return nil, nil, err
	}
	keyPath := filepath.Join(dir, "id")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}

	sig := make(chan os.Signal, 1)
	cleanup = func() {
		signal.Stop(sig)
		if raw, err := os.ReadFile(keyPath); err == nil {
			zero := make([]byte, len(raw))
			os.WriteFile(keyPath, zero, 0o600)
		}
		os.RemoveAll(dir)
	}
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		if _, ok := <-sig; ok {
			cleanup()
		}
	}()

	args := []string{
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-p", fmt.Sprintf("%d", p.Port),
	}
	if p.HostKey != "" {
		khPath := filepath.Join(dir, "known_hosts")
		if err := os.WriteFile(khPath, []byte(knownHostsLine(p)+"\n"), 0o600); err != nil {
			cleanup()
			return nil, nil, err
		}
		args = append(args,
			"-o", "UserKnownHostsFile="+khPath,
			"-o", "StrictHostKeyChecking=yes")
	}
	if p.ProxyJump != "" {
		args = append(args, "-J", p.ProxyJump)
	}
	args = append(args, fmt.Sprintf("%s@%s", p.User, p.Host))

	cmd = exec.Command("ssh", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd, cleanup, nil
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
	if p.ProxyJump != "" {
		return "", "", errors.New("password auth through a ProxyJump is not supported yet — use key auth for jump-host profiles")
	}
	var observed, observedLine string
	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: hostKeyRecorder(p.HostKeyFP, &observed, &observedLine),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", p.Addr(), cfg)
	if err != nil {
		return observed, observedLine, err
	}
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
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty(termType, h, w, modes); err != nil {
		return observed, observedLine, err
	}
	sess.Stdin, sess.Stdout, sess.Stderr = os.Stdin, os.Stdout, os.Stderr

	// Track terminal resizes for the remote PTY.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	done := make(chan struct{})
	defer func() { signal.Stop(winch); close(done) }()
	go func() {
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

	if err := sess.Shell(); err != nil {
		return observed, observedLine, err
	}
	err = sess.Wait()
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		err = nil // remote shell exited non-zero; that's a normal logout, not our error
	}
	return observed, observedLine, err
}
