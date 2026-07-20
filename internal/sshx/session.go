package sshx

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/armtch-dev/clavis/internal/profile"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ExternalCommand builds the system-ssh invocation for a key-auth session.
// The decrypted key is materialized into a 0600 file inside a private 0700
// temp dir; call cleanup (idempotent) the moment the session ends — it
// best-effort overwrites the key bytes before unlinking.
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
	cleanup = func() {
		if raw, err := os.ReadFile(keyPath); err == nil {
			zero := make([]byte, len(raw))
			os.WriteFile(keyPath, zero, 0o600)
		}
		os.RemoveAll(dir)
	}

	args := []string{
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-p", fmt.Sprintf("%d", p.Port),
	}
	if p.ProxyJump != "" {
		args = append(args, "-J", p.ProxyJump)
	}
	args = append(args, fmt.Sprintf("%s@%s", p.User, p.Host))

	cmd = exec.Command("ssh", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd, cleanup, nil
}

// RunPasswordSession opens a fully interactive in-process session for
// password-auth profiles (system ssh can't take a password non-interactively
// without sshpass). Returns the observed host key fingerprint for TOFU
// pinning by the caller.
func RunPasswordSession(p profile.Profile, password string) (hostKeyFP string, err error) {
	if p.ProxyJump != "" {
		return "", errors.New("password auth through a ProxyJump is not supported yet — use key auth for jump-host profiles")
	}
	var observed string
	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: hostKeyRecorder(p.HostKeyFP, &observed),
	}
	client, err := ssh.Dial("tcp", p.Addr(), cfg)
	if err != nil {
		return observed, err
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return observed, err
	}
	defer sess.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return observed, fmt.Errorf("cannot enter raw mode: %w", err)
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
		return observed, err
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
		return observed, err
	}
	err = sess.Wait()
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		err = nil // remote shell exited non-zero; that's a normal logout, not our error
	}
	return observed, err
}
