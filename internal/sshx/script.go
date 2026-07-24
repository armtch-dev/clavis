package sshx

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/armtch-dev/clavis/internal/profile"
	"golang.org/x/crypto/ssh"
)

// remoteShell prefers bash (most pasted scripts assume it) but degrades to
// POSIX sh on minimal hosts; the script itself arrives on stdin, so nothing
// is written to the remote filesystem and no quoting of the script is needed.
const remoteShell = `command -v bash >/dev/null 2>&1 && exec bash -s || exec sh -s`

// RunScript executes script on the profile's host over a fresh SSH
// connection, streaming stdout/stderr as it runs. It works for both key and
// password auth (in-process client), pins the host key like Test does, and
// returns the remote exit code: exitCode is meaningful only when err is nil.
// No PTY is requested — output stays uncooked and stderr stays separate; a
// script that needs a full terminal should be run via a normal session.
func RunScript(p profile.Profile, creds Credentials, script string, stdout, stderr io.Writer, timeout time.Duration) (hostKeyFP, hostKeyLine string, exitCode int, err error) {
	if p.ProxyJump != "" {
		return "", "", 0, errors.New("script runs through a ProxyJump are not supported yet")
	}
	methods, err := AuthMethods(creds)
	if err != nil {
		return "", "", 0, err
	}
	var observed, observedLine string
	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            methods,
		HostKeyCallback: hostKeyRecorder(p.HostKeyFP, &observed, &observedLine),
		Timeout:         timeout,
	}
	conn, err := net.DialTimeout("tcp", p.Addr(), timeout)
	if err != nil {
		return observed, observedLine, 0, errors.New(dialReason(err))
	}
	// Deadline covers the handshake only; the script itself may run as long
	// as it likes (the user is watching and can ^C the whole session).
	conn.SetDeadline(time.Now().Add(timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, p.Addr(), cfg)
	if err != nil {
		conn.Close()
		if errors.Is(err, ErrHostKeyChanged) {
			return observed, observedLine, 0, err
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return observed, observedLine, 0, errors.New("server rejected the credentials")
		}
		return observed, observedLine, 0, fmt.Errorf("SSH handshake failed: %w", err)
	}
	conn.SetDeadline(time.Time{})
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return observed, observedLine, 0, fmt.Errorf("opening a session failed: %w", err)
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(script)
	sess.Stdout, sess.Stderr = stdout, stderr

	if err := sess.Run(remoteShell); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return observed, observedLine, exitErr.ExitStatus(), nil
		}
		return observed, observedLine, 0, err
	}
	return observed, observedLine, 0, nil
}
