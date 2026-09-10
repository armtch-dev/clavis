package sshx

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/armtch-dev/clavis/internal/profile"
)

// passwordHandoff uses OpenSSH's supported askpass interface without putting the
// password in a regular file, argv, or environment. A prefilled private FIFO
// needs no writer goroutine and also cleans up when the key succeeds unused.
func passwordHandoff(cmd *exec.Cmd, dir string, p profile.Profile, password string) (func(), error) {
	// OpenSSH askpass reads a bounded, single-line C string. Refuse values it
	// would truncate instead of silently authenticating with different bytes.
	if len(password) > 1022 || strings.ContainsAny(password, "\x00\r\n") {
		return nil, errors.New("OpenSSH password fallback requires a single line of at most 1022 bytes")
	}
	if err := preserveJumpEnvironment(cmd, dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "password.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		return nil, err
	}
	fifo, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0600)
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			// Unlink before closing the writer so an askpass open can never find
			// a visible FIFO without its writer and block forever during cleanup.
			os.Remove(path)
			fifo.Close()
		})
	}
	bytes := []byte(password + "\n")
	n, err := fifo.Write(bytes)
	clear(bytes)
	if err == nil && n != len(password)+1 {
		err = io.ErrShortWrite
	}
	if err != nil {
		cleanup()
		return nil, err
	}
	// The implicit ProxyJump child inherits askpass too. Only the SSH process
	// launched directly by this process may consume it, even if a jump uses the
	// same user/host on another port. Then check the exact target password prompt.
	prompt := shellQuote(p.User + "@" + p.Host + "'s password: ")
	helper := filepath.Join(dir, "askpass")
	script := fmt.Sprintf(`#!/bin/sh
parent=$(/bin/ps -o ppid= -p "$PPID") || exit 1
[ "$parent" -eq %d ] 2>/dev/null || exit 1
case "$1" in
  %s) ;;
  *) exit 1 ;;
esac
/bin/mkdir "${0%%/*}/password.claimed" 2>/dev/null || exit 1
IFS= read -r password < "${0%%/*}/password.fifo" || exit 1
printf '%%s\n' "$password"
`, os.Getpid(), prompt)
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		cleanup()
		return nil, err
	}
	env := cmd.Env[:0]
	for _, entry := range cmd.Env {
		if !strings.HasPrefix(entry, "SSH_ASKPASS=") && !strings.HasPrefix(entry, "SSH_ASKPASS_REQUIRE=") {
			env = append(env, entry)
		}
	}
	cmd.Env = append(env, "SSH_ASKPASS="+helper, "SSH_ASKPASS_REQUIRE=force")
	cmd.Args = append(cmd.Args[:1], append([]string{
		"-o", "BatchMode=no", "-o", "PreferredAuthentications=publickey,password",
		"-o", "PasswordAuthentication=yes", "-o", "KbdInteractiveAuthentication=no",
		"-o", "NumberOfPasswordPrompts=1",
	}, cmd.Args[1:]...)...)
	return cleanup, nil
}

// OpenSSH constructs its implicit ProxyJump command using argv[0]. Give only
// those child launches a private trampoline that restores the original prompt
// environment before exec'ing the same SSH binary. The target still runs the
// real binary directly; jumps retain native askpass/TTY policy, config parsing,
// and multi-hop handling without ever inheriting the target's askpass override.
func preserveJumpEnvironment(cmd *exec.Cmd, dir string) error {
	const name = "clavis-jump-ssh"
	sshPath, err := filepath.Abs(cmd.Path)
	if err != nil {
		return err
	}
	original := make(map[string]string)
	for _, entry := range cmd.Env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			original[key] = value
		}
	}
	script := "#!/bin/sh\n"
	for _, key := range []string{"SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "PATH"} {
		if value, set := original[key]; set {
			script += "export " + key + "=" + shellQuote(value) + "\n"
		} else {
			script += "unset " + key + "\n"
		}
	}
	script += "exec " + shellQuote(sshPath) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
		return err
	}
	// A basename avoids interpolating an unquoted temporary path into the
	// native ProxyCommand string (the private directory can contain spaces).
	cmd.Args[0] = name
	env := cmd.Env[:0]
	for _, entry := range cmd.Env {
		if !strings.HasPrefix(entry, "PATH=") {
			env = append(env, entry)
		}
	}
	cmd.Env = append(env, "PATH="+dir+string(os.PathListSeparator)+original["PATH"])
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
