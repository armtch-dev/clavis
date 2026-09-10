package sshx

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestJumpAskpassProviderSurvivesTargetFallback(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH unavailable")
	}
	for _, tc := range []struct{ name, policy, targetAuth string }{
		{"baseline", "force", "key-only"},
		{"unused-target-password", "force", "key"},
		{"used-target-password", "force", "password"},
		{"original-auto-policy", "unset", "password"},
		{"original-never-policy", "never", "key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SSH_AUTH_SOCK", "")
			t.Setenv("DISPLAY", "clavis-fixture")
			creds, targetPub := encryptedCredential(t)
			if tc.targetAuth == "password" {
				targetPub = nil
			}
			if tc.targetAuth == "key-only" {
				creds.Password = ""
			} else if tc.targetAuth == "key" {
				creds.Password = "unused-target-secret"
			}
			target, wantFP := lifecycleServer(t, "ok", targetPub)
			jumpCreds, jumpPub := encryptedCredential(t)
			jump, _, jumpDone := jumpServer(t, target, jumpPub)
			// OpenSSH truncates key names in this prompt to 100 bytes. Keep the
			// synthetic key path short so the provider can match it exactly.
			dir, err := os.MkdirTemp("", "jump-auth-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			identity := filepath.Join(dir, "jump-key")
			if err := os.WriteFile(identity, jumpCreds.PrivateKey, 0600); err != nil {
				t.Fatal(err)
			}
			helper := filepath.Join(dir, "jump's askpass")
			log := filepath.Join(dir, "provider.log")
			t.Setenv("FIXTURE_JUMP_KEY", identity)
			t.Setenv("FIXTURE_ASKPASS_LOG", log)
			provider := `#!/bin/sh
printf '%s\n' "$SSH_ASKPASS" "${SSH_ASKPASS_REQUIRE-unset}" "$1" >> "$FIXTURE_ASKPASS_LOG"
case "$1" in
  "Enter passphrase for key '$FIXTURE_JUMP_KEY': ") printf '%s\n' ' stored phrase ' ;;
  *) exit 1 ;;
esac
`
			if err := os.WriteFile(helper, []byte(provider), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SSH_ASKPASS", helper)
			t.Setenv("SSH_ASKPASS_REQUIRE", tc.policy)
			if tc.policy == "unset" {
				if err := os.Unsetenv("SSH_ASKPASS_REQUIRE"); err != nil {
					t.Fatal(err)
				}
			}
			host, port, _ := net.SplitHostPort(jump)
			config := filepath.Join(dir, "config")
			if err := os.WriteFile(config, []byte(fmt.Sprintf("Host jump\n HostName %s\n Port %s\n User fixture\n IdentityFile %s\n IdentityAgent none\n IdentitiesOnly yes\n NumberOfPasswordPrompts 1\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n GlobalKnownHostsFile /dev/null\n", host, port, identity)), 0600); err != nil {
				t.Fatal(err)
			}
			p := profileFor(t, target)
			p.ProxyJump = "jump"
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd, _, cleanup, err := ExternalKeyCommandContext(ctx, p, creds)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			cmd.Args = append(cmd.Args[:1], append([]string{"-F", config}, cmd.Args[1:]...)...)
			cmd.Args = append(cmd.Args, "echo clavis-ok")
			// Guarantee no controlling TTY even when go test itself has one:
			// "never" must fail normally, while auto/force use the real provider.
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			var stdout, stderr bytes.Buffer
			cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, &stdout, &stderr
			err = cmd.Run()
			if tc.policy == "never" {
				if err == nil || ctx.Err() != nil {
					t.Fatalf("native never policy not retained: %v", err)
				}
				if _, err := os.Stat(log); !os.IsNotExist(err) {
					t.Fatal("never policy called the jump provider")
				}
			} else {
				if err != nil || stdout.String() != "clavis-ok" {
					providerLog, _ := os.ReadFile(log)
					t.Fatalf("jump credentials were displaced: %v; stdout=%q stderr=%s provider=%q", err, stdout.String(), stderr.String(), providerLog)
				}
				fp, _, err := ExternalHostKey(cmd)
				if err != nil || fp != wantFP {
					t.Fatalf("target observation: %q %v", fp, err)
				}
				data, err := os.ReadFile(log)
				if err != nil {
					t.Fatal(err)
				}
				want := helper + "\n" + tc.policy + "\nEnter passphrase for key '" + identity + "': \n"
				if string(data) != want {
					t.Fatalf("provider received altered environment or unrelated prompts: %q", data)
				}
			}
			for _, secret := range []string{creds.Password, creds.Passphrase} {
				if secret != "" && (strings.Contains(strings.Join(cmd.Args, "\n"), secret) || strings.Contains(strings.Join(cmd.Env, "\n"), secret)) {
					t.Fatal("target credential exposed in argv/environment")
				}
			}
			select {
			case <-jumpDone:
			case <-time.After(time.Second):
				t.Fatal("jump helper transport stranded")
			}
			cleanup()
			cleanup()
		})
	}
}

func TestJumpAndTargetPasswordsRemainSeparate(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	creds, _ := encryptedCredential(t)
	target, wantFP := lifecycleServer(t, "ok", nil) // reject target key, accept its password
	seen := make(chan string, 4)
	jump, _, jumpDone := jumpServerWithConfig(t, target, &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			seen <- string(password)
			if string(password) != " jump secret " {
				return nil, fmt.Errorf("wrong jump credential")
			}
			return nil, nil
		},
	})
	dir := t.TempDir()
	helper, log := filepath.Join(dir, "jump-askpass"), filepath.Join(dir, "prompts")
	t.Setenv("FIXTURE_ASKPASS_LOG", log)
	// The jump and target deliberately produce identical user/host prompts;
	// they differ only by port, which OpenSSH omits from password prompts.
	provider := `#!/bin/sh
printf '%s\n' "$1" >> "$FIXTURE_ASKPASS_LOG"
case "$1" in
  "root@127.0.0.1's password: ") printf '%s\n' ' jump secret ' ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(helper, []byte(provider), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_ASKPASS", helper)
	t.Setenv("SSH_ASKPASS_REQUIRE", "force")
	host, port, _ := net.SplitHostPort(jump)
	config := filepath.Join(dir, "config")
	if err := os.WriteFile(config, []byte(fmt.Sprintf("Host jump\n HostName %s\n Port %s\n User root\n IdentityFile none\n IdentityAgent none\n PubkeyAuthentication no\n PreferredAuthentications password\n NumberOfPasswordPrompts 1\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n GlobalKnownHostsFile /dev/null\n", host, port)), 0600); err != nil {
		t.Fatal(err)
	}
	p := profileFor(t, target)
	p.ProxyJump = "jump"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd, _, cleanup, err := ExternalKeyCommandContext(ctx, p, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	cmd.Args = append(cmd.Args[:1], append([]string{"-F", config}, cmd.Args[1:]...)...)
	cmd.Args = append(cmd.Args, "echo clavis-ok")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, &stdout, &stderr
	if err := cmd.Run(); err != nil || stdout.String() != "clavis-ok" {
		t.Fatalf("separate jump/target auth: %v stdout=%q stderr=%s", err, stdout.String(), stderr.String())
	}
	select {
	case password := <-seen:
		if password != " jump secret " {
			t.Fatal("target password reached jump authentication")
		}
	default:
		t.Fatal("jump password authentication was not exercised")
	}
	if data, err := os.ReadFile(log); err != nil || string(data) != "root@127.0.0.1's password: \n" {
		t.Fatalf("original provider received non-jump prompts: %q %v", data, err)
	}
	if fp, _, err := ExternalHostKey(cmd); err != nil || fp != wantFP {
		t.Fatalf("wrong target observation %q %v", fp, err)
	}
	select {
	case <-jumpDone:
	case <-time.After(time.Second):
		t.Fatal("jump transport stranded")
	}
}
