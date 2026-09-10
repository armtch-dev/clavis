package sshx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func jumpServer(t *testing.T, target string, pub ssh.PublicKey) (string, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) != string(pub.Marshal()) {
			return nil, fmt.Errorf("denied")
		}
		return nil, nil
	}}
	return jumpServerWithConfig(t, target, cfg)
}

func jumpServerWithConfig(t *testing.T, target string, cfg *ssh.ServerConfig) (string, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	key, _ := genKey(t)
	signer, _ := ssh.ParsePrivateKey(key)
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	forwarded, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		sc, channels, requests, err := ssh.NewServerConn(c, cfg)
		if err != nil {
			return
		}
		defer sc.Close()
		go ssh.DiscardRequests(requests)
		for nc := range channels {
			var p struct {
				Host       string
				Port       uint32
				Origin     string
				OriginPort uint32
			}
			if nc.ChannelType() != "direct-tcpip" || ssh.Unmarshal(nc.ExtraData(), &p) != nil || net.JoinHostPort(p.Host, fmt.Sprint(p.Port)) != target {
				nc.Reject(ssh.Prohibited, "fixture only")
				continue
			}
			remote, err := net.DialTimeout("tcp", target, time.Second)
			if err != nil {
				return
			}
			defer remote.Close()
			ch, reqs, err := nc.Accept()
			if err != nil {
				return
			}
			defer ch.Close()
			go ssh.DiscardRequests(reqs)
			close(forwarded)
			copied := make(chan struct{})
			go func() { io.Copy(ch, remote); ch.Close(); close(copied) }()
			io.Copy(remote, ch)
			remote.Close()
			<-copied
		}
	}()
	return ln.Addr().String(), forwarded, done
}

func TestOpenSSHProxyJumpCancellationReapsTransport(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH unavailable")
	}
	creds, pub := encryptedCredential(t)
	creds.Password = ""
	target, _ := lifecycleServer(t, "output", pub)
	jumpKey, jumpPub := genKey(t)
	jump, forwarded, jumpDone := jumpServer(t, target, jumpPub)
	dir := t.TempDir()
	identity := filepath.Join(dir, "jump-key")
	if err := os.WriteFile(identity, jumpKey, 0600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(jump)
	config := filepath.Join(dir, "config")
	if err := os.WriteFile(config, []byte(fmt.Sprintf("Host jump\n HostName %s\n Port %s\n User fixture\n IdentityFile %s\n IdentitiesOnly yes\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n GlobalKnownHostsFile /dev/null\n", host, port, identity)), 0600); err != nil {
		t.Fatal(err)
	}
	p := profileFor(t, target)
	p.ProxyJump = "jump"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, _, cleanup, err := ExternalKeyCommandContext(ctx, p, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	cmd.Args = append(cmd.Args[:1], append([]string{"-F", config, "-o", "BatchMode=yes"}, cmd.Args[1:]...)...)
	cmd.Args = append(cmd.Args, "hang")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case <-forwarded:
	case <-time.After(2 * time.Second):
		t.Fatal("ProxyJump did not forward")
	}
	// Cancel a real OpenSSH child plus its real implicit -W helper.
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled process succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("OpenSSH child stranded")
	}
	select {
	case <-jumpDone:
	case <-time.After(time.Second):
		t.Fatal("ProxyJump helper transport stranded")
	}
	cleanup()
	for i, arg := range cmd.Args {
		if arg == "-i" {
			if _, err := os.Stat(cmd.Args[i+1]); !os.IsNotExist(err) {
				t.Fatal("temporary key survived cancellation")
			}
		}
	}
	if strings.Contains(strings.Join(cmd.Args, " "), creds.Passphrase) {
		t.Fatal("passphrase exposed in argv")
	}
}

func TestExternalPinCannotBeBypassedByAmbientTrust(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH unavailable")
	}
	creds, pub := encryptedCredential(t)
	creds.Password = ""
	addr, _ := lifecycleServer(t, "ok", pub)
	p := profileFor(t, addr)
	_, pinned := genKey(t)
	p.HostKeyFP, p.HostKey = ssh.FingerprintSHA256(pinned), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pinned)))
	config := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(config, []byte("Host *\n NoHostAuthenticationForLocalhost yes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd, _, cleanup, err := ExternalKeyCommandContext(ctx, p, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	cmd.Args = append(cmd.Args[:1], append([]string{"-F", config, "-o", "BatchMode=yes"}, cmd.Args[1:]...)...)
	cmd.Args = append(cmd.Args, "true")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	if err := cmd.Run(); err == nil {
		t.Fatal("ambient localhost exception bypassed stored host-key pin")
	}
}

func TestReviewProxyJumpMixedCredentials(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH unavailable")
	}
	for _, mode := range []string{"key", "password-fallback", "rejected-password"} {
		t.Run(mode, func(t *testing.T) {
			creds, pub := encryptedCredential(t)
			accepted := pub
			if mode == "key" {
				creds.Password = "unused-wrong-password"
			} else {
				accepted = nil
			}
			if mode == "rejected-password" {
				creds.Password = "wrong-password"
			}
			target, wantFP := lifecycleServer(t, "ok", accepted)
			jumpKey, jumpPub := genKey(t)
			jump, _, jumpDone := jumpServer(t, target, jumpPub)
			dir := t.TempDir()
			identity := filepath.Join(dir, "jump-key")
			if err := os.WriteFile(identity, jumpKey, 0600); err != nil {
				t.Fatal(err)
			}
			host, port, _ := net.SplitHostPort(jump)
			config := filepath.Join(dir, "config")
			if err := os.WriteFile(config, []byte(fmt.Sprintf("Host jump\n HostName %s\n Port %s\n User fixture\n IdentityFile %s\n IdentitiesOnly yes\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n GlobalKnownHostsFile /dev/null\n", host, port, identity)), 0600); err != nil {
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
			var stdout, stderr bytes.Buffer
			cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, &stdout, &stderr
			err = cmd.Run()
			if mode == "rejected-password" {
				if err == nil || ctx.Err() != nil {
					t.Fatalf("wrong password did not fail promptly: %v", err)
				}
			} else {
				if err != nil || stdout.String() != "clavis-ok" {
					t.Fatalf("real jump auth failed: %v stdout=%q stderr=%s", err, stdout.String(), stderr.String())
				}
				fp, line, err := ExternalHostKey(cmd)
				if err != nil || fp != wantFP || line == "" {
					t.Fatalf("actual target pin: %s %q %v", fp, line, err)
				}
			}
			for _, secret := range []string{creds.Password, creds.Passphrase} {
				if strings.Contains(strings.Join(cmd.Args, "\n"), secret) || strings.Contains(strings.Join(cmd.Env, "\n"), secret) {
					t.Fatal("credential exposed in argv/environment")
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
