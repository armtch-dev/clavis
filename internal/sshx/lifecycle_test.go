package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Each fixture has an independent hard deadline so a regression cannot strand
// the test runner. The client must finish well before that deadline.
func lifecycleServer(t *testing.T, mode string, pub ssh.PublicKey) (string, string) {
	t.Helper()
	key, _ := genKey(t)
	return lifecycleServerWithHost(t, mode, pub, key)
}

func lifecycleServerWithHost(t *testing.T, mode string, pub ssh.PublicKey, key []byte) (string, string) {
	t.Helper()
	signer, _ := ssh.ParsePrivateKey(key)
	host := signer.PublicKey()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, b []byte) (*ssh.Permissions, error) {
			if mode == "auth" {
				time.Sleep(time.Second)
			}
			if string(b) == " secret " {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if pub != nil && string(k.Marshal()) == string(pub.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if mode == "banner" {
			io.Copy(io.Discard, conn)
			return
		}
		sc, channels, requests, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer sc.Close()
		go ssh.DiscardRequests(requests)
		for nc := range channels {
			if mode == "session" {
				continue
			}
			ch, reqs, err := nc.Accept()
			if err != nil {
				return
			}
			go func() {
				defer ch.Close()
				for r := range reqs {
					if mode == "exec" || mode == "pty" {
						continue
					}
					r.Reply(true, nil)
					if r.Type == "pty-req" {
						continue
					}
					if mode == "output" {
						continue
					}
					if mode == "flood" {
						for {
							if _, err := ch.Write(make([]byte, 32768)); err != nil {
								return
							}
						}
					}
					if r.Type == "exec" {
						var payload struct{ Command string }
						ssh.Unmarshal(r.Payload, &payload)
						if payload.Command == remoteShell {
							io.Copy(io.Discard, ch)
						}
					}
					fmt.Fprint(ch, "clavis-ok")
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}
			}()
		}
	}()
	return ln.Addr().String(), ssh.FingerprintSHA256(host)
}

func TestWholeLifecycleBounded(t *testing.T) {
	for _, mode := range []string{"auth", "session", "exec", "output", "flood"} {
		t.Run(mode, func(t *testing.T) {
			addr, _ := lifecycleServer(t, mode, nil)
			start := time.Now()
			r := Test(profileFor(t, addr), Credentials{Password: " secret "}, 80*time.Millisecond)
			if r.OK || r.Err == nil {
				t.Fatalf("expected bounded failure: %+v", r)
			}
			if time.Since(start) > 500*time.Millisecond {
				t.Fatalf("%s exceeded lifecycle budget: %v", mode, time.Since(start))
			}
		})
	}
}

func TestExternalCleanupDoesNotLeak(t *testing.T) {
	key, _ := genKey(t)
	before := runtime.NumGoroutine()
	for range 20 {
		_, _, cleanup, err := ExternalCommand(profileFor(t, "127.0.0.1:22"), key)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(cleanup)
		}
		wg.Wait()
	}
	time.Sleep(100 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+3 {
		t.Fatalf("cleanup leaked goroutines: %d -> %d", before, after)
	}
}

func TestContextExternalCleanupIsIdempotentOnNormalExit(t *testing.T) {
	key, _ := genKey(t)
	_, _, cleanup, err := ExternalKeyCommandContext(context.Background(), profileFor(t, "127.0.0.1:22"), Credentials{PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(cleanup)
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("normal context cleanup deadlocked on repetition")
	}
}

func encryptedCredential(t *testing.T) (Credentials, ssh.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte(" stored phrase "))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(public)
	return Credentials{PrivateKey: pem.EncodeToMemory(block), Passphrase: " stored phrase ", Password: " secret "}, pub
}

func TestSessionSetupDeadlineAndSharedCredentials(t *testing.T) {
	for _, mode := range []string{"banner", "auth", "session"} {
		t.Run(mode, func(t *testing.T) {
			addr, _ := lifecycleServer(t, mode, nil)
			start := time.Now()
			_, _, err := RunSessionContext(context.Background(), profileFor(t, addr), Credentials{Password: " secret "}, 80*time.Millisecond)
			if err == nil || time.Since(start) > 500*time.Millisecond {
				t.Fatalf("setup not bounded: %v (%v)", err, time.Since(start))
			}
		})
	}
	creds, pub := encryptedCredential(t)
	for _, fallback := range []bool{false, true} {
		accepted := pub
		if fallback {
			accepted = nil
		}
		// The same openClient used by interactive PTY setup must authenticate
		// with the encrypted key, or the stored password after key rejection.
		addr, wantFP := lifecycleServer(t, "ok", accepted)
		// This asserts successful bcrypt-protected authentication, not speed.
		// Race instrumentation under full-suite load can spend >1s parsing a key.
		client, _, fp, line, cleanup, err := openClient(context.Background(), profileFor(t, addr), creds, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if fp != wantFP || line == "" {
			t.Fatalf("actual host key missing: %s %s", fp, line)
		}
		client.Close()
		cleanup()
		addr, _ = lifecycleServer(t, "ok", accepted)
		if r := Test(profileFor(t, addr), creds, 5*time.Second); !r.OK {
			t.Fatalf("test auth: %+v", r)
		}
		addr, _ = lifecycleServer(t, "ok", accepted)
		if _, _, _, err := RunScript(profileFor(t, addr), creds, "true", io.Discard, io.Discard, 5*time.Second); err != nil {
			t.Fatalf("script auth: %v", err)
		}
	}
}

func TestCancellationUnblocksNetwork(t *testing.T) {
	for _, mode := range []string{"preflight", "test", "script", "session"} {
		t.Run(mode, func(t *testing.T) {
			serverMode := "output"
			if mode == "preflight" || mode == "session" {
				serverMode = "banner"
			}
			addr, _ := lifecycleServer(t, serverMode, nil)
			p := profileFor(t, addr)
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(80*time.Millisecond, cancel)
			defer cancel()
			start := time.Now()
			var err error
			switch mode {
			case "preflight":
				err = PreflightContext(ctx, addr, time.Minute)
			case "test":
				err = TestContext(ctx, p, Credentials{Password: " secret "}, time.Minute).Err
			case "script":
				_, _, _, err = RunScriptContext(ctx, p, Credentials{Password: " secret "}, "true", io.Discard, io.Discard, time.Minute)
			case "session":
				_, _, err = RunSessionContext(ctx, p, Credentials{Password: " secret "}, time.Minute)
			}
			if err == nil || time.Since(start) > 500*time.Millisecond {
				t.Fatalf("cancellation failed: %v (%v)", err, time.Since(start))
			}
		})
	}
}

func TestPTYSetupUsesRealSessionRequests(t *testing.T) {
	for _, mode := range []string{"ok", "pty", "exec"} {
		addr, _ := lifecycleServer(t, mode, nil)
		client, _, _, _, cleanup, err := openClient(context.Background(), profileFor(t, addr), Credentials{Password: " secret "}, 100*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		err = startPTY(sess, "xterm", 24, 80)
		if (mode == "ok") != (err == nil) || time.Since(start) > 500*time.Millisecond {
			t.Fatalf("PTY setup %s: %v", mode, err)
		}
		client.Close()
		cleanup()
	}
}

func TestExternalStoredPassphraseAndObservedPin(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH unavailable")
	}
	creds, pub := encryptedCredential(t)
	creds.Password = ""
	addr, wantFP := lifecycleServer(t, "ok", pub)
	p := profileFor(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd, _, cleanup, err := ExternalKeyCommandContext(ctx, p, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	// Explicit synthetic config: no ambient SSH options, known_hosts or keys.
	config := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(config, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cmd.Args = append(cmd.Args[:1], append([]string{"-F", config, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "GlobalKnownHostsFile=/dev/null"}, cmd.Args[1:]...)...)
	cmd.Args = append(cmd.Args, "echo clavis-ok")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	fp, line, err := ExternalHostKey(cmd)
	if err != nil || fp != wantFP || line == "" {
		t.Fatalf("actual external pin: %s %q %v", fp, line, err)
	}
}
