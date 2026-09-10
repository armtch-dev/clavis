package sshx

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestReviewFullPublicKeyPinsAllDirectAuthenticators(t *testing.T) {
	key, pub := genKey(t)
	_, pinned := genKey(t)
	for _, mode := range []string{"session", "test", "script"} {
		t.Run(mode, func(t *testing.T) {
			addr, actual := lifecycleServer(t, "ok", pub)
			p := profileFor(t, addr)
			p.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pinned)))
			creds := Credentials{PrivateKey: key}
			var err error
			var fp string
			switch mode {
			case "session":
				client, _, observed, _, cleanup, e := openClient(context.Background(), p, creds, time.Second)
				if cleanup != nil {
					defer cleanup()
				}
				if client != nil {
					defer client.Close()
				}
				err, fp = e, observed
			case "test":
				r := Test(p, creds, time.Second)
				err, fp = r.Err, r.HostKeyFP
			case "script":
				fp, _, _, err = RunScript(p, creds, "true", io.Discard, io.Discard, time.Second)
			}
			if !errors.Is(err, ErrHostKeyChanged) || fp != actual {
				t.Fatalf("full-key pin not enforced with actual observation: fp=%q err=%v", fp, err)
			}
		})
	}
}

func TestReviewMalformedOrInconsistentPinRefusedBeforeDial(t *testing.T) {
	key, pub := genKey(t)
	for _, line := range []string{"malformed", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))} {
		p := profileFor(t, "127.0.0.1:1")
		p.HostKey, p.HostKeyFP = line, "SHA256:inconsistent"
		r := Test(p, Credentials{PrivateKey: key}, time.Second)
		if r.Stage != StageHostKey || r.Err == nil {
			t.Fatalf("pin validation lost before dial: %+v", r)
		}
	}
}

func TestReviewMatchingFullKeyOnlyPinStillAuthenticates(t *testing.T) {
	key, pub := genKey(t)
	hostKey, hostPub := genKey(t)
	addr, fp := lifecycleServerWithHost(t, "ok", pub, hostKey)
	p := profileFor(t, addr)
	p.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostPub)))
	r := Test(p, Credentials{PrivateKey: key}, time.Second)
	if !r.OK || r.HostKeyFP != fp || r.HostKeyLine != p.HostKey {
		t.Fatalf("matching full-key-only pin rejected: %+v", r)
	}
}

func TestReviewAskpassDoesNotPersistOrServeUnrelatedProcess(t *testing.T) {
	key, _ := genKey(t)
	p := profileFor(t, "127.0.0.1:22")
	p.ProxyJump = "jump"
	password := " private fallback "
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, _, cleanup, err := ExternalKeyCommandContext(ctx, p, Credentials{PrivateKey: key, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	var helper string
	for _, e := range cmd.Env {
		if value, ok := strings.CutPrefix(e, "SSH_ASKPASS="); ok {
			helper = value
		}
	}
	if helper == "" {
		t.Fatal("no supported password handoff")
	}
	dir := filepath.Dir(helper)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), password) {
				t.Fatal("fallback password persisted in a regular file")
			}
		}
	}
	// A jump helper inherits askpass and may even have the same user/hostname
	// on another port. Matching prompt text alone must not authorize a process.
	out, err := exec.Command(helper, p.User+"@"+p.Host+"'s password: ").Output()
	if err == nil || len(out) != 0 {
		t.Fatalf("unrelated process obtained target password: success=%v output bytes=%d", err == nil, len(out))
	}
	cancel()
	cleanup()
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("handoff resources survived cancellation: %v", err)
	}
}
