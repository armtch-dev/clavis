package sshx

import (
	"context"
	"errors"
	"io"
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
