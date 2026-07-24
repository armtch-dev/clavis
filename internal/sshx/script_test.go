package sshx

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/armtch-dev/clavis/internal/profile"
	"golang.org/x/crypto/ssh"
)

// testSSHServer is a one-connection sshd: password auth, one exec request.
// It echoes the exec'd command and the whole of stdin (the script) back on
// stdout, writes a marker on stderr, and exits with the given status.
func testSSHServer(t *testing.T, exitStatus uint32) (addr string) {
	t.Helper()
	hostPEM, _ := genKey(t)
	signer, err := ssh.ParsePrivateKey(hostPEM)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == "hunter2" {
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
		sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				newCh.Reject(ssh.UnknownChannelType, "no")
				continue
			}
			ch, chReqs, err := newCh.Accept()
			if err != nil {
				return
			}
			go func() {
				for req := range chReqs {
					if req.Type != "exec" {
						req.Reply(false, nil)
						continue
					}
					var payload struct{ Command string }
					ssh.Unmarshal(req.Payload, &payload)
					req.Reply(true, nil)
					stdin, _ := io.ReadAll(ch)
					fmt.Fprintf(ch, "cmd=%s\n%s", payload.Command, stdin)
					fmt.Fprint(ch.Stderr(), "stderr-marker\n")
					ch.SendRequest("exit-status", false,
						ssh.Marshal(struct{ Status uint32 }{exitStatus}))
					ch.Close()
					return
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func profileFor(t *testing.T, addr string) profile.Profile {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return profile.Profile{ID: "ptest", Name: "test", Host: host, Port: port, User: "root",
		Auth: []profile.AuthKind{profile.AuthPassword}}
}

// The headline behaviour: the script travels over stdin (never the remote
// filesystem or argv), output streams back, and the remote exit code is
// reported without being treated as a transport error.
func TestRunScriptStreamsAndReportsExit(t *testing.T) {
	addr := testSSHServer(t, 7)
	p := profileFor(t, addr)

	var out, errOut bytes.Buffer
	script := "echo hello\nuname -a\n"
	fp, line, code, err := RunScript(p, Credentials{Password: "hunter2"}, script, &out, &errOut, 5*time.Second)
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if code != 7 {
		t.Errorf("exit code = %d, want 7", code)
	}
	if fp == "" || line == "" {
		t.Error("host key not observed for TOFU pinning")
	}
	if !strings.Contains(out.String(), "cmd="+remoteShell) {
		t.Errorf("remote command wrong:\n%s", out.String())
	}
	if !strings.Contains(out.String(), script) {
		t.Errorf("script did not arrive on stdin:\n%s", out.String())
	}
	if !strings.Contains(errOut.String(), "stderr-marker") {
		t.Errorf("stderr not streamed separately: %q", errOut.String())
	}
}

func TestRunScriptRefusesProxyJumpAndBadAuth(t *testing.T) {
	p := profileFor(t, "127.0.0.1:1")
	p.ProxyJump = "user@bastion"
	if _, _, _, err := RunScript(p, Credentials{Password: "x"}, "true", io.Discard, io.Discard, time.Second); err == nil || !strings.Contains(err.Error(), "ProxyJump") {
		t.Errorf("ProxyJump not refused, err = %v", err)
	}

	addr := testSSHServer(t, 0)
	p2 := profileFor(t, addr)
	_, _, _, err := RunScript(p2, Credentials{Password: "wrong"}, "true", io.Discard, io.Discard, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Errorf("bad password: err = %v, want credentials rejection", err)
	}
}

// A pinned fingerprint that no longer matches must abort before the script
// runs — same MITM guarantee as Test/connect.
func TestRunScriptHostKeyPinMismatch(t *testing.T) {
	addr := testSSHServer(t, 0)
	p := profileFor(t, addr)
	p.HostKeyFP = "SHA256:pinned-something-else"
	_, _, _, err := RunScript(p, Credentials{Password: "hunter2"}, "true", io.Discard, io.Discard, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "host key changed") {
		t.Errorf("err = %v, want host-key-changed refusal", err)
	}
}
