package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/armtch-dev/clavis/internal/profile"
	"golang.org/x/crypto/ssh"
)

func genKey(t *testing.T) (pemBytes []byte, pub ssh.PublicKey) {
	t.Helper()
	pubk, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pubk)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), sshPub
}

func TestHostKeyRecorderPinsAndDetectsChange(t *testing.T) {
	_, pubA := genKey(t)
	_, pubB := genKey(t)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}

	// First contact: nothing pinned, any key accepted and observed.
	var observed, observedLine string
	cb := hostKeyRecorder("", &observed, &observedLine)
	if err := cb("h", addr, pubA); err != nil {
		t.Fatalf("TOFU first contact rejected: %v", err)
	}
	fpA := ssh.FingerprintSHA256(pubA)
	if observed != fpA {
		t.Fatalf("observed %q, want %q", observed, fpA)
	}
	wantLine := string(ssh.MarshalAuthorizedKey(pubA))
	if observedLine == "" || observedLine != strings.TrimSpace(wantLine) {
		t.Fatalf("observedLine = %q, want %q", observedLine, wantLine)
	}

	// Pinned and matching: fine.
	cb = hostKeyRecorder(fpA, &observed, &observedLine)
	if err := cb("h", addr, pubA); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}

	// Pinned and different: must fail with ErrHostKeyChanged.
	cb = hostKeyRecorder(fpA, &observed, &observedLine)
	err := cb("h", addr, pubB)
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("changed key error = %v, want ErrHostKeyChanged", err)
	}
}

func TestAuthMethods(t *testing.T) {
	if _, err := AuthMethods(Credentials{}); err == nil {
		t.Fatal("empty credentials accepted")
	}
	if _, err := AuthMethods(Credentials{Password: "x"}); err != nil {
		t.Fatalf("password creds rejected: %v", err)
	}
	keyPEM, _ := genKey(t)
	m, err := AuthMethods(Credentials{PrivateKey: keyPEM})
	if err != nil || len(m) != 1 {
		t.Fatalf("key creds: %v, %d methods", err, len(m))
	}
	if _, err := AuthMethods(Credentials{PrivateKey: []byte("garbage")}); err == nil {
		t.Fatal("garbage key accepted")
	}
}

func TestExternalCommandPinsKnownHosts(t *testing.T) {
	keyPEM, pub := genKey(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	p := profile.Profile{
		Name: "x", Host: "srv.example.com", Port: 2222, User: "root",
		Auth: []profile.AuthKind{profile.AuthKey}, HostKey: line,
	}
	cmd, cleanup, err := ExternalCommand(p, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "StrictHostKeyChecking=yes") || !strings.Contains(args, "UserKnownHostsFile=") {
		t.Fatalf("pinned profile not locked to known_hosts: %v", cmd.Args)
	}
	// known_hosts content must carry the [host]:port form for non-22 ports.
	var khPath string
	for _, a := range cmd.Args {
		if strings.HasPrefix(a, "UserKnownHostsFile=") {
			khPath = strings.TrimPrefix(a, "UserKnownHostsFile=")
		}
	}
	raw, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := "[srv.example.com]:2222 " + line; !strings.Contains(string(raw), want) {
		t.Fatalf("known_hosts = %q, want %q", raw, want)
	}

	// Unpinned profile: no strict pinning flags.
	p.HostKey = ""
	cmd2, cleanup2, err := ExternalCommand(p, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup2()
	if strings.Contains(strings.Join(cmd2.Args, " "), "StrictHostKeyChecking") {
		t.Fatalf("unpinned profile got strict flags: %v", cmd2.Args)
	}

	// cleanup must shred the key file and dir.
	var keyPath string
	for i, a := range cmd.Args {
		if a == "-i" {
			keyPath = cmd.Args[i+1]
		}
	}
	cleanup()
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("temp key survived cleanup")
	}
}
