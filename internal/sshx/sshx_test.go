package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"testing"

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
	var observed string
	cb := hostKeyRecorder("", &observed)
	if err := cb("h", addr, pubA); err != nil {
		t.Fatalf("TOFU first contact rejected: %v", err)
	}
	fpA := ssh.FingerprintSHA256(pubA)
	if observed != fpA {
		t.Fatalf("observed %q, want %q", observed, fpA)
	}

	// Pinned and matching: fine.
	cb = hostKeyRecorder(fpA, &observed)
	if err := cb("h", addr, pubA); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}

	// Pinned and different: must fail with ErrHostKeyChanged.
	cb = hostKeyRecorder(fpA, &observed)
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
