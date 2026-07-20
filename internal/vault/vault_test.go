package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newVault(t *testing.T) (*Vault, string, string) {
	t.Helper()
	dir := t.TempDir()
	v, key, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !strings.HasPrefix(key, "AGE-SECRET-KEY-") {
		t.Fatalf("identity has unexpected form: %q", key[:20])
	}
	return v, key, dir
}

func TestRoundTrip(t *testing.T) {
	v, _, _ := newVault(t)
	secret := []byte("hunter2\nmultiline\x00binary")
	if err := v.Put("p1.pass", secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := v.Get("p1.pass")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestLockedVaultCanWriteButNotRead(t *testing.T) {
	_, key, dir := newVault(t)
	v, err := Load(dir) // fresh load = locked
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v.Unlocked() {
		t.Fatal("freshly loaded vault should be locked")
	}
	if err := v.Put("p1.pass", []byte("s")); err != nil {
		t.Fatalf("Put while locked should work (recipient-only): %v", err)
	}
	if _, err := v.Get("p1.pass"); err != ErrLocked {
		t.Fatalf("Get while locked = %v, want ErrLocked", err)
	}
	if err := v.Unlock(key); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := v.Get("p1.pass"); err != nil {
		t.Fatalf("Get after unlock: %v", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	_, _, dir := newVault(t)
	otherV, otherKey, _ := func() (*Vault, string, string) {
		d := t.TempDir()
		v, k, err := Init(d)
		if err != nil {
			t.Fatal(err)
		}
		return v, k, d
	}()
	_ = otherV
	v, _ := Load(dir)
	if err := v.Unlock(otherKey); err != ErrWrongKey {
		t.Fatalf("Unlock with foreign key = %v, want ErrWrongKey", err)
	}
	if err := v.Unlock("AGE-SECRET-KEY-GARBAGE"); err == nil {
		t.Fatal("garbage key accepted")
	}
}

func TestCiphertextOnDiskIsAge(t *testing.T) {
	v, _, dir := newVault(t)
	if err := v.Put("p1.pass", []byte("topsecret")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "vault", "p1.pass.age"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte(AgeHeader)) {
		t.Fatalf("vault file does not start with age header")
	}
	if bytes.Contains(raw, []byte("topsecret")) {
		t.Fatal("plaintext leaked into vault file")
	}
	info, _ := os.Stat(filepath.Join(dir, "vault", "p1.pass.age"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secret perms = %v, want 0600", info.Mode().Perm())
	}
}

func TestRekey(t *testing.T) {
	v, oldKey, dir := newVault(t)
	if err := v.Put("p1.pass", []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if err := v.PutLocal("github-token", []byte("ghp_x")); err != nil {
		t.Fatal(err)
	}
	newKey, err := v.Rekey()
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if newKey == oldKey {
		t.Fatal("rekey returned same identity")
	}
	// Fresh load: old key must fail, new key must decrypt everything.
	v2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v2.Unlock(oldKey); err != ErrWrongKey {
		t.Fatalf("old key after rekey = %v, want ErrWrongKey", err)
	}
	if err := v2.Unlock(newKey); err != nil {
		t.Fatalf("new key: %v", err)
	}
	got, err := v2.Get("p1.pass")
	if err != nil || string(got) != "alpha" {
		t.Fatalf("Get after rekey = %q, %v", got, err)
	}
	tok, err := v2.GetLocal("github-token")
	if err != nil || string(tok) != "ghp_x" {
		t.Fatalf("GetLocal after rekey = %q, %v", tok, err)
	}
	if err := v2.VerifyAll(); err != nil {
		t.Fatalf("VerifyAll after rekey: %v", err)
	}
}

func TestReset(t *testing.T) {
	v, oldKey, dir := newVault(t)
	if err := v.Put("p1.pass", []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	v2, newKey, err := Reset(dir)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if newKey == oldKey {
		t.Fatal("reset kept the same identity")
	}
	if v2.Has("p1.pass") {
		t.Fatal("secret survived reset")
	}
	names, _ := v2.List()
	if len(names) != 0 {
		t.Fatalf("List after reset = %v", names)
	}
}

func TestNameValidation(t *testing.T) {
	v, _, _ := newVault(t)
	for _, bad := range []string{"../evil", "a/../b", ".hidden", "", "a/b", "..", "-flag"} {
		if err := v.Put(bad, []byte("x")); err == nil {
			t.Fatalf("Put(%q) accepted", bad)
		}
	}
	for _, good := range []string{"p1.pass", "p-2.sshkey", "github-token", "A.B_c-9"} {
		if err := v.Put(good, []byte("x")); err != nil {
			t.Fatalf("Put(%q) rejected: %v", good, err)
		}
	}
}

func TestVerifyAllDetectsCorruption(t *testing.T) {
	v, _, dir := newVault(t)
	if err := v.Put("p1.pass", []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyAll(); err != nil {
		t.Fatalf("VerifyAll clean vault: %v", err)
	}
	p := filepath.Join(dir, "vault", "p1.pass.age")
	raw, _ := os.ReadFile(p)
	raw[len(raw)-1] ^= 0xFF
	os.WriteFile(p, raw, 0o600)
	if err := v.VerifyAll(); err == nil {
		t.Fatal("VerifyAll missed corrupted blob")
	}
}

func TestFirstKeyLine(t *testing.T) {
	file := "# created: 2026-07-20\n# public key: age1xyz\nAGE-SECRET-KEY-1ABCDEF\n"
	if got := firstKeyLine(file); got != "AGE-SECRET-KEY-1ABCDEF" {
		t.Fatalf("firstKeyLine = %q", got)
	}
	if got := firstKeyLine("no key here"); got != "" {
		t.Fatalf("firstKeyLine on junk = %q", got)
	}
}
