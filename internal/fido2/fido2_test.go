package fido2

import (
	"encoding/json"
	"fmt"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/vault"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Deterministic 32-byte "hmac secrets" the fake fido2-assert emits.
const (
	testSecret  = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // base64("0123...def")
	wrongSecret = "V1JPTkdXUk9OR1dST05HV1JPTkdXUk9OR1dST05HISE=" // a different 32 bytes
)

func writeFake(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// setAssertFake (re)writes the fido2-assert stub. Output lines match
// fido2-assert(1) -G for a non-resident credential: client data hash, rpid,
// authenticator data, signature, hmac secret.
func setAssertFake(t *testing.T, dir, secret string) {
	writeFake(t, dir, "fido2-assert", fmt.Sprintf(`#!/bin/sh
read cdh; read rp; read cred; read salt
echo "$cdh"
echo "$rp"
echo "YXV0aGRhdGE="
echo "c2lnbmF0dXJl"
echo "%s"
`, secret))
}

// installFakes puts man-page-accurate stubs of the three fido2 tools on
// PATH and returns their directory so tests can rewrite them.
func installFakes(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake fido2 tools are shell scripts")
	}
	dir := t.TempDir()
	writeFake(t, dir, "fido2-token", `#!/bin/sh
echo "ioreg://4295231483: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)"
`)
	// Output lines match fido2-cred(1) -M: client data hash, rpid, format,
	// authenticator data, credential id, signature, certificate.
	writeFake(t, dir, "fido2-cred", `#!/bin/sh
read cdh; read rp; read name; read uid
echo "$cdh"
echo "$rp"
echo "packed"
echo "YXV0aGRhdGE="
echo "ZmFrZS1jcmVkZW50aWFsLWlk"
echo "c2lnbmF0dXJl"
echo "Y2VydGlmaWNhdGU="
`)
	setAssertFake(t, dir, testSecret)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func TestAvailable(t *testing.T) {
	installFakes(t)
	if !Available() {
		t.Fatal("Available() = false with all three tools on PATH")
	}
	t.Setenv("PATH", t.TempDir())
	if Available() {
		t.Fatal("Available() = true with an empty PATH")
	}
}

func TestEnrollUnlockRoundTrip(t *testing.T) {
	installFakes(t)
	cfg := t.TempDir()
	_, identity, err := vault.Init(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if Enrolled(cfg) {
		t.Fatal("Enrolled() = true before enrolling")
	}
	if err := Enroll(cfg, identity); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !Enrolled(cfg) {
		t.Fatal("Enrolled() = false after enrolling")
	}

	raw, err := os.ReadFile(filepath.Join(cfg, "local", "fido2.json"))
	if err != nil {
		t.Fatalf("fido2.json: %v", err)
	}
	var m meta
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("fido2.json: %v", err)
	}
	if m.RPID != "clavis" || m.CredentialID != "ZmFrZS1jcmVkZW50aWFsLWlk" || m.Salt == "" {
		t.Fatalf("unexpected metadata: %+v", m)
	}

	for path, want := range map[string]os.FileMode{
		filepath.Join(cfg, "local"):                         0o700,
		filepath.Join(cfg, "local", "fido2.json"):           0o600,
		filepath.Join(cfg, "local", "master-key.fido2.age"): 0o600,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: perm = %o, want %o", path, fi.Mode().Perm(), want)
		}
	}

	got, err := Unlock(cfg)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got != identity {
		t.Fatalf("Unlock returned wrong identity")
	}
}

func TestUnlockWrongSecretFails(t *testing.T) {
	fakes := installFakes(t)
	cfg := t.TempDir()
	_, identity, err := vault.Init(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Enroll(cfg, identity); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// A different key (or tampered salt) yields a different hmac secret.
	setAssertFake(t, fakes, wrongSecret)
	_, err = Unlock(cfg)
	if err == nil {
		t.Fatal("Unlock succeeded with the wrong hmac secret")
	}
	for _, leak := range []string{identity, testSecret, wrongSecret} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error message leaks a secret: %v", err)
		}
	}
}

func TestRemove(t *testing.T) {
	installFakes(t)
	cfg := t.TempDir()
	_, identity, err := vault.Init(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Enroll(cfg, identity); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := Remove(cfg); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if Enrolled(cfg) {
		t.Fatal("Enrolled() = true after Remove")
	}
	if err := Remove(cfg); err != nil {
		t.Fatalf("Remove (already removed): %v", err)
	}
}

func TestPresent(t *testing.T) {
	fakes := installFakes(t)
	if !Present() {
		t.Fatal("Present() = false with a device listed")
	}
	writeFake(t, fakes, "fido2-token", "#!/bin/sh\nexit 0\n")
	if Present() {
		t.Fatal("Present() = true with no device connected")
	}
}

func TestEnrollNoDevice(t *testing.T) {
	fakes := installFakes(t)
	writeFake(t, fakes, "fido2-token", "#!/bin/sh\nexit 0\n")
	if err := Enroll(t.TempDir(), "AGE-SECRET-KEY-1TEST"); err == nil {
		t.Fatal("Enroll succeeded with no device connected")
	}
}

func TestEnrollmentCannotPublishRetiredKey(t *testing.T) {
	installFakes(t)
	dir := t.TempDir()
	v, old, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := v.PrepareRekey()
	if err != nil {
		t.Fatal(err)
	}
	if err := prep.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := Enroll(dir, old); err == nil {
		t.Fatal("stale enrollment committed")
	}
	if Enrolled(dir) {
		t.Fatal("retired identity became active")
	}
}

func TestEnrollmentPreservesLegacyEnvelopeSpelling(t *testing.T) {
	installFakes(t)
	dir := t.TempDir()
	_, key, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Enroll(dir, key); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "local", "Master-Key.FIDO2.AGE")
	if err := os.Rename(keyPath(dir), legacy); err != nil {
		t.Fatal(err)
	}
	l, err := fstxn.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	path, pathErr := envelopePathLocked(l)
	l.Close()
	if pathErr != nil || path != "local/Master-Key.FIDO2.AGE" {
		t.Fatalf("legacy path lookup: %q %v", path, pathErr)
	}
	if err := Enroll(dir, key); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "local"))
	if err != nil {
		t.Fatal(err)
	}
	var envelopes []string
	for _, e := range entries {
		if strings.EqualFold(e.Name(), "master-key.fido2.age") {
			envelopes = append(envelopes, e.Name())
		}
	}
	if len(envelopes) != 1 || envelopes[0] != "Master-Key.FIDO2.AGE" {
		t.Fatalf("alias replaced/duplicated: %v", envelopes)
	}
	if !Enrolled(dir) {
		t.Fatal("legacy enrollment absent")
	}
	if got, err := Unlock(dir); err != nil || got != key {
		t.Fatalf("legacy unlock: %v", err)
	}
}

func TestEnrollmentRechecksRecipientAfterHardwareCeremony(t *testing.T) {
	fakes := installFakes(t)
	dir := t.TempDir()
	v, key, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	ready, proceed := filepath.Join(fakes, "ready"), filepath.Join(fakes, "proceed")
	writeFake(t, fakes, "fido2-assert", fmt.Sprintf(`#!/bin/sh
read cdh; read rp; read cred; read salt
printf ready > '%s'
while [ ! -f '%s' ]; do sleep 0.01; done
printf '%%s\n' "$cdh" "$rp" YXV0aGRhdGE= c2lnbmF0dXJl '%s'
`, ready, proceed, testSecret))
	done := make(chan error, 1)
	go func() { done <- Enroll(dir, key) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ceremony did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	prep, err := v.PrepareRekey()
	if err != nil {
		t.Fatal(err)
	}
	if err := prep.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proceed, nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("enrollment published retired recipient after ceremony")
		}
	// Envelope scrypt runs after the ceremony and before the recipient check;
	// allow race-instrumented crypto to finish while retaining a bounded wait.
	case <-time.After(15 * time.Second):
		t.Fatal("enrollment did not complete within the 15-second budget")
	}
	if Enrolled(dir) {
		t.Fatal("retired enrollment active")
	}
}
