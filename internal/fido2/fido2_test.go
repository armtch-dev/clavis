package fido2

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
	const identity = "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST"

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
	const identity = "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST"
	if err := Enroll(cfg, identity); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// A different key (or tampered salt) yields a different hmac secret.
	setAssertFake(t, fakes, wrongSecret)
	_, err := Unlock(cfg)
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
	if err := Enroll(cfg, "AGE-SECRET-KEY-1TEST"); err != nil {
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
