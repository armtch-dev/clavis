package tui

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/fido2"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/vault"
)

func writeFakeTool(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// installFido2Fakes puts stubs of the three fido2 tools on PATH (same
// man-page-accurate shapes as the fido2 package's own tests) and returns
// their directory so tests can rewrite them.
func installFido2Fakes(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake fido2 tools are shell scripts")
	}
	dir := t.TempDir()
	writeFakeTool(t, dir, "fido2-token", `#!/bin/sh
echo "ioreg://4295231483: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)"
`)
	writeFakeTool(t, dir, "fido2-cred", `#!/bin/sh
read cdh; read rp; read name; read uid
echo "$cdh"
echo "$rp"
echo "packed"
echo "YXV0aGRhdGE="
echo "ZmFrZS1jcmVkZW50aWFsLWlk"
echo "c2lnbmF0dXJl"
echo "Y2VydGlmaWNhdGU="
`)
	writeFakeTool(t, dir, "fido2-assert", `#!/bin/sh
read cdh; read rp; read cred; read salt
echo "$cdh"
echo "$rp"
echo "YXV0aGRhdGE="
echo "c2lnbmF0dXJl"
echo "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// newLaunchModel builds a Model the way main.go does for an existing, locked
// vault. CLAVIS_KEY is pinned to a non-matching identity so ResolveIdentity
// resolves from the env and never reads the developer's real Keychain
// (which would fire a Touch ID prompt mid-test).
func newLaunchModel(t *testing.T, dir string) *Model {
	t.Helper()
	t.Setenv(vault.EnvKey, "AGE-SECRET-KEY-1WRONG")
	v, err := vault.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(dir)
	store, _ := profile.LoadStore(dir)
	idents, _ := profile.LoadIdentities(dir)
	scripts, _ := script.LoadStore(dir)
	m := New(dir, cfg, store, idents, scripts, v)
	t.Cleanup(m.Close)
	return m
}

// Launch with a security key enrolled and plugged in: the assertion starts
// by itself, and its result unlocks straight onto the list — no tab press.
func TestLaunchAutoFidoUnlock(t *testing.T) {
	installFido2Fakes(t)
	dir := t.TempDir()
	_, identity, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := fido2.Enroll(dir, identity); err != nil {
		t.Fatal(err)
	}

	m := newLaunchModel(t, dir)
	if m.screen != scrUnlock {
		t.Fatalf("locked vault should land on unlock, got screen %d", m.screen)
	}
	if !m.unlock.fidoBusy {
		t.Fatal("assertion should auto-start when enrolled and a token is present")
	}
	m.dispatch(m.fidoUnlockCmd()())
	if m.screen != scrList {
		t.Fatalf("after assertion, want list, got screen %d (err %q)", m.screen, m.unlock.errs)
	}
	if !m.vault.Unlocked() {
		t.Fatal("vault should be unlocked")
	}
}

// Enrolled but no token plugged in: today's behavior — the unlock prompt,
// nothing in flight.
func TestLaunchFidoTokenAbsent(t *testing.T) {
	fakes := installFido2Fakes(t)
	dir := t.TempDir()
	_, identity, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := fido2.Enroll(dir, identity); err != nil {
		t.Fatal(err)
	}
	writeFakeTool(t, fakes, "fido2-token", "#!/bin/sh\nexit 0\n")

	m := newLaunchModel(t, dir)
	if m.screen != scrUnlock {
		t.Fatalf("want unlock screen, got %d", m.screen)
	}
	if m.unlock.fidoBusy {
		t.Fatal("no token connected — assertion must not auto-start")
	}
}
