package cli

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/vault"
)

func TestDoctorFreshConfigDir(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	err := Doctor(&buf, dir)
	out := buf.String()

	// A fresh dir has no vault, so doctor must report the hard failure
	// without ever trying to prompt for a key (which would block on stdin
	// in a test).
	if err == nil {
		t.Fatalf("expected Doctor to fail on an uninitialized vault, got nil; output:\n%s", out)
	}
	if !strings.Contains(out, "vault") {
		t.Errorf("expected output to mention the vault check, got:\n%s", out)
	}
	if !strings.Contains(out, "git sync not configured") {
		t.Errorf("expected an informational git-sync line, got:\n%s", out)
	}
	if strings.Contains(out, "Enter clavis master key") {
		t.Errorf("Doctor should not have prompted for a key when the vault isn't initialized:\n%s", out)
	}
}

func TestDoctorInitializedVaultUnlocksViaEnv(t *testing.T) {
	dir := t.TempDir()
	// t.TempDir()'s mode depends on the process umask; a real clavis config
	// dir is always created 0700, so pin it here for a realistic doctor run.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	v, identity, err := vault.Init(dir)
	if err != nil {
		t.Fatalf("vault.Init: %v", err)
	}
	_ = v

	t.Setenv(vault.EnvKey, identity)

	var buf bytes.Buffer
	if err := Doctor(&buf, dir); err != nil {
		t.Fatalf("Doctor returned error: %v\noutput:\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "vault initialized") {
		t.Errorf("expected vault-initialized line, got:\n%s", out)
	}
	if !strings.Contains(out, "master key resolved (env "+vault.EnvKey+")") {
		t.Errorf("expected key resolution via env to be reported, got:\n%s", out)
	}
	if !strings.Contains(out, "vault unlocked") || !strings.Contains(out, "vault integrity check") {
		t.Errorf("expected unlock + integrity checks to pass, got:\n%s", out)
	}
	if !strings.Contains(out, "all checks passed") {
		t.Errorf("expected overall success message, got:\n%s", out)
	}
}

func TestImportSSHConfigMapping(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := vault.Init(dir); err != nil {
		t.Fatalf("vault.Init: %v", err)
	}

	// A readable identity file for "withkey", a missing one for "nokey", no
	// User directive for "nouser" (must fall back to the current OS user),
	// and an explicit Port/ProxyJump for "full".
	sshDir := t.TempDir()
	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("fake-private-key-material"), 0o600); err != nil {
		t.Fatalf("writing fake key: %v", err)
	}
	missingKeyPath := filepath.Join(sshDir, "id_missing")

	configText := `
Host withkey
    HostName 10.0.0.1
    User alice
    Port 2222
    IdentityFile ` + keyPath + `

Host nokey
    HostName 10.0.0.2
    IdentityFile ` + missingKeyPath + `

Host nouser
    HostName 10.0.0.3

Host full
    HostName 10.0.0.4
    User bob
    Port 2200
    ProxyJump jumpbox
    IdentityFile ` + keyPath + `
`
	cfgPath := filepath.Join(sshDir, "config")
	if err := os.WriteFile(cfgPath, []byte(configText), 0o600); err != nil {
		t.Fatalf("writing ssh config: %v", err)
	}

	var buf bytes.Buffer
	if err := ImportSSHConfig(&buf, dir, cfgPath); err != nil {
		t.Fatalf("ImportSSHConfig: %v\noutput:\n%s", err, buf.String())
	}

	store, err := profile.LoadStore(dir)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(store.Profiles) != 4 {
		t.Fatalf("expected 4 imported profiles, got %d: %+v", len(store.Profiles), store.Profiles)
	}

	p := store.ByName("withkey")
	if p == nil {
		t.Fatal("withkey profile not found")
	}
	if p.Host != "10.0.0.1" || p.User != "alice" || p.Port != 2222 {
		t.Errorf("withkey mapping wrong: %+v", p)
	}
	if len(p.Auth) != 1 || p.Auth[0] != profile.AuthKey {
		t.Errorf("withkey should have Auth=[key], got %v", p.Auth)
	}

	v, err := vault.Load(dir)
	if err != nil {
		t.Fatalf("vault.Load: %v", err)
	}
	if !v.Has(p.KeySecret()) {
		t.Errorf("expected %s's private key to be stored in the vault", p.Name)
	}

	nokey := store.ByName("nokey")
	if nokey == nil {
		t.Fatal("nokey profile not found")
	}
	if v.Has(nokey.KeySecret()) {
		t.Errorf("nokey should NOT have a vault secret (identity file was missing)")
	}
	if !strings.Contains(buf.String(), "nokey") || !strings.Contains(buf.String(), "credential missing") {
		t.Errorf("expected a warning about nokey's missing credential, got:\n%s", buf.String())
	}

	nouser := store.ByName("nouser")
	if nouser == nil {
		t.Fatal("nouser profile not found")
	}
	wantUser := ""
	if u, err := user.Current(); err == nil {
		wantUser = u.Username
	}
	if nouser.User != wantUser {
		t.Errorf("nouser.User = %q, want fallback to current OS user %q", nouser.User, wantUser)
	}

	full := store.ByName("full")
	if full == nil {
		t.Fatal("full profile not found")
	}
	if full.Port != 2200 || full.ProxyJump != "jumpbox" || full.User != "bob" {
		t.Errorf("full mapping wrong: %+v", full)
	}
}

func TestImportSSHConfigSkipsCollision(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := vault.Init(dir); err != nil {
		t.Fatalf("vault.Init: %v", err)
	}

	store, err := profile.LoadStore(dir)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if _, err := store.Add(profile.Profile{
		Name: "taken",
		Host: "existing.example.com",
		User: "someone",
		Auth: []profile.AuthKind{profile.AuthPassword},
	}); err != nil {
		t.Fatalf("seeding existing profile: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("saving seed store: %v", err)
	}

	sshDir := t.TempDir()
	cfgPath := filepath.Join(sshDir, "config")
	configText := "Host taken\n    HostName 10.0.0.9\n"
	if err := os.WriteFile(cfgPath, []byte(configText), 0o600); err != nil {
		t.Fatalf("writing ssh config: %v", err)
	}

	var buf bytes.Buffer
	if err := ImportSSHConfig(&buf, dir, cfgPath); err != nil {
		t.Fatalf("ImportSSHConfig: %v", err)
	}
	if !strings.Contains(buf.String(), "skipped") {
		t.Errorf("expected the colliding host to be reported as skipped, got:\n%s", buf.String())
	}

	reloaded, err := profile.LoadStore(dir)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(reloaded.Profiles) != 1 {
		t.Fatalf("expected the existing profile to be untouched (no duplicate), got %d profiles", len(reloaded.Profiles))
	}
	if reloaded.Profiles[0].Host != "existing.example.com" {
		t.Errorf("existing profile was overwritten: %+v", reloaded.Profiles[0])
	}
}

func TestPrintKeyBanner(t *testing.T) {
	var buf bytes.Buffer
	PrintKeyBanner(&buf, "AGE-SECRET-KEY-1EXAMPLE")
	out := buf.String()
	if !strings.Contains(out, "AGE-SECRET-KEY-1EXAMPLE") {
		t.Errorf("banner should contain the identity, got:\n%s", out)
	}
	if !strings.Contains(strings.ToUpper(out), "OUTSIDE THIS MACHINE") {
		t.Errorf("banner should tell the user to store the key outside this machine, got:\n%s", out)
	}
}
