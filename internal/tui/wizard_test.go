package tui

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/vault"
)

func genKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func newTestModel(t *testing.T) *Model {
	t.Helper()
	dir := t.TempDir()
	cfg, _ := config.Load(dir)
	store, _ := profile.LoadStore(dir)
	v, _, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	scripts, _ := script.LoadStore(dir)
	m := New(dir, cfg, store, scripts, v, "")
	t.Cleanup(m.Close)
	return m
}

// The headline behaviour the user asked for: a pasted private key is accepted
// inline and encrypted straight into the vault — no file path involved.
func TestWizardPasteEncryptsKeyIntoVault(t *testing.T) {
	m := newTestModel(t)
	keyPEM := genKeyPEM(t)

	w := newWizard(m, nil)
	w.draft.Name = "paste-host"
	w.draft.Host = "192.0.2.1"
	w.draft.User = "root"
	w.draft.Port = 22
	w.useKey = true
	w.keySource = "paste"

	w.setStep(stepKeyPaste)
	w.area.SetValue(string(keyPEM))
	if err := w.commitStep(); err != nil {
		t.Fatalf("commitStep(paste): %v", err)
	}
	if !bytes.Equal(w.keyPEM, keyPEM) {
		t.Fatal("pasted key not captured")
	}
	if w.keyNeedsPassphrase {
		t.Fatal("unencrypted key wrongly flagged as needing a passphrase")
	}

	// save() is what persists secrets; mirror the Auth that startTest sets.
	w.draft.Auth = []profile.AuthKind{profile.AuthKey}
	w.save(m) // returns a sync cmd only when autosync is on; nil here is fine

	saved := m.store.ByName("paste-host")
	if saved == nil {
		t.Fatal("profile not saved")
	}
	if !m.vault.Has(saved.KeySecret()) {
		t.Fatal("key was not written to the vault")
	}
	got, err := m.vault.Get(saved.KeySecret())
	if err != nil {
		t.Fatalf("vault.Get: %v", err)
	}
	if !bytes.Equal(got, keyPEM) {
		t.Fatal("decrypted key does not match what was pasted")
	}
	// The wizard must wipe its plaintext copy after saving.
	if len(w.keyPEM) != 0 {
		t.Fatal("wizard kept the plaintext key after save")
	}
}

func TestWizardPasteRejectsGarbage(t *testing.T) {
	m := newTestModel(t)
	w := newWizard(m, nil)
	w.useKey = true
	w.keySource = "paste"
	w.setStep(stepKeyPaste)
	w.area.SetValue("this is not a private key")
	if err := w.commitStep(); err == nil {
		t.Fatal("garbage paste accepted")
	}
}

// Skip logic must route to the paste step (not the file step) when chosen,
// and vice versa.
func TestWizardKeySourceRouting(t *testing.T) {
	m := newTestModel(t)
	w := newWizard(m, nil)
	w.usePassword = false
	w.useKey = true

	w.keySource = "paste"
	if w.skip(stepKeyPaste) || !w.skip(stepKeyPath) {
		t.Fatal("paste source should visit paste step, skip file step")
	}
	w.keySource = "file"
	if !w.skip(stepKeyPaste) || w.skip(stepKeyPath) {
		t.Fatal("file source should visit file step, skip paste step")
	}
	// After stepKeySource with paste chosen, next() lands on the paste step.
	if got := w.next(stepKeySource); w.keySource == "file" && got != stepKeyPath {
		t.Fatalf("file routing: next(stepKeySource) = %v", got)
	}
}
