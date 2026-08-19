package tui

import (
	"os/exec"
	"runtime"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/fido2"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/vault"
)

func typeInto(t *testing.T, m *Model, s string) {
	t.Helper()
	for _, r := range s {
		m.dispatch(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
}

// The fresh-machine story end to end: source machine syncs to a bare repo,
// a nil-vault model walks welcome → restore → fetch → master-key paste, and
// comes out unlocked on the list with the source's secrets readable.
func TestWelcomeRestoreFlow(t *testing.T) {
	// Source: vault with a secret, synced to a local bare "remote".
	srcDir := t.TempDir()
	srcVault, identity, err := vault.Init(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := srcVault.Put("host.password", []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	bare := t.TempDir()
	if out, err := exec.Command("git", "init", "--bare", "-b", gitsync.DefaultBranch, bare).CombinedOutput(); err != nil {
		t.Fatalf("bare init: %v\n%s", err, out)
	}
	src := gitsync.New(srcDir, "fake-token")
	if err := src.EnsureRepo(); err != nil {
		t.Fatal(err)
	}
	if err := src.SetRemote(bare); err != nil {
		t.Fatal(err)
	}
	if err := src.Sync("initial"); err != nil {
		t.Fatal(err)
	}

	// Fresh machine: no vault → welcome screen.
	dir := t.TempDir()
	cfg, _ := config.Load(dir)
	store, _ := profile.LoadStore(dir)
	idents, _ := profile.LoadIdentities(dir)
	scripts, _ := script.LoadStore(dir)
	m := New(dir, cfg, store, idents, scripts, nil)
	t.Cleanup(m.Close)
	if m.screen != scrWelcome {
		t.Fatalf("nil vault should land on welcome, got screen %d", m.screen)
	}

	m.dispatch(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	typeInto(t, m, bare)         // repo URL
	typeInto(t, m, "fake-token") // PAT → fetch cmd fired (async in the real app)
	if !m.welcome.busy {
		t.Fatal("expected fetch in flight after token entry")
	}
	// Run the fetch synchronously and deliver its message.
	m.updateWelcome(restoreFetchedMsg{gitsync.New(dir, "fake-token").Bootstrap(bare)})
	if m.welcome.step != wKey {
		t.Fatalf("after fetch, want master-key step, got %d (err %q)", m.welcome.step, m.welcome.errs)
	}

	// Wrong key is rejected, right key unlocks.
	typeInto(t, m, "AGE-SECRET-KEY-NOT-A-REAL-KEY")
	if m.screen == scrList || m.welcome.errs == "" {
		t.Fatal("bogus key must not unlock")
	}
	typeInto(t, m, identity)
	if runtime.GOOS == "darwin" {
		// One-time Keychain offer follows the unlock; decline it here — a
		// test must never write into the developer's real Keychain.
		if m.welcome.step != wCache {
			t.Fatalf("want Keychain offer after unlock, got step %d (screen %d)", m.welcome.step, m.screen)
		}
		m.dispatch(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	}
	if m.screen != scrList {
		t.Fatalf("valid key should reach the list, got screen %d (err %q)", m.screen, m.welcome.errs)
	}
	if m.welcome.key != "" {
		t.Fatal("master key must not linger in the welcome model")
	}
	if pw, err := m.vault.Get("host.password"); err != nil || string(pw) != "hunter2" {
		t.Fatalf("restored secret: %q, %v", pw, err)
	}
	if !m.vault.HasLocal("github-token") {
		t.Fatal("PAT should be stored in local/ after restore")
	}
	if m.cfg.Sync.Remote != bare {
		t.Fatalf("remote not recorded: %q", m.cfg.Sync.Remote)
	}
}

// The per-OS branch after a restore unlock, covered for both platforms
// regardless of where the tests run.
func TestRestoreOffer(t *testing.T) {
	for _, tc := range []struct {
		goos      string
		fidoReady bool
		step      welStep
		ok        bool
	}{
		{"darwin", false, wCache, true},
		{"darwin", true, wCache, true}, // macOS offers the Keychain, never enrollment
		{"linux", true, wEnroll, true},
		{"linux", false, 0, false},
	} {
		step, ok := restoreOffer(tc.goos, tc.fidoReady)
		if ok != tc.ok || (ok && step != tc.step) {
			t.Errorf("restoreOffer(%q, %v) = (%d, %v), want (%d, %v)",
				tc.goos, tc.fidoReady, step, ok, tc.step, tc.ok)
		}
	}
}

// The enrollment offer itself is OS-independent once reached: y enrolls via
// the security key (fakes here), n skips; either way the key leaves memory
// and the flow lands on the list.
func TestWelcomeEnrollOffer(t *testing.T) {
	installFido2Fakes(t)
	dir := t.TempDir()
	v, identity, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(dir)
	store, _ := profile.LoadStore(dir)
	idents, _ := profile.LoadIdentities(dir)
	scripts, _ := script.LoadStore(dir)
	m := New(dir, cfg, store, idents, scripts, v)
	t.Cleanup(m.Close)

	// Decline: straight to the list, key dropped.
	m.welcome = &welcomeModel{step: wEnroll, key: identity, url: "repo"}
	m.screen = scrWelcome
	m.dispatch(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	if m.screen != scrList || m.welcome.key != "" {
		t.Fatalf("decline: screen %d, key kept: %v", m.screen, m.welcome.key != "")
	}

	// Accept: enrollment runs async, its completion lands on the list enrolled.
	m.welcome = &welcomeModel{step: wEnroll, key: identity, url: "repo"}
	m.screen = scrWelcome
	_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if cmd == nil || !m.welcome.busy {
		t.Fatal("accept should start the enrollment command")
	}
	m.dispatch(cmd())
	if m.screen != scrList || m.welcome.key != "" {
		t.Fatalf("after enrollment: screen %d, err %q", m.screen, m.welcome.errs)
	}
	if !fido2.Enrolled(dir) {
		t.Fatal("enrollment files should exist after accepting the offer")
	}
}
