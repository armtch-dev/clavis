package tui

import (
	"os/exec"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/config"
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
	if m.screen != scrList {
		t.Fatalf("valid key should reach the list, got screen %d (err %q)", m.screen, m.welcome.errs)
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
