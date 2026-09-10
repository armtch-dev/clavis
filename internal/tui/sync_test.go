package tui

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

func bareRemote(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "--bare", "-b", "main", dir).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	return dir
}

func TestFailedSaveCannotBeOverwrittenBySyncReload(t *testing.T) {
	m := newTestModel(t)
	m.cfg.Sync.Remote = bareRemote(t)
	if _, err := m.store.Add(profile.Profile{Name: "unsaved", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthKey}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(m.cfgDir, "profiles.json"), 0700); err != nil {
		t.Fatal(err)
	}
	m.saveAll("failed save")
	if cmd := m.syncCmd("manual"); cmd != nil {
		t.Fatal("sync allowed to overwrite unsaved in-memory state")
	}
	if m.store.ByName("unsaved") == nil {
		t.Fatal("unsaved local edit lost")
	}
}

func TestCloseCancelsSyncWaitingForOtherProcess(t *testing.T) {
	m := newTestModel(t)
	m.cfg.Sync.Remote = bareRemote(t)
	l, err := fstxn.Acquire(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cmd := m.syncCmd("manual")
	done := make(chan syncDoneMsg, 1)
	go func() { done <- cmd().(syncDoneMsg) }()
	m.Close()
	select {
	case msg := <-done:
		if msg.err == nil {
			t.Fatal("canceled sync succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown left sync waiting for ownership")
	}
}

func runSync(t *testing.T, m *Model) syncDoneMsg {
	t.Helper()
	cmd := m.syncCmd("test sync")
	if cmd == nil {
		t.Fatalf("no sync: %s", m.statusMsg)
	}
	msg := cmd().(syncDoneMsg)
	m.dispatch(msg)
	if msg.err != nil {
		t.Fatal(msg.err)
	}
	return msg
}

func TestSyncTwoMachinesReloadAndRecipient(t *testing.T) {
	a := newTestModel(t)
	remote := bareRemote(t)
	a.cfg.Sync.Remote = remote
	if err := a.cfg.Save(a.cfgDir); err != nil {
		t.Fatal(err)
	}
	p, err := a.store.Add(profile.Profile{Name: "local", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthKey}})
	if err != nil {
		t.Fatal(err)
	}
	localID := p.ID
	if err := a.store.Save(); err != nil {
		t.Fatal(err)
	}
	key, _ := a.vault.Identity()
	runSync(t, a)
	dir := t.TempDir()
	if err := gitsync.New(dir, "").Bootstrap(remote); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(dir)
	ps, _ := profile.LoadStore(dir)
	ids, _ := profile.LoadIdentities(dir)
	ss, _ := script.LoadStore(dir)
	v, _ := vault.Load(dir)
	if err := v.Unlock(key); err != nil {
		t.Fatal(err)
	}
	b := New(dir, cfg, ps, ids, ss, v)
	defer b.Close()
	if _, err := b.store.Add(profile.Profile{Name: "remote", Host: "127.0.0.1", Port: 2, User: "user", Auth: []profile.AuthKind{profile.AuthKey}}); err != nil {
		t.Fatal(err)
	}
	if err := b.store.Save(); err != nil {
		t.Fatal(err)
	}
	id, err := b.idents.Add(profile.Identity{Name: "remote identity", User: "user", Auth: []profile.AuthKind{profile.AuthKey}})
	if err != nil {
		t.Fatal(err)
	}
	idKey := id.KeySecret()
	if err := b.idents.Save(); err != nil {
		t.Fatal(err)
	}
	if err := b.vault.Put(idKey, []byte("synthetic SSH key")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.scripts.Add(script.Script{Name: "remote script", Content: "true"}); err != nil {
		t.Fatal(err)
	}
	if err := b.scripts.Save(); err != nil {
		t.Fatal(err)
	}
	b.cfg.Sync.AutoSync = true
	if err := b.cfg.Save(b.cfgDir); err != nil {
		t.Fatal(err)
	}
	runSync(t, b)
	a.cursor = 0
	runSync(t, a)
	if a.store.ByName("remote") == nil {
		t.Fatal("pulled profile absent from model")
	}
	if !a.vault.Unlocked() {
		t.Fatal("unchanged recipient lost unlocked identity")
	}
	if a.idents.ByName("remote identity") == nil || a.scripts.ByName("remote script") == nil || !a.cfg.Sync.AutoSync {
		t.Fatal("incomplete sync snapshot reload")
	}
	if got, err := a.vault.Get(idKey); err != nil || string(got) != "synthetic SSH key" {
		t.Fatalf("retained identity cannot decrypt pulled secret: %v", err)
	}
	a.cfg.Sync.AutoSync = false
	if err := a.cfg.Save(a.cfgDir); err != nil {
		t.Fatal(err)
	}
	if got := a.selected(a.visible()); got == nil || got.ID != localID {
		t.Fatal("selection changed")
	}
	a.store.ByID(localID).Category = "edited"
	a.saveAll("next save")
	reloaded, err := profile.LoadStore(a.cfgDir)
	if err != nil || reloaded.ByName("remote") == nil {
		t.Fatalf("next save lost remote record: %v", err)
	}
	runSync(t, a)
	runSync(t, b)
	prep, err := b.vault.PrepareRekey()
	if err != nil {
		t.Fatal(err)
	}
	newKey := prep.Key()
	if err := prep.Commit(); err != nil {
		t.Fatal(err)
	}
	runSync(t, b)
	runSync(t, a)
	if a.vault.Unlocked() || a.screen != scrUnlock {
		t.Fatal("recipient rotation did not prompt unlock")
	}
	if err := a.vault.Unlock(newKey); err != nil {
		t.Fatal(err)
	}
	if a.SyncStatus().Destination != remote || a.SyncStatus().LastSuccess.IsZero() {
		t.Fatal("missing actual sync status")
	}
}

func TestSyncCoalescesAndFreezesSaveBeforeMutation(t *testing.T) {
	m := newTestModel(t)
	m.cfg.Sync.Remote = bareRemote(t)
	if err := m.cfg.Save(m.cfgDir); err != nil {
		t.Fatal(err)
	}
	cmd := m.syncCmd("manual")
	if cmd == nil {
		t.Fatalf("%s", m.statusMsg)
	}
	l, err := fstxn.Acquire(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	doneCh := make(chan syncDoneMsg, 1)
	go func() { doneCh <- cmd().(syncDoneMsg) }()
	for i := 0; i < 10; i++ {
		if next := m.syncCmd("autosync"); next != nil {
			t.Fatal("overlapping command")
		}
	}
	m.wizard = newWizard(m, nil)
	m.screen = scrWizard
	m.wizard.draft.Name = "draft"
	m.wizard.draft.Host = "127.0.0.1"
	m.wizard.draft.User = "user"
	m.wizard.draft.Port = 22
	before := m.wizard
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlS})
	if len(m.store.Profiles) != 0 || m.wizard != before {
		t.Fatal("save mutated state while syncing")
	}
	l.Close()
	var msg syncDoneMsg
	select {
	case msg = <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("sync remained blocked")
	}
	_, next := m.dispatch(msg)
	if msg.err != nil {
		t.Fatal(msg.err)
	}
	if next == nil || !m.syncing {
		t.Fatal("coalesced follow-up not scheduled")
	}
	done := next().(syncDoneMsg)
	m.dispatch(done)
	if done.err != nil || m.syncing || m.SyncStatus().Pending {
		t.Fatalf("follow-up: %v", done.err)
	}
	if m.wizard != before || m.wizard.draft.Name != "draft" {
		t.Fatal("draft lost on completion")
	}
}

func TestUIBusyLockAndStaleSnapshotPreserveDraft(t *testing.T) {
	m := newTestModel(t)
	m.wizard = newWizard(m, nil)
	m.screen = scrWizard
	m.wizard.draft.Name = "draft"
	l, err := fstxn.Acquire(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlS})
	if time.Since(started) > 200*time.Millisecond {
		t.Fatal("UI blocked on owner")
	}
	l.Close()
	remote, _ := profile.LoadStore(m.cfgDir)
	remote.Add(profile.Profile{Name: "remote", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthKey}})
	if err := remote.Save(); err != nil {
		t.Fatal(err)
	}
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlS})
	if m.store.ByName("remote") == nil || m.wizard == nil || m.wizard.draft.Name != "draft" {
		t.Fatal("stale reload lost remote or draft")
	}
}

func TestSyncReconcilesChangedOrigin(t *testing.T) {
	m := newTestModel(t)
	first, second := bareRemote(t), bareRemote(t)
	m.cfg.Sync.Remote = first
	runSync(t, m)
	m.cfg.Sync.Remote = second
	if err := m.cfg.Save(m.cfgDir); err != nil {
		t.Fatal(err)
	}
	runSync(t, m)
	if got := gitsync.New(m.cfgDir, "").RemoteURL(); got != second {
		t.Fatalf("origin = %q", got)
	}
	if m.SyncStatus().Destination != second {
		t.Fatal("status reports wrong remote")
	}
}

func TestCredentialOnlyConcurrentEditCannotBeOverwritten(t *testing.T) {
	m := newTestModel(t)
	p, err := m.store.Add(profile.Profile{Name: "edit", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Put(p.PassSecret(), []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	m.wizard = newWizard(m, p)
	m.screen = scrWizard
	m.wizard.password = "my draft"
	other, err := vault.Load(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Put(p.PassSecret(), []byte("remote")); err != nil {
		t.Fatal(err)
	}
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlS})
	got, err := m.vault.Get(p.PassSecret())
	if err != nil || string(got) != "remote" {
		t.Fatalf("concurrent credential overwritten: %q %v", got, err)
	}
	if m.wizard == nil || m.wizard.password != "my draft" {
		t.Fatal("draft discarded on stale credential save")
	}
}

func TestRestoreWorkerReturnsCoherentSnapshot(t *testing.T) {
	a := newTestModel(t)
	remote := bareRemote(t)
	a.cfg.Sync.Remote = remote
	if err := a.cfg.Save(a.cfgDir); err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.Add(profile.Profile{Name: "restored", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthKey}}); err != nil {
		t.Fatal(err)
	}
	if err := a.store.Save(); err != nil {
		t.Fatal(err)
	}
	runSync(t, a)
	dir := t.TempDir()
	cfg, _ := config.Load(dir)
	ps, _ := profile.LoadStore(dir)
	ids, _ := profile.LoadIdentities(dir)
	ss, _ := script.LoadStore(dir)
	m := New(dir, cfg, ps, ids, ss, nil)
	defer m.Close()
	m.welcome.url = remote
	m.welcome.textStep(wToken, "token", true)
	m.welcome.input.SetValue("synthetic-token")
	_, cmd := m.welcomeKey(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("restore command missing")
	}
	result := cmd().(restoreSnapshotMsg)
	if result.err != nil {
		t.Fatal(result.err)
	}
	m.dispatch(result)
	if m.store.ByName("restored") == nil || m.cfg.Sync.Remote != remote || m.vault.Recipient() != a.vault.Recipient() || m.welcome.step != wKey {
		t.Fatal("restore returned partial state")
	}
}

func TestDiskReloadDiscardsStalePinAndFinishesTest(t *testing.T) {
	m := newTestModel(t)
	p, err := m.store.Add(profile.Profile{Name: "test", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthKey}})
	if err != nil {
		t.Fatal(err)
	}
	id := p.ID
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	m.testing[id] = true
	other, err := profile.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	other.ByID(id).Port = 2
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	m.dispatch(testDoneMsg{profileID: id, result: sshx.TestResult{OK: true, HostKeyFP: "old-endpoint-key"}})
	if m.testing[id] {
		t.Fatal("stale reload stranded pending test")
	}
	if m.store.ByID(id).HostKeyFP != "" {
		t.Fatal("stale result pinned the changed endpoint")
	}
}

func TestSyncReloadRejectsDeferredPinForPreviousEndpoint(t *testing.T) {
	m := newTestModel(t)
	p, err := m.store.Add(profile.Profile{Name: "test", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthKey}})
	if err != nil {
		t.Fatal(err)
	}
	old := *p
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	other, err := profile.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	other.ByID(old.ID).Port = 2
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	l, err := fstxn.Acquire(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadDiskLocked(l)
	l.Close()
	if err != nil {
		t.Fatal(err)
	}
	m.applyDisk(state)
	m.dispatch(testDoneMsg{profileID: old.ID, endpoint: old, result: sshx.TestResult{OK: true, HostKeyFP: "old-endpoint-key"}})
	if m.store.ByID(old.ID).HostKeyFP != "" {
		t.Fatal("deferred result pinned replacement endpoint")
	}
}

func TestRestoreDoesNotOverwriteConcurrentInitialization(t *testing.T) {
	a := newTestModel(t)
	remote := bareRemote(t)
	a.cfg.Sync.Remote = remote
	runSync(t, a)
	dir := t.TempDir()
	cfg, _ := config.Load(dir)
	ps, _ := profile.LoadStore(dir)
	ids, _ := profile.LoadIdentities(dir)
	ss, _ := script.LoadStore(dir)
	m := New(dir, cfg, ps, ids, ss, nil)
	defer m.Close()
	m.welcome.url = remote
	m.welcome.textStep(wToken, "token", true)
	m.welcome.input.SetValue("synthetic-token")
	_, cmd := m.welcomeKey(tea.KeyMsg{Type: tea.KeyEnter})
	local, _, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := cmd().(restoreSnapshotMsg)
	if result.err == nil {
		t.Fatal("stale restore replaced another process's vault")
	}
	got, err := vault.Load(dir)
	if err != nil || got.Recipient() != local.Recipient() {
		t.Fatal("concurrent initialization lost")
	}
}
