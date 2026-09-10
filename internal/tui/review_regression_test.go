package tui

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

func reviewKey(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

func TestReviewStaleWizardEverySaveRoute(t *testing.T) {
	for _, route := range []string{"s", "S", "direct", "direct-without-reload"} {
		t.Run(route, func(t *testing.T) {
			m := newTestModel(t)
			p, err := m.store.Add(profile.Profile{Name: "original", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
			if err != nil {
				t.Fatal(err)
			}
			id, secret := p.ID, p.PassSecret()
			if err := m.vault.Put(secret, []byte("stored password")); err != nil {
				t.Fatal(err)
			}
			if err := m.store.Save(); err != nil {
				t.Fatal(err)
			}
			w := newWizard(m, m.store.ByID(id))
			w.step = stepTest
			w.password = "retained password draft"
			m.wizard = w
			m.screen = scrWizard
			other, err := profile.LoadStore(m.cfgDir)
			if err != nil {
				t.Fatal(err)
			}
			other.ByID(id).Host = "127.0.0.2"
			if err := other.Save(); err != nil {
				t.Fatal(err)
			}
			if route != "direct-without-reload" {
				m.dispatch(reviewKey("s"))
			}
			for i := 0; i < 2; i++ {
				if route == "direct" || route == "direct-without-reload" {
					w.save(m)
				} else {
					m.dispatch(reviewKey(route))
				}
				got, err := profile.LoadStore(m.cfgDir)
				if err != nil {
					t.Fatal(err)
				}
				if got.ByID(id).Host != "127.0.0.2" {
					t.Fatal("repeated stale save overwrote remote host")
				}
				raw, err := m.vault.Get(secret)
				if err != nil || string(raw) != "stored password" {
					t.Fatalf("stale save changed credential: %q %v", raw, err)
				}
				if m.wizard != w || w.password != "retained password draft" || w.errs == "" {
					t.Fatal("rejected draft/error was not retained")
				}
			}
		})
	}
}

func TestReviewWelcomeLockTransitions(t *testing.T) {
	which := os.Getenv("CLAVIS_REVIEW_WELCOME_CASE")
	if which == "" {
		for _, scenario := range []string{"restored", "contended"} {
			t.Run(scenario, func(t *testing.T) {
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, exe, "-test.run=^TestReviewWelcomeLockTransitions$", "-test.count=1")
				cmd.Env = append(os.Environ(), "CLAVIS_REVIEW_WELCOME_CASE="+scenario)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("welcome transition did not complete safely (context %v): %v\n%s", ctx.Err(), err, out)
				}
			})
		}
		return
	}
	if which == "restored" {
		m := newTestModel(t)
		recipient := m.vault.Recipient()
		l, err := fstxn.Acquire(m.cfgDir)
		if err != nil {
			t.Fatal(err)
		}
		state, err := loadDiskLocked(l)
		l.Close()
		if err != nil {
			t.Fatal(err)
		}
		m.vault = nil
		m.welcome = &welcomeModel{}
		m.screen = scrWelcome
		m.dispatch(restoreSnapshotMsg{state: state})
		m.welcome.input.SetValue("retained unlock draft")
		m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
		for _, key := range []string{"n", "N"} {
			m.dispatch(reviewKey(key))
			if m.vault.Recipient() != recipient || m.firstRun.identity != "" || m.welcome.input.Value() != "retained unlock draft" {
				t.Fatal("new-vault action replaced restored state or input")
			}
		}
		m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
		if m.vault.Recipient() != recipient || m.firstRun.identity != "" {
			t.Fatal("Enter replaced restored vault")
		}
		return
	}
	dir := t.TempDir()
	cfg, _ := config.Load(dir)
	ps, _ := profile.LoadStore(dir)
	ids, _ := profile.LoadIdentities(dir)
	ss, _ := script.LoadStore(dir)
	m := New(dir, cfg, ps, ids, ss, nil)
	defer m.Close()
	l, err := fstxn.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	m.dispatch(reviewKey("n"))
	if m.vault != nil || m.welcome.errs == "" {
		t.Fatal("initialization ignored held directory ownership")
	}
	l.Close()
	m.dispatch(reviewKey("n"))
	if m.vault == nil || m.screen != scrFirstRun || m.firstRun.identity == "" {
		t.Fatalf("uncontended initialization failed: %s", m.welcome.errs)
	}
}

func TestReviewStaleIdentityChoiceAndDirectSave(t *testing.T) {
	for _, route := range []string{"choice", "direct", "direct-without-reload"} {
		t.Run(route, func(t *testing.T) {
			m := newTestModel(t)
			id, err := m.idents.Add(profile.Identity{Name: "identity", User: "original", Auth: []profile.AuthKind{profile.AuthPassword}})
			if err != nil {
				t.Fatal(err)
			}
			target, secret := id.ID, id.PassSecret()
			if err := m.idents.Save(); err != nil {
				t.Fatal(err)
			}
			if err := m.vault.Put(secret, []byte("stored")); err != nil {
				t.Fatal(err)
			}
			w := newIdentityWizard(m, id)
			w.password = "retained"
			w.step = stepUseKey
			m.wizard = w
			m.screen = scrWizard
			other, err := profile.LoadIdentities(m.cfgDir)
			if err != nil {
				t.Fatal(err)
			}
			other.ByID(target).User = "remote"
			if err := other.Save(); err != nil {
				t.Fatal(err)
			}
			if route != "direct-without-reload" {
				m.dispatch(reviewKey("n"))
			}
			for i := 0; i < 2; i++ {
				if route == "choice" {
					w.step = stepUseKey
					m.dispatch(reviewKey("n"))
				} else {
					w.saveIdentity(m)
				}
				got, err := profile.LoadIdentities(m.cfgDir)
				if err != nil {
					t.Fatal(err)
				}
				if got.ByID(target).User != "remote" {
					t.Fatal("stale identity choice/save overwrote remote username")
				}
				raw, err := m.vault.Get(secret)
				if err != nil || string(raw) != "stored" {
					t.Fatal("stale identity save replaced credential")
				}
				if m.wizard != w || w.password != "retained" || w.errs == "" {
					t.Fatal("identity draft/error discarded")
				}
			}
		})
	}
}

func TestReviewDirectStaleScriptSave(t *testing.T) {
	m := newTestModel(t)
	sc, err := m.scripts.Add(script.Script{Name: "script", Content: "original"})
	if err != nil {
		t.Fatal(err)
	}
	id := sc.ID
	if err := m.scripts.Save(); err != nil {
		t.Fatal(err)
	}
	s := newScriptsManager(m)
	s.openEditor(m.scripts.ByID(id))
	s.area.SetValue("retained draft")
	m.scriptsUI = s
	m.screen = scrScripts
	other, err := script.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	other.ByID(id).Content = "remote"
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlD})
	for i := 0; i < 2; i++ {
		m.updateScriptEditor(tea.KeyMsg{Type: tea.KeyCtrlD})
	}
	got, err := script.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	if got.ByID(id).Content != "remote" || !s.editing || s.area.Value() != "retained draft" || s.errs == "" {
		t.Fatal("direct script save bypassed stale editor protection")
	}
}

func TestReviewIdentityDeleteRechecksCurrentReferences(t *testing.T) {
	for _, route := range []string{"reload-retry", "direct-stale", "direct-current"} {
		t.Run(route, func(t *testing.T) {
			m := newTestModel(t)
			id, err := m.idents.Add(profile.Identity{Name: "shared", User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
			if err != nil {
				t.Fatal(err)
			}
			target, secret := id.ID, id.PassSecret()
			if err := m.idents.Save(); err != nil {
				t.Fatal(err)
			}
			if err := m.vault.Put(secret, []byte("shared credential")); err != nil {
				t.Fatal(err)
			}
			m.identsUI = &identsModel{}
			m.screen = scrIdentities
			m.dispatch(reviewKey("d"))
			if !m.identsUI.confirmDel {
				t.Fatal("fixture did not confirm deletion")
			}
			other, err := profile.LoadStore(m.cfgDir)
			if err != nil {
				t.Fatal(err)
			}
			if route == "direct-current" {
				other = m.store
			}
			if _, err := other.Add(profile.Profile{Name: "dependent", Host: "127.0.0.1", Port: 1, IdentityID: target}); err != nil {
				t.Fatal(err)
			}
			if err := other.Save(); err != nil {
				t.Fatal(err)
			}
			if route == "reload-retry" {
				m.dispatch(reviewKey("y"))
				if m.identsUI.confirmDel {
					t.Fatal("reload retained a destructive confirmation")
				}
				m.dispatch(reviewKey("y"))
			} else {
				m.updateIdentities(reviewKey("y"))
			}
			got, err := profile.LoadIdentities(m.cfgDir)
			if err != nil {
				t.Fatal(err)
			}
			if got.ByID(target) == nil {
				t.Fatal("confirmed deletion removed a now-referenced identity")
			}
			raw, err := m.vault.Get(secret)
			if err != nil || string(raw) != "shared credential" {
				t.Fatal("referenced credential was deleted")
			}
			ps, err := profile.LoadStore(m.cfgDir)
			if err != nil || ps.ByName("dependent") == nil || ps.ByName("dependent").IdentityID != target {
				t.Fatal("new reference was lost")
			}
		})
	}
}

func TestReviewConfirmationsUseStableIDs(t *testing.T) {
	t.Run("identities", func(t *testing.T) {
		m := newTestModel(t)
		for _, name := range []string{"a-other", "z-target"} {
			if _, err := m.idents.Add(profile.Identity{Name: name, User: "user", Auth: []profile.AuthKind{profile.AuthPassword}}); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.idents.Save(); err != nil {
			t.Fatal(err)
		}
		target := m.idents.ByName("z-target").ID
		other := m.idents.ByName("a-other").ID
		m.identsUI = &identsModel{cursor: 1}
		m.screen = scrIdentities
		m.dispatch(reviewKey("d"))
		m.identsUI.cursor = 0
		m.updateIdentities(reviewKey("y"))
		if m.idents.ByID(target) != nil || m.idents.ByID(other) == nil {
			t.Fatal("identity deletion followed the cursor instead of confirmed ID")
		}
	})
	t.Run("scripts", func(t *testing.T) {
		m := newTestModel(t)
		for _, name := range []string{"a-other", "z-target"} {
			if _, err := m.scripts.Add(script.Script{Name: name, Content: "true"}); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.scripts.Save(); err != nil {
			t.Fatal(err)
		}
		target := m.scripts.ByName("z-target").ID
		other := m.scripts.ByName("a-other").ID
		m.scriptsUI = newScriptsManager(m)
		m.scriptsUI.cursor = 1
		m.screen = scrScripts
		m.dispatch(reviewKey("d"))
		m.scriptsUI.cursor = 0
		m.updateScriptPicker(reviewKey("y"))
		if m.scripts.ByID(target) != nil || m.scripts.ByID(other) == nil {
			t.Fatal("script deletion followed the cursor instead of confirmed ID")
		}
	})
}

func TestReviewScriptReloadCancelsDeletion(t *testing.T) {
	m := newTestModel(t)
	if _, err := m.scripts.Add(script.Script{Name: "target", Content: "true"}); err != nil {
		t.Fatal(err)
	}
	if err := m.scripts.Save(); err != nil {
		t.Fatal(err)
	}
	m.scriptsUI = newScriptsManager(m)
	m.screen = scrScripts
	m.dispatch(reviewKey("d"))
	other, err := script.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Add(script.Script{Name: "a-new", Content: "true"}); err != nil {
		t.Fatal(err)
	}
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	m.dispatch(reviewKey("y"))
	m.dispatch(reviewKey("y"))
	got, err := script.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Scripts) != 2 || m.scriptsUI.confirmDel {
		t.Fatal("reload retained/retargeted script deletion")
	}
}

func TestReviewRotationRefusalRetainsUsableOfflineProfile(t *testing.T) {
	a := newTestModel(t)
	remote := bareRemote(t)
	a.cfg.Sync.Remote = remote
	if err := a.cfg.Save(a.cfgDir); err != nil {
		t.Fatal(err)
	}
	oldKey, _ := a.vault.Identity()
	runSync(t, a)
	dir := t.TempDir()
	if err := gitsync.New(dir, "").Bootstrap(remote); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(dir)
	ps, _ := profile.LoadStore(dir)
	ids, _ := profile.LoadIdentities(dir)
	ss, _ := script.LoadStore(dir)
	v, err := vault.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(oldKey); err != nil {
		t.Fatal(err)
	}
	b := New(dir, cfg, ps, ids, ss, v)
	defer b.Close()
	runSync(t, b)
	lastSuccess := b.SyncStatus().LastSuccess
	prep, err := a.vault.PrepareRekey()
	if err != nil {
		t.Fatal(err)
	}
	newKey := prep.Key()
	if err := prep.Commit(); err != nil {
		t.Fatal(err)
	}
	runSync(t, a)
	p, err := b.store.Add(profile.Profile{Name: "offline", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
	if err != nil {
		t.Fatal(err)
	}
	secret := p.PassSecret()
	if err := b.vault.Put(secret, []byte("offline password")); err != nil {
		t.Fatal(err)
	}
	if err := b.store.Save(); err != nil {
		t.Fatal(err)
	}
	cmd := b.syncCmd("offline changes")
	if cmd == nil {
		t.Fatal("missing command")
	}
	result := cmd().(syncDoneMsg)
	b.dispatch(result)
	if result.err == nil || b.SyncStatus().Error == "" || !b.SyncStatus().LastSuccess.Equal(lastSuccess) {
		t.Fatal("mixed generation reported successful sync")
	}
	raw, err := b.vault.Get(secret)
	if err != nil || string(raw) != "offline password" || b.store.ByName("offline") == nil {
		t.Fatal("refusal lost access to valid local data")
	}
	fresh := t.TempDir()
	if err := gitsync.New(fresh, "").Bootstrap(remote); err != nil {
		t.Fatal(err)
	}
	remoteProfiles, err := profile.LoadStore(fresh)
	if err != nil || remoteProfiles.ByName("offline") != nil {
		t.Fatal("offline generation reached remote")
	}
	remoteVault, err := vault.Load(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := remoteVault.Unlock(newKey); err != nil {
		t.Fatal(err)
	}
	if err := remoteVault.VerifyAll(); err != nil {
		t.Fatal(err)
	}
}

func TestReviewDirectProfileDeleteChecksSnapshotBeforeSecrets(t *testing.T) {
	m := newTestModel(t)
	p, err := m.store.Add(profile.Profile{Name: "profile", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
	if err != nil {
		t.Fatal(err)
	}
	id, secret := p.ID, p.PassSecret()
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Put(secret, []byte("keep")); err != nil {
		t.Fatal(err)
	}
	m.confirm = confirmModel{profileID: id, name: p.Name}
	m.screen = scrConfirmDelete
	other, err := profile.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	other.ByID(id).Host = "127.0.0.2"
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	m.updateConfirm(reviewKey("y"))
	if m.store.ByID(id) == nil {
		t.Fatal("stale direct confirmation removed live metadata")
	}
	raw, err := m.vault.Get(secret)
	if err != nil || string(raw) != "keep" {
		t.Fatal("stale direct confirmation removed credentials")
	}
}
