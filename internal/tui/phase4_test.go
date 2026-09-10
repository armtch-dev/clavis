package tui

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/probe"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/sshconfig"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh"
)

// Blocking the transaction scratch path fails actual disk installation, after
// validation/encryption, without a mock that could hide partial persistence.
func blockPhase4Writes(t *testing.T, m *Model) func() {
	t.Helper()
	release, err := m.mutationLock()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(m.cfgDir, "local", ".clavis-write.tmp")
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		release()
	}
}

func TestPhase4DeleteRecoveryRequiresReconfirmation(t *testing.T) {
	for _, kind := range []string{"profile", "identity", "script"} {
		t.Run(kind, func(t *testing.T) {
			m := newTestModel(t)
			p := phase4Profile(t, m)
			secret := p.PassSecret()
			var target string
			switch kind {
			case "profile":
				target = p.ID
				m.screen = scrConfirmDelete
				m.confirm = confirmModel{profileID: p.ID, name: p.Name}
			case "identity":
				id, err := m.idents.Add(profile.Identity{Name: "identity", User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
				if err != nil {
					t.Fatal(err)
				}
				target = id.ID
				secret = id.PassSecret()
				if err := m.idents.Save(); err != nil {
					t.Fatal(err)
				}
				if err := m.vault.Put(secret, []byte("old secret")); err != nil {
					t.Fatal(err)
				}
				m.screen = scrIdentities
				m.identsUI = &identsModel{confirmDel: true, deleteID: target}
			case "script":
				s, err := m.scripts.Add(script.Script{Name: "script", Content: "echo original"})
				if err != nil {
					t.Fatal(err)
				}
				target = s.ID
				if err := m.scripts.Save(); err != nil {
					t.Fatal(err)
				}
				m.screen = scrScripts
				m.scriptsUI = newScriptsManager(m)
				m.scriptsUI.confirmDel, m.scriptsUI.deleteID = true, target
			}
			unblock := blockPhase4Writes(t, m)
			m.dispatchUnlocked(reviewKey("y"))
			unblock()
			if kind == "script" && !strings.Contains(m.scriptsUI.view(120, 40), "unsafe") {
				t.Fatal("script deletion error is invisible in the picker")
			}
			if kind == "identity" && m.idents.ByID(target) == nil || kind == "script" && m.scripts.ByID(target) == nil || kind == "profile" && m.store.ByID(target) == nil {
				t.Fatal("failed delete published removal")
			}
			_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
			if cmd == nil {
				t.Fatal("recovery missing")
			}
			m.dispatch(cmd())
			if m.persistenceErr != nil {
				t.Fatal("recovery did not clear latch")
			}
			m.dispatch(reviewKey("d"))
			m.dispatch(reviewKey("y"))
			if kind == "identity" && m.idents.ByID(target) != nil || kind == "script" && m.scripts.ByID(target) != nil || kind == "profile" && m.store.ByID(target) != nil {
				t.Fatal("reconfirmed deletion did not persist")
			}
			if kind != "script" {
				if _, err := m.vault.Get(secret); !errors.Is(err, vault.ErrNotFound) {
					t.Fatalf("secret not removed: %v", err)
				}
			}
		})
	}
}

func TestPhase4ImportPreservesSelectedIDAndPublishedRevision(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	m.cursor = 0
	if err := m.importSSHEntries([]sshconfig.Entry{{Alias: "aaa", HostName: "127.0.0.1", Port: 2, User: "user"}}); err != nil {
		t.Fatal(err)
	}
	if got := m.selected(m.visible()); got == nil || got.ID != p.ID {
		t.Fatal("import reordered selection")
	}
	if err := m.store.Save(); err != nil {
		t.Fatal("import published stale revision", err)
	}
}

func TestPhase4RecoveryFailureAndCredentialConflictRetainEdit(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	w := newWizard(m, &p)
	m.wizard, m.screen = w, scrWizard
	w.step = stepTest
	w.password = "retained replacement"
	unblock := blockPhase4Writes(t, m)
	w.save(m)
	// Release ownership while leaving the fault, exercising real failed recovery.
	l := m.uiLock
	m.uiLock = nil
	l.Close()
	_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
	if cmd == nil {
		t.Fatal("missing recovery")
	}
	m.dispatch(cmd())
	if m.persistenceErr == nil || m.wizard != w || w.password != "retained replacement" {
		t.Fatal("failed recovery lost draft or cleared barrier")
	}
	unblock()
	if err := m.vault.Put(p.PassSecret(), []byte("other writer")); err != nil {
		t.Fatal(err)
	}
	_, cmd = m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
	m.dispatch(cmd())
	m.dispatch(reviewKey("s"))
	b, err := m.vault.Get(p.PassSecret())
	if err != nil || string(b) != "other writer" || m.wizard != w || w.errs == "" {
		t.Fatal("recovery refreshed a conflicting credential baseline")
	}
}

func TestPhase4PassphraseWhitespaceAndEarlySaveValidation(t *testing.T) {
	m := newTestModel(t)
	w := newWizard(m, nil)
	m.wizard, m.screen = w, scrWizard
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("  key phrase  "))
	if err != nil {
		t.Fatal(err)
	}
	w.draft.Name, w.draft.Host, w.draft.User = "protected", "127.0.0.1", "user"
	w.useKey = true
	if err := w.acceptKey(pem.EncodeToMemory(block)); err != nil {
		t.Fatal(err)
	}
	w.setStep(stepPassphrase)
	w.input.SetValue("  key phrase  ")
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if w.passphrase != "  key phrase  " {
		t.Fatalf("passphrase altered/rejected: %q %s", w.passphrase, w.errs)
	}
	w.step = stepTest
	m.dispatch(reviewKey("s"))
	got, err := m.vault.Get(w.draft.PassphraseSecret())
	if err != nil || string(got) != "  key phrase  " {
		t.Fatalf("stored phrase %q %v", got, err)
	}
	w = newWizard(m, nil)
	m.wizard = w
	m.screen = scrWizard
	w.input.SetValue("invalid/name")
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if w.step != stepName || w.errs == "" {
		t.Fatal("invalid name escaped its field without visible error")
	}
	w.input.SetValue("protected")
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if w.step != stepName || w.errs == "" {
		t.Fatal("duplicate name escaped its field without visible error")
	}
}

func TestPhase4QuickSaveCannotLoseProtectedKeyPassphrase(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	w := newWizard(m, &p)
	m.wizard, m.screen = w, scrWizard
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("protected"))
	if err != nil {
		t.Fatal(err)
	}
	w.useKey = true
	w.setStep(stepKeyPaste)
	w.area.SetValue(string(pem.EncodeToMemory(block)))
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlS})
	if m.wizard != w || w.errs == "" || m.store.ByID(p.ID).HasAuth(profile.AuthKey) {
		t.Fatal("quick save stored protected key without its passphrase")
	}
}

func TestPhase4CredentialReadErrorsAreNotOptionalAbsence(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	m.store.ByID(p.ID).Auth = []profile.AuthKind{profile.AuthKey}
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	p = *m.store.ByID(p.ID)
	if err := m.vault.Put(p.KeySecret(), genKeyPEM(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(m.cfgDir, "vault", p.PassphraseSecret()+".age"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.credsFor(&p); err == nil {
		t.Fatal("credential I/O error treated as absent optional passphrase")
	}
	w := newWizard(m, &p)
	m.wizard, m.screen = w, scrWizard
	w.step = stepTest
	if cmd := w.startTest(m); cmd != nil || w.testResult == nil || w.testResult.Err == nil {
		t.Fatal("draft test swallowed credential read error")
	}
}

func TestPhase4KeepStoredKeyDiscardsReplacementDraft(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	old := genKeyPEM(t)
	m.store.ByID(p.ID).Auth = []profile.AuthKind{profile.AuthKey}
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Put(p.KeySecret(), old); err != nil {
		t.Fatal(err)
	}
	p = *m.store.ByID(p.ID)
	w := newWizard(m, &p)
	m.wizard, m.screen = w, scrWizard
	if err := w.acceptKey(genKeyPEM(t)); err != nil {
		t.Fatal(err)
	}
	w.setStep(stepKeySource)
	m.dispatch(reviewKey("k"))
	w.step = stepTest
	m.dispatch(reviewKey("s"))
	b, err := m.vault.Get(p.KeySecret())
	if err != nil || string(b) != string(old) {
		t.Fatal("keep stored key persisted an abandoned replacement")
	}
}

func TestPhase4FailedMutationCancelsPendingJobs(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	m.runTest(p, sshx.Credentials{Password: "unused"}, nil)
	job := m.sshTests[p.ID]
	m.testing[p.ID] = true
	m.pending = &pendingConnect{p: p, creds: sshx.Credentials{Password: "pending"}, job: m.networkJob(p)}
	m.connecting = p.ID
	w := newWizard(m, &p)
	w.password = "replacement"
	m.wizard, m.screen = w, scrWizard
	unblock := blockPhase4Writes(t, m)
	w.save(m)
	unblock()
	if job.ctx.Err() == nil || len(m.testing) != 0 || m.pending != nil {
		t.Fatal("persistence barrier strands pending jobs/results")
	}
}

func TestPhase4PendingConnectionCanceledOnBackAndReload(t *testing.T) {
	for _, action := range []string{"escape", "unlock-escape", "reload", "quit"} {
		t.Run(action, func(t *testing.T) {
			m := newTestModel(t)
			p := phase4Profile(t, m)
			m.pending = &pendingConnect{p: p, creds: sshx.Credentials{Password: "pending secret"}, job: m.networkJob(p)}
			m.connecting = p.ID
			job := m.pending.job
			switch action {
			case "escape":
				m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
			case "unlock-escape":
				m.vault.Lock()
				m.unlock = newUnlock(m.vault, m.cfgDir)
				m.screen = scrUnlock
				m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
			case "reload":
				l, err := fstxn.Acquire(m.cfgDir)
				if err != nil {
					t.Fatal(err)
				}
				s, err := loadDiskLocked(l)
				l.Close()
				if err != nil {
					t.Fatal(err)
				}
				m.applyDisk(s)
			case "quit":
				m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlC})
			}
			if m.pending != nil || m.connecting != "" || job.ctx.Err() == nil {
				t.Fatal("abandoned pending connection retained credentials/job")
			}
		})
	}
}

func TestPhase4RestoreFinalizationFailureRetainsTokenAndConfig(t *testing.T) {
	m := newTestModel(t)
	id, err := m.vault.Identity()
	if err != nil {
		t.Fatal(err)
	}
	m.welcome = &welcomeModel{step: wKey, url: "https://example.invalid/repo", token: "retained token", input: newTextInput("key", true)}
	m.welcome.input.SetValue(id)
	m.screen = scrWelcome
	unblock := blockPhase4Writes(t, m)
	m.welcomeKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.welcome.token != "retained token" || m.welcome.errs == "" || m.cfg.Sync.Remote != "" || m.welcome.step != wKey {
		t.Fatal("failed restore finalization lost draft/published success")
	}
	unblock()
}

func TestPhase4SelectionSurvivesLiveOrderingAndActions(t *testing.T) {
	m := newTestModel(t)
	a := phase4Profile(t, m)
	b, err := m.store.Add(profile.Profile{Name: "second", Host: "127.0.0.1", Port: 2, User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
	if err != nil {
		t.Fatal(err)
	}
	bID := b.ID
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	m.monitor.Stop()
	m.monitor = probe.New(time.Millisecond, 20*time.Millisecond, func(s probe.Status) {
		select {
		case m.probeCh <- s:
		default:
		}
	})
	m.syncTargets()
	m.dispatch(reviewKey("o"))
	st := probe.Status{ProfileID: bID, Reachable: true, LatencyMs: 1}
	// Use an actual monitor generation so the normal stale-probe gate applies.
	for _, s := range m.monitor.Snapshot() {
		if s.ProfileID == bID {
			st = s
			st.Reachable = true
			st.LatencyMs = 1
		}
	}
	// Generation arrives from the real target monitor callback.
	deadline := time.After(time.Second)
	for !m.monitor.Current(st) {
		select {
		case s := <-m.probeCh:
			if s.ProfileID == bID {
				st = s
			}
		case <-deadline:
			t.Fatal("no probe")
		}
		st.Reachable = true
		st.LatencyMs = 1
	}
	m.dispatch(probeMsg(st))
	if p := m.selected(m.visible()); p == nil || p.ID != a.ID {
		t.Fatal("live sort redirected selection")
	}
	m.dispatch(reviewKey("c"))
	m.catInput = "aaa"
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if p := m.selected(m.visible()); p == nil || p.ID != a.ID {
		t.Fatal("category redirected selection")
	}
	m.dispatch(reviewKey("d"))
	if m.confirm.profileID != a.ID {
		t.Fatal("delete targets another profile")
	}
}

func TestPhase4ScriptAndSettingsFailureRetainLiveState(t *testing.T) {
	for _, which := range []string{"script", "settings", "category"} {
		t.Run(which, func(t *testing.T) {
			m := newTestModel(t)
			p := phase4Profile(t, m)
			m.scriptsUI = newScriptsManager(m)
			m.scriptsUI.openEditor(nil)
			m.scriptsUI.name.SetValue("draft")
			m.scriptsUI.area.SetValue("echo retained")
			m.settings = newSettings(m)
			m.settings.textStep(sRemoteURL, "url", false)
			m.settings.input.SetValue("https://example.invalid/repo")
			unblock := blockPhase4Writes(t, m)
			switch which {
			case "script":
				m.updateScriptEditor(tea.KeyMsg{Type: tea.KeyCtrlD})
				if !m.scriptsUI.editing || m.scriptsUI.errs == "" || len(m.scripts.Scripts) != 0 {
					t.Fatal("failed script published or lost draft")
				}
			case "settings":
				m.settingsKey(tea.KeyMsg{Type: tea.KeyEnter})
				if m.cfg.Sync.Remote != "" || m.settings.input.Value() != "https://example.invalid/repo" || m.settings.errs == "" {
					t.Fatal("failed setting changed live config/lost draft")
				}
			case "category":
				m.catTarget, m.catInput = p.ID, "new category"
				m.updateList(tea.KeyMsg{Type: tea.KeyEnter})
				if m.catTarget != p.ID || m.store.ByID(p.ID).Category != "" {
					t.Fatal("failed category changed live metadata/lost input")
				}
			}
			unblock()
		})
	}
}

func phase4Profile(t *testing.T, m *Model) profile.Profile {
	t.Helper()
	p, err := m.store.Add(profile.Profile{Name: "original", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
	if err != nil {
		t.Fatal(err)
	}
	cp := *p
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Put(cp.PassSecret(), []byte("old secret")); err != nil {
		t.Fatal(err)
	}
	return cp
}

func TestPhase4FailedWizardSaveRetainsDraftAndCanRetry(t *testing.T) {
	for _, identity := range []bool{false, true} {
		t.Run(map[bool]string{false: "profile", true: "identity"}[identity], func(t *testing.T) {
			m := newTestModel(t)
			w := newWizard(m, nil)
			w.draft.Name, w.draft.Host, w.draft.User = "new", "127.0.0.1", "user"
			if identity {
				w = newIdentityWizard(m, nil)
				w.ident.Name, w.ident.User = "new", "user"
			}
			w.usePassword, w.password, w.step = true, " exact secret ", stepTest
			m.wizard, m.screen = w, scrWizard
			unblock := blockPhase4Writes(t, m)
			m.updateWizard(reviewKey("s"))
			if m.wizard != w || w.password != " exact secret " || w.errs == "" || m.statusType == statusOK {
				t.Fatalf("failed save discarded draft/reported success: wizard=%v error=%q status=%s", m.wizard != nil, w.errs, m.statusMsg)
			}
			if len(m.store.Profiles)+len(m.idents.Identities) != 0 {
				t.Fatal("failed save published metadata")
			}
			unblock()
			_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
			if cmd != nil {
				m.dispatch(cmd())
			}
			m.dispatch(reviewKey("s"))
			if m.wizard != nil || m.statusType != statusOK {
				t.Fatalf("retry failed: %s / %s", w.errs, m.statusMsg)
			}
			secret := w.draft.PassSecret()
			if identity {
				secret = m.idents.ByName("new").PassSecret()
			}
			b, err := m.vault.Get(secret)
			if err != nil || string(b) != " exact secret " {
				t.Fatalf("credential %q: %v", b, err)
			}
			if err := m.store.Save(); err != nil {
				t.Fatalf("published stale profiles revision: %v", err)
			}
			if err := m.idents.Save(); err != nil {
				t.Fatalf("published stale identities revision: %v", err)
			}
		})
	}
}

func TestPhase4FailedDeleteAndRebindAreAtomic(t *testing.T) {
	for _, operation := range []string{"delete", "rebind"} {
		t.Run(operation, func(t *testing.T) {
			m := newTestModel(t)
			p := phase4Profile(t, m)
			id, err := m.idents.Add(profile.Identity{Name: "shared", User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.idents.Save(); err != nil {
				t.Fatal(err)
			}
			if err := m.vault.Put(id.PassSecret(), []byte("shared secret")); err != nil {
				t.Fatal(err)
			}
			w := newWizard(m, &p)
			w.draft.IdentityID = id.ID
			w.step = stepTest
			unblock := blockPhase4Writes(t, m)
			if operation == "delete" {
				m.confirm = confirmModel{profileID: p.ID, name: p.Name}
				m.screen = scrConfirmDelete
				m.updateConfirm(reviewKey("y"))
			} else {
				m.wizard, m.screen = w, scrWizard
				m.updateWizard(reviewKey("s"))
			}
			if got := m.store.ByID(p.ID); got == nil || got.IdentityID != "" {
				t.Fatal("failed operation changed live metadata")
			}
			unblock()
			b, err := m.vault.Get(p.PassSecret())
			if err != nil || string(b) != "old secret" {
				t.Fatalf("lost credential %q %v", b, err)
			}
			store, err := profile.LoadStore(m.cfgDir)
			if err != nil || store.ByID(p.ID) == nil || store.ByID(p.ID).IdentityID != "" {
				t.Fatal("disk metadata changed")
			}
		})
	}
}

func TestPhase4ExactPasswordAndVisibleValidationTransitions(t *testing.T) {
	m := newTestModel(t)
	w := newWizard(m, nil)
	m.wizard, m.screen = w, scrWizard
	w.usePassword = true
	w.setStep(stepPassword)
	w.input.SetValue("  password  ")
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if w.password != "  password  " {
		t.Fatalf("secret trimmed: %q", w.password)
	}
	w.draft.Name, w.draft.Host, w.draft.User = "invalid/name", "127.0.0.1", "user"
	w.step = stepTest
	m.dispatch(reviewKey("s"))
	if w.errs == "" || !strings.Contains(w.view(120, 30), "name") {
		t.Fatal("validation disappeared")
	}
	m.settings = newSettings(m)
	m.screen = scrSettings
	m.settings.textStep(sToken, "token", true)
	m.settings.token = "rejected"
	m.settings.input.SetValue("rejected")
	m.dispatch(tokenCheckedMsg{err: errors.New("token rejected")})
	if m.settings.errs == "" || !strings.Contains(m.settings.view(120, 30), "token rejected") {
		t.Fatal("token validation disappeared")
	}
}
