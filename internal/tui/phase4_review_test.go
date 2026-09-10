package tui

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
)

func TestPhase4ReviewSettingsCompletionConsumedOnce(t *testing.T) {
	for _, kind := range []string{"token", "repo"} {
		t.Run(kind, func(t *testing.T) {
			m := newTestModel(t)
			p := phase4Profile(t, m)
			s := phase4ReviewSettingsWork(t, m, kind)
			var completion tea.Msg = tokenCheckedMsg{login: "validated-user", request: s.request}
			if kind == "repo" {
				completion = repoCreatedMsg{url: "https://example.invalid/created.git", request: s.request}
			}
			phase4ReviewPinFailure(t, m, p)
			m.dispatch(completion)
			_, recover := m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
			m.dispatch(recover())
			m.dispatch(tea.KeyMsg{Type: tea.KeyEnter}) // explicitly retry only local persistence
			if s.busy != "" || s.step != sMenu {
				t.Fatal("outcome did not settle and save", s.errs)
			}
			if kind == "token" {
				if err := m.vault.PutLocal("github-token", []byte("later token")); err != nil {
					t.Fatal(err)
				}
				s.textStep(sToken, "token", true)
			} else {
				if err := m.changeConfig(func(c *config.Config) { c.Sync.Remote = "https://example.invalid/later.git" }); err != nil {
					t.Fatal(err)
				}
				s.textStep(sRemoteURL, "URL", false)
			}
			s.input.SetValue("new unsaved input")
			m.dispatch(completion) // delayed duplicate must not replay the completed operation
			if s.input.Value() != "new unsaved input" || s.busy != "" {
				t.Fatal("duplicate completion replaced current input")
			}
			if kind == "token" {
				b, err := m.vault.GetLocal("github-token")
				if err != nil || string(b) != "later token" {
					t.Fatal("duplicate completion overwrote later token")
				}
			} else if m.cfg.Sync.Remote != "https://example.invalid/later.git" {
				t.Fatal("duplicate completion overwrote later destination")
			}
		})
	}
}

func TestPhase4ReviewSettingsCompletionStaysWithOrigin(t *testing.T) {
	m := newTestModel(t)
	s := phase4ReviewSettingsWork(t, m, "token")
	original := s.request
	path := filepath.Join(m.cfgDir, "local", "github-token.age")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A recipient-change unlock/browse transition can expose a newly opened
	// settings model while the old network command is still outstanding.
	m.vault.Lock()
	m.unlock = newUnlock(m.vault, m.cfgDir)
	m.screen = scrUnlock
	m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
	m.dispatch(reviewKey("g"))
	newer := m.settings
	newer.textStep(sToken, "token", true)
	newer.input.SetValue("newer token")
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	newRequest := newer.request
	m.dispatch(tokenCheckedMsg{login: "old-user", request: original})
	if s.busy != "" || s.token != "synthetic-token" || s.errs == "" {
		t.Fatal("originating outcome not retained")
	}
	if newer.request != newRequest || newer.busy == "" || newer.input.Value() != "newer token" {
		t.Fatal("old completion consumed the new settings operation")
	}
	// Encryption would work even with a locked vault: compare ciphertext to prove
	// the stale owner's result did not reach persistence at all.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("old settings owner overwrote current credentials")
	}
	if newer.tokenSet != true || newer.login != "" {
		t.Fatal("old validation result published into new settings")
	}
}

func TestPhase4ReviewDeferredSettingsCompletionKeepsOwnershipAndRunsOnce(t *testing.T) {
	m := newTestModel(t)
	s := phase4ReviewSettingsWork(t, m, "token")
	completion := tokenCheckedMsg{login: "user", request: s.request}
	m.syncing = true
	_, cmd := m.dispatch(completion)
	if cmd == nil || s.busy == "" {
		t.Fatal("sync did not defer settings persistence")
	}
	m.syncing = false
	l, err := fstxn.Acquire(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	_, cmd = m.dispatch(cmd())
	if cmd == nil || s.busy == "" {
		l.Close()
		t.Fatal("external ownership was bypassed")
	}
	l.Close()
	m.dispatch(cmd())
	if s.busy != "" || !s.tokenSet {
		t.Fatal("deferred result did not finish")
	}
	path := filepath.Join(m.cfgDir, "local", "github-token.age")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m.dispatch(completion)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("duplicate delivery encrypted/wrote the token again")
	}
}

func phase4ReviewSettingsWork(t *testing.T, m *Model, kind string) *settingsModel {
	t.Helper()
	if err := m.vault.PutLocal("github-token", []byte("old stored token")); err != nil {
		t.Fatal(err)
	}
	m.settings, m.screen = newSettings(m), scrSettings
	s := m.settings
	if kind == "token" {
		s.textStep(sToken, "token", true)
		s.input.SetValue("synthetic-token")
	} else {
		s.textStep(sRepoName, "repository", false)
		s.input.SetValue("synthetic-repo")
		m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	}
	key := tea.KeyMsg{Type: tea.KeyEnter}
	if kind == "repo" {
		key = reviewKey("y")
	}
	_, cmd := m.dispatch(key) // schedule only: never call GitHub
	if cmd == nil || s.busy == "" {
		t.Fatal("fixture did not start settings work")
	}
	return s
}

func phase4ReviewPinFailure(t *testing.T, m *Model, p profile.Profile) {
	t.Helper()
	m.runTest(p, sshx.Credentials{Password: "unused"}, nil)
	job := m.sshTests[p.ID]
	fp, line := phase4HostKey(t)
	unblock := blockPhase4Writes(t, m)
	m.dispatchUnlocked(testDoneMsg{profileID: p.ID, endpoint: p, job: job, result: sshx.TestResult{OK: true, HostKeyFP: fp, HostKeyLine: line}})
	unblock()
	if m.persistenceErr == nil {
		t.Fatal("fixture did not fail pin persistence")
	}
}

func TestPhase4ReviewSettingsCompletionSurvivesRecovery(t *testing.T) {
	for _, kind := range []string{"token", "repo"} {
		for _, duringRecovery := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/barrier", true: "/recovering"}[duringRecovery], func(t *testing.T) {
				m := newTestModel(t)
				p := phase4Profile(t, m)
				s := phase4ReviewSettingsWork(t, m, kind)
				phase4ReviewPinFailure(t, m, p)
				var recovery tea.Cmd
				if duringRecovery {
					_, recovery = m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
				}
				var completion tea.Msg = tokenCheckedMsg{login: "synthetic-user"}
				if kind == "repo" {
					completion = repoCreatedMsg{url: "https://example.invalid/new-repo.git"}
				}
				m.dispatch(completion)
				if s.busy != "" {
					t.Fatal("barrier discarded completion and stranded settings busy")
				}
				if m.persistenceErr == nil || s.errs == "" {
					t.Fatal("completion erased recovery barrier or lacked retry feedback")
				}
				if kind == "token" && (s.token != "synthetic-token" || s.input.Value() != "synthetic-token") {
					t.Fatal("token draft lost")
				}
				if kind == "repo" && (s.step != sRemoteURL || s.input.Value() != "https://example.invalid/new-repo.git") {
					t.Fatal("returned repository URL lost")
				}
				b, err := m.vault.GetLocal("github-token")
				if err != nil || string(b) != "old stored token" {
					t.Fatal("completion wrote token through persistence barrier")
				}
				cfg, err := config.Load(m.cfgDir)
				if err != nil || cfg.Sync.Remote != "" {
					t.Fatal("completion wrote config through persistence barrier")
				}
				if !duringRecovery {
					_, recovery = m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
				}
				if recovery == nil {
					t.Fatal("missing recovery command")
				}
				m.dispatch(recovery())
				if m.persistenceErr != nil {
					t.Fatal("recovery failed", m.persistenceErr)
				}
				m.dispatch(tea.KeyMsg{Type: tea.KeyEsc}) // recovery must also survive returning to the menu
				field, value := "t", "synthetic-token"
				if kind == "repo" {
					field, value = "u", "https://example.invalid/new-repo.git"
				}
				m.dispatch(reviewKey(field))
				if s.input.Value() != value {
					t.Fatal("returning to the field lost the completed network outcome")
				}
				_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
				if cmd != nil || s.busy != "" {
					t.Fatal("local retry repeated network work instead of consuming the retained completion")
				}
				if s.step != sMenu {
					t.Fatal("retained outcome did not save after recovery", s.errs)
				}
				if kind == "token" {
					b, err = m.vault.GetLocal("github-token")
					if err != nil || string(b) != "synthetic-token" || s.login != "synthetic-user" {
						t.Fatal("validated token outcome was lost")
					}
				} else {
					cfg, err = config.Load(m.cfgDir)
					if err != nil || cfg.Sync.Remote != "https://example.invalid/new-repo.git" {
						t.Fatal("returned URL was not saved")
					}
				}
				m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
				if m.screen != scrList {
					t.Fatal("settings remained stuck after retry")
				}
			})
		}
	}
}

func TestPhase4ReviewRejectedSettingsCompletionRemainsVisible(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	s := phase4ReviewSettingsWork(t, m, "token")
	phase4ReviewPinFailure(t, m, p)
	m.dispatch(tokenCheckedMsg{err: errors.New("token was rejected")})
	if s.busy != "" || s.input.Value() != "synthetic-token" || !strings.Contains(s.view(120, 40), "token was rejected") {
		t.Fatal("rejected validation was discarded by recovery barrier")
	}
	_, recovery := m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
	m.dispatch(recovery())
	_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || s.busy == "" {
		t.Fatal("rejected token was treated as validated rather than allowing a network retry")
	}
}

func TestPhase4ReviewIdentityPickerReloadRetainsTargetOrRequiresChoice(t *testing.T) {
	for _, change := range []string{"remove-selected", "remove-all", "remove-predecessor", "reorder"} {
		t.Run(change, func(t *testing.T) {
			m := newTestModel(t)
			for _, name := range []string{"alpha", "beta"} {
				if _, err := m.idents.Add(profile.Identity{Name: name, User: "user", Auth: []profile.AuthKind{profile.AuthPassword}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.idents.Save(); err != nil {
				t.Fatal(err)
			}
			alpha, beta := m.idents.ByName("alpha").ID, m.idents.ByName("beta").ID
			w := newWizard(m, nil)
			w.draft.Name, w.draft.IdentityID = "retained profile", alpha
			w.password = " retained secret "
			m.wizard, m.screen = w, scrWizard
			w.setStep(stepIdentity)
			m.dispatch(reviewKey("j")) // highlight beta, without changing the alpha draft binding
			other, err := profile.LoadIdentities(m.cfgDir)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "remove-selected", "remove-all":
				if _, err := other.Remove(beta); err != nil {
					t.Fatal(err)
				}
				if change == "remove-all" {
					if _, err := other.Remove(alpha); err != nil {
						t.Fatal(err)
					}
				}
			case "remove-predecessor":
				if _, err := other.Remove(alpha); err != nil {
					t.Fatal(err)
				}
			case "reorder":
				other.ByID(beta).Name = "aaa beta"
			}
			if err := other.Save(); err != nil {
				t.Fatal(err)
			}
			m.dispatch(tea.KeyMsg{Type: tea.KeyEnter}) // real stale-revision reload
			if m.wizard != w || w.password != " retained secret " || w.draft.Name != "retained profile" {
				t.Fatal("reload discarded draft")
			}
			removed := change == "remove-selected" || change == "remove-all"
			if removed {
				for i := 0; i < 3; i++ {
					m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
					if w.step != stepIdentity || w.draft.IdentityID != alpha || w.errs == "" {
						t.Fatal("missing highlight silently committed another identity/per-host fallback")
					}
				}
				if !strings.Contains(w.view(120, 40), "choose") {
					t.Fatal("missing-identity feedback not visible")
				}
				if change == "remove-all" {
					m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
					m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
					if w.step != stepIdentity {
						t.Fatal("back/next skipped the only way to replace a deleted identity binding")
					}
				}
				m.dispatch(reviewKey("k")) // deliberately choose per-host credentials
				m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
				if w.step == stepIdentity || w.draft.IdentityID != "" {
					t.Fatal("fresh per-host choice could not be committed")
				}
			} else {
				m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
				if w.draft.IdentityID != beta || w.step == stepIdentity {
					t.Fatal("reordered picker committed by old row instead of highlighted identity ID")
				}
			}
			if w.password != " retained secret " {
				t.Fatal("choosing credentials lost the password draft")
			}
		})
	}
}

func TestPhase4ReviewIdentityQuickSaveCommitsHighlightedID(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	id, err := m.idents.Add(profile.Identity{Name: "shared", User: "user", Auth: []profile.AuthKind{profile.AuthPassword}})
	if err != nil {
		t.Fatal(err)
	}
	target := id.ID
	if err := m.idents.Save(); err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Put(id.PassSecret(), []byte("shared password")); err != nil {
		t.Fatal(err)
	}
	w := newWizard(m, &p)
	m.wizard, m.screen = w, scrWizard
	w.setStep(stepIdentity)
	m.dispatch(reviewKey("j"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlS})
	store, err := profile.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	if store.ByID(p.ID).IdentityID != target {
		t.Fatal("quick save silently used the previous binding instead of highlighted identity")
	}
}
