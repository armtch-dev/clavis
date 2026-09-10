package tui

import (
	"strings"
	"testing"

	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh"
)

func phase4HostKey(t *testing.T) (string, string) {
	t.Helper()
	key, err := ssh.ParsePrivateKey(genKeyPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(key.PublicKey()), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
}

func TestPhase4RetrustRequiresReviewAndCurrentSnapshot(t *testing.T) {
	for _, change := range []string{"none", "endpoint", "pin", "failure"} {
		t.Run(change, func(t *testing.T) {
			m := newTestModel(t)
			m.width, m.height = 120, 40
			p := phase4Profile(t, m)
			oldFP, oldKey := phase4HostKey(t)
			newFP, newKey := phase4HostKey(t)
			m.store.ByID(p.ID).HostKey = oldKey // full-key-only legacy profile
			if err := m.store.Save(); err != nil {
				t.Fatal(err)
			}
			p = *m.store.ByID(p.ID)
			m.runTest(p, sshx.Credentials{Password: "unused"}, nil) // schedule identity, no network execution
			job := m.sshTests[p.ID]
			m.dispatch(testDoneMsg{profileID: p.ID, endpoint: p, job: job, result: sshx.TestResult{Stage: sshx.StageHostKey, Err: sshx.ErrHostKeyChanged, HostKeyFP: newFP, HostKeyLine: newKey}})
			if m.store.ByID(p.ID).HostKey != oldKey {
				t.Fatal("mismatch automatically replaced trust")
			}
			m.dispatch(reviewKey("h"))
			view := m.View()
			if !strings.Contains(view, oldFP) || !strings.Contains(view, newFP) {
				t.Fatal("review lacks full old/new fingerprints")
			}
			m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
			if m.store.ByID(p.ID).HostKey != oldKey {
				t.Fatal("empty confirmation updated pin")
			}
			if change == "endpoint" || change == "pin" {
				other, err := profile.LoadStore(m.cfgDir)
				if err != nil {
					t.Fatal(err)
				}
				if change == "endpoint" {
					other.ByID(p.ID).Host = "127.0.0.2"
				} else {
					_, key := phase4HostKey(t)
					other.ByID(p.ID).HostKey = key
				}
				if err := other.Save(); err != nil {
					t.Fatal(err)
				}
			}
			m.dispatch(reviewKey("trust"))
			if change == "failure" {
				unblock := blockPhase4Writes(t, m)
				m.dispatchUnlocked(tea.KeyMsg{Type: tea.KeyEnter})
				unblock()
			} else {
				m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
			}
			got, err := profile.LoadStore(m.cfgDir)
			if err != nil {
				t.Fatal(err)
			}
			if change == "none" {
				if got.ByID(p.ID).HostKey != newKey || got.ByID(p.ID).HostKeyFP != newFP {
					t.Fatal("deliberate confirmation did not persist")
				}
			} else if got.ByID(p.ID).HostKey == newKey {
				t.Fatal("stale/failed confirmation replaced trust")
			}
		})
	}
}

func TestPhase4WizardResultsPinOnlyMatchingSavedDraft(t *testing.T) {
	for _, action := range []string{"save", "back-retarget", "cancel", "supersede"} {
		t.Run(action, func(t *testing.T) {
			m := newTestModel(t)
			p := phase4Profile(t, m)
			w := newWizard(m, &p)
			m.wizard, m.screen = w, scrWizard
			w.step = stepTest
			fp, line := phase4HostKey(t)
			m.runTest(p, sshx.Credentials{Password: "unused"}, w)
			job := w.testJob
			w.awaitingTest = true
			if action == "cancel" {
				m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
			}
			if action == "supersede" {
				m.runTest(p, sshx.Credentials{Password: "unused"}, w)
			}
			m.dispatch(testDoneMsg{profileID: p.ID, endpoint: p, job: job, wizard: w, result: sshx.TestResult{OK: true, HostKeyFP: fp, HostKeyLine: line}})
			if m.store.ByID(p.ID).HostKey != "" {
				t.Fatal("draft test updated live trust before save")
			}
			if action == "cancel" || action == "supersede" {
				if w.testResult != nil {
					t.Fatal("stale result reached draft")
				}
				return
			}
			if action == "back-retarget" {
				m.dispatch(reviewKey("b"))
				w.draft.Host = "127.0.0.2"
				w.step = stepTest
			}
			m.dispatch(reviewKey("s"))
			got := m.store.ByID(p.ID)
			if action == "save" && got.HostKey != line {
				t.Fatal("successful draft contact not pinned on save")
			}
			if action == "back-retarget" && got.HostKey != "" {
				t.Fatal("old draft test pinned retargeted endpoint")
			}
		})
	}
}

func TestPhase4FailedSessionCannotPin(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	fp, line := phase4HostKey(t)
	m.dispatch(sessionDoneMsg{profileID: p.ID, endpoint: p, hostKeyFP: fp, hostKeyLine: line, err: sshx.ErrHostKeyChanged})
	if m.store.ByID(p.ID).HostKey != "" {
		t.Fatal("failed session pinned unauthenticated observation")
	}
}

func TestPhase4WizardRetrustIsDraftUntilAtomicSave(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	oldFP, oldKey := phase4HostKey(t)
	fp, key := phase4HostKey(t)
	m.store.ByID(p.ID).HostKeyFP, m.store.ByID(p.ID).HostKey = oldFP, oldKey
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	p = *m.store.ByID(p.ID)
	w := newWizard(m, &p)
	m.wizard, m.screen = w, scrWizard
	w.step = stepTest
	w.awaitingTest = true
	m.runTest(p, sshx.Credentials{Password: "unused"}, w)
	m.dispatch(testDoneMsg{profileID: p.ID, endpoint: p, job: w.testJob, wizard: w, result: sshx.TestResult{Stage: sshx.StageHostKey, Err: sshx.ErrHostKeyChanged, HostKeyFP: fp, HostKeyLine: key}})
	m.dispatch(reviewKey("h"))
	m.dispatch(reviewKey("trust"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if w.draft.HostKey != key || m.store.ByID(p.ID).HostKey != oldKey {
		t.Fatal("draft confirmation did not isolate live trust")
	}
	w.password = "new password"
	unblock := blockPhase4Writes(t, m)
	w.save(m)
	unblock()
	if m.wizard != w || m.store.ByID(p.ID).HostKey != oldKey {
		t.Fatal("failed save published approved draft pin")
	}
	_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
	if cmd == nil {
		t.Fatal("recovery not scheduled")
	}
	m.dispatch(cmd())
	m.dispatch(reviewKey("s"))
	if m.wizard != nil || m.store.ByID(p.ID).HostKey != key {
		t.Fatalf("approved draft retry failed: %s", w.errs)
	}
	b, err := m.vault.Get(p.PassSecret())
	if err != nil || string(b) != "new password" {
		t.Fatal("pin and credentials not saved together")
	}
}

func TestPhase4CompactTrustReviewScrollsInsteadOfHidingNewKey(t *testing.T) {
	m := newTestModel(t)
	m.width, m.height = 40, 8
	p := phase4Profile(t, m)
	oldFP, oldKey := phase4HostKey(t)
	newFP, newKey := phase4HostKey(t)
	p.HostKeyFP, p.HostKey = oldFP, oldKey
	m.openTrust(p, sshx.TestResult{Stage: sshx.StageHostKey, Err: sshx.ErrHostKeyChanged, HostKeyFP: newFP, HostKeyLine: newKey}, nil)
	frames := m.View()
	for i := 0; i < 10; i++ {
		m.dispatch(tea.KeyMsg{Type: tea.KeyPgDown})
		frames += "\n" + m.View()
	}
	if !strings.Contains(frames, oldFP[:24]) || !strings.Contains(frames, newFP[:24]) || !strings.Contains(frames, oldFP[len(oldFP)-8:]) || !strings.Contains(frames, newFP[len(newFP)-8:]) {
		t.Fatal("compact review hides fingerprint bytes despite scrolling")
	}
}

func TestPhase4ReloadDeletionCancelsWizardJob(t *testing.T) {
	m := newTestModel(t)
	p := phase4Profile(t, m)
	w := newWizard(m, &p)
	m.wizard, m.screen = w, scrWizard
	w.awaitingTest = true
	m.runTest(p, sshx.Credentials{Password: "unused"}, w)
	job := w.testJob
	other, err := profile.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Remove(p.ID); err != nil {
		t.Fatal(err)
	}
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
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
	if job.ctx.Err() == nil || w.awaitingTest {
		t.Fatal("deleted edit retained its test job")
	}
}
