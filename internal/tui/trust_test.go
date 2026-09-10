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
