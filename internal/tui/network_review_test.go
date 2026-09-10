package tui

import (
	"testing"
	"time"

	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshx"
)

func TestReviewSavedTestCannotCompleteWizard(t *testing.T) {
	for _, staleDisk := range []bool{false, true} {
		m := newTestModel(t)
		p := addPasswordProfile(t, m, "saved")
		if err := m.store.Save(); err != nil {
			t.Fatal(err)
		}
		original := *p
		_ = m.runTest(original, sshx.Credentials{Password: "synthetic"}, nil)
		savedJob := m.sshTests[p.ID]
		w := newWizard(m, p)
		w.draft.Host = "127.0.0.2"
		m.wizard, m.screen = w, scrWizard
		_ = w.startTest(m)
		wizardJob := w.testJob
		if staleDisk {
			other, err := profile.LoadStore(m.cfgDir)
			if err != nil {
				t.Fatal(err)
			}
			other.ByID(p.ID).Name = "renamed"
			if err := other.Save(); err != nil {
				t.Fatal(err)
			}
		}
		m.dispatch(testDoneMsg{profileID: p.ID, endpoint: original, job: savedJob, result: sshx.TestResult{OK: true, Reason: "saved endpoint"}})
		if !w.awaitingTest || w.testResult != nil || w.testJob != wizardJob {
			t.Fatalf("saved completion consumed wizard (stale=%v): awaiting=%v result=%+v", staleDisk, w.awaitingTest, w.testResult)
		}
		if !staleDisk {
			m.dispatch(testDoneMsg{profileID: p.ID, endpoint: w.draft, wizard: w, job: wizardJob, result: sshx.TestResult{OK: true, Reason: "draft endpoint"}})
			if w.awaitingTest || w.testResult == nil || w.testResult.Reason != "draft endpoint" {
				t.Fatal("own wizard result did not complete draft")
			}
		}
	}
}

func TestReviewScopedPreflightRechecksRevisionAndOwnership(t *testing.T) {
	for _, change := range []string{"retarget", "remove", "unrelated", "sync", "busy"} {
		t.Run(change, func(t *testing.T) {
			m := newTestModel(t)
			p := addPasswordProfile(t, m, "saved")
			if err := m.store.Save(); err != nil {
				t.Fatal(err)
			}
			id := p.ID
			_ = m.startConnect(*p)
			pending := m.pending
			msg := scopedPreflightMsg{preflightMsg: preflightMsg{id, nil}, pending: pending}
			if change == "sync" || change == "busy" {
				var release func()
				if change == "sync" {
					m.syncing = true
					release = func() { m.syncing = false }
				} else {
					l, err := fstxn.Acquire(m.cfgDir)
					if err != nil {
						t.Fatal(err)
					}
					defer l.Close()
					release = func() { l.Close() }
				}
				start := time.Now()
				_, retry := m.dispatch(msg)
				if time.Since(start) > 200*time.Millisecond || m.pending != pending || retry == nil {
					t.Fatal("preflight bypassed or blocked behind ownership gate")
				}
				release()
				deferred, ok := retry().(scopedPreflightMsg)
				if !ok || deferred.pending != pending {
					t.Fatal("deferral lost scoped operation identity")
				}
				_, handover := m.dispatch(deferred)
				if handover == nil || m.pending != nil {
					t.Fatal("current preflight did not resume after ownership released")
				}
				return
			}
			other, err := profile.LoadStore(m.cfgDir)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "retarget":
				other.ByID(id).Host = "127.0.0.2"
			case "remove":
				if _, err := other.Remove(id); err != nil {
					t.Fatal(err)
				}
			case "unrelated":
				other.ByID(id).Name = "renamed"
			}
			if err := other.Save(); err != nil {
				t.Fatal(err)
			}
			_, handover := m.dispatch(msg)
			if handover != nil || m.pending != nil || pending.job.ctx.Err() == nil {
				t.Fatal("stale preflight handed over or remained stranded")
			}
			if change == "retarget" && m.store.ByID(id).Host != "127.0.0.2" {
				t.Fatal("revision gate did not publish reload")
			}
			if change == "remove" && m.store.ByID(id) != nil {
				t.Fatal("revision gate did not reload removal")
			}
		})
	}
}
