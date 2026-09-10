package tui

import (
	"testing"
	"time"

	"github.com/armtch-dev/clavis/internal/probe"
	"github.com/armtch-dev/clavis/internal/profile"
	tea "github.com/charmbracelet/bubbletea"
)

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
