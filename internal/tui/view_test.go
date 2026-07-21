package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/armtch-dev/clavis/internal/probe"
	"github.com/armtch-dev/clavis/internal/profile"
)

// Status messages fade: a matching statusExpireMsg clears the message, a
// stale-generation one must not clear a newer message, and each message
// schedules exactly one expiry tick.
func TestStatusExpiry(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList

	m.setStatus(statusInfo, "first")
	if _, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24}); cmd == nil {
		t.Fatal("expected an expiry tick to be scheduled after setStatus")
	}
	if _, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24}); cmd != nil {
		t.Error("second pass scheduled another tick for the same message")
	}

	// Matching expiry clears the message.
	seq := m.statusSeq
	m.Update(statusExpireMsg{seq})
	if m.statusMsg != "" {
		t.Errorf("matching expiry left statusMsg = %q", m.statusMsg)
	}

	// A stale expiry (scheduled for an older message) must not clear a newer one.
	m.setStatus(statusInfo, "older")
	stale := m.statusSeq
	m.setStatus(statusOK, "newer")
	m.Update(statusExpireMsg{stale})
	if m.statusMsg != "newer" {
		t.Errorf("stale expiry cleared newer message, statusMsg = %q", m.statusMsg)
	}
	m.Update(statusExpireMsg{m.statusSeq})
	if m.statusMsg != "" {
		t.Errorf("current expiry left statusMsg = %q", m.statusMsg)
	}

	// While syncing the footer keeps its line; expiry leaves the message alone.
	m.setStatus(statusOK, "held")
	m.syncing = true
	m.Update(statusExpireMsg{m.statusSeq})
	if m.statusMsg != "held" {
		t.Errorf("expiry during sync cleared statusMsg, got %q", m.statusMsg)
	}
	m.syncing = false
}

// While work is in flight the footer (and testing rows) animate: the view
// must contain the current spinner frame, and Update must start/stop the
// spinner tick loop with the work.
func TestSpinnerActive(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	m.width, m.height = 80, 24

	m.syncing = true
	if out := m.View(); !strings.Contains(out, spinner.MiniDot.Frames[0]) {
		t.Error("syncing view is missing the spinner frame")
	}
	if _, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24}); cmd == nil {
		t.Fatal("expected a spinner tick to be scheduled while syncing")
	}
	if !m.spinning {
		t.Error("spinning flag not set while active")
	}

	// Work done: the next TickMsg is swallowed and the loop marked stopped.
	m.syncing = false
	if _, cmd := m.Update(spinner.TickMsg{ID: m.spin.ID()}); cmd != nil {
		t.Error("tick after work finished should be swallowed")
	}
	if m.spinning {
		t.Error("spinning flag still set after work finished")
	}
}

// Render the list at a spread of terminal sizes: no panics, the key legend is
// always present, and the frame never exceeds the terminal height.
func TestViewListResponsive(t *testing.T) {
	m := newTestModel(t)
	for _, name := range []string{"alpha", "a-fairly-long-profile-name-here", "gamma"} {
		p, err := m.store.Add(profile.Profile{
			Name: name, Host: name + ".example.com", Port: 22, User: "root",
			Auth: []profile.AuthKind{profile.AuthKey}, Tags: []string{"prod", "eu"},
		})
		if err != nil {
			t.Fatal(err)
		}
		m.statuses[p.ID] = probe.Status{ProfileID: p.ID, Reachable: true, LatencyMs: 42,
			History: []float64{10, 20, -1, 40}}
	}
	m.screen = scrList

	sizes := [][2]int{{40, 10}, {60, 15}, {80, 24}, {100, 30}, {140, 45}}
	for _, s := range sizes {
		m.width, m.height = s[0], s[1]
		out := m.View()
		if !strings.Contains(out, "quit") {
			t.Errorf("%dx%d: key legend missing", s[0], s[1])
		}
		if h := lipgloss.Height(out); h > s[1] {
			t.Errorf("%dx%d: frame is %d lines tall", s[0], s[1], h)
		}
	}

	// Wide terminal: detail side panel plus each sort mode (including the
	// tag-group headings) must render without panics and stay within the
	// terminal height. Give one host a down status with a LastSeen so the
	// relative "↓ …" cell and the detail pane's down state render too.
	vis := m.visible()
	down := vis[len(vis)-1]
	m.statuses[down.ID] = probe.Status{ProfileID: down.ID, Reachable: false,
		LastSeen: time.Now().Add(-7 * time.Minute), History: []float64{10, -1, -1}}
	if _, err := m.store.Add(profile.Profile{
		Name: "untagged-host", Host: "u.example.com", Port: 2222, User: "ops",
		Auth: []profile.AuthKind{profile.AuthPassword},
	}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []sortMode{sortDefault, sortLatency, sortTags} {
		m.sortMode = mode
		for _, s := range [][2]int{{140, 45}, {140, 12}, {130, 20}} {
			m.width, m.height = s[0], s[1]
			for c := range m.visible() {
				m.cursor = c
				out := m.View()
				if h := lipgloss.Height(out); h > s[1] {
					t.Errorf("sort=%v %dx%d cursor=%d: frame is %d lines tall", mode, s[0], s[1], c, h)
				}
			}
		}
	}
	m.width, m.height = 140, 45
	m.cursor = 0
	if out := m.View(); !strings.Contains(out, "↓ 7m") {
		t.Errorf("down host with LastSeen should show relative age, got frame without \"↓ 7m\"")
	}
	m.sortMode = sortTags
	if out := m.View(); !strings.Contains(out, "— prod —") || !strings.Contains(out, "— untagged —") {
		t.Errorf("tag-grouped mode should render group headings")
	}
	m.sortMode = sortDefault
	m.cursor = 0

	// Overlay screens should render without panicking at any size.
	for _, s := range sizes {
		m.width, m.height = s[0], s[1]
		m.help = true
		_ = m.View()
		m.help = false
		m.wizard = newWizard(m, nil)
		m.screen = scrWizard
		_ = m.View()
		m.settings = newSettings(m)
		m.screen = scrSettings
		_ = m.View()
		m.screen = scrList
	}
}
