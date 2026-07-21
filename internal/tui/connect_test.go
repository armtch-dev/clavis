package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/profile"
)

// addPasswordProfile stores a password-auth profile with its secret in the
// vault so credsFor succeeds without touching the network.
func addPasswordProfile(t *testing.T, m *Model, name string) *profile.Profile {
	t.Helper()
	p, err := m.store.Add(profile.Profile{
		Name: name, Host: "192.0.2.1", Port: 22, User: "root",
		Auth: []profile.AuthKind{profile.AuthPassword},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Put(p.PassSecret(), []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	return p
}

// The headline UX fix: connecting runs a preflight inside the TUI. A host
// that doesn't answer surfaces as a status-bar error on the list screen —
// the terminal is never handed to ssh, so the user never lands on a
// suspended shell watching a timeout.
func TestConnectPreflightFailureStaysInTUI(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	p := addPasswordProfile(t, m, "unreachable-host")

	cmd := m.startConnect(*p)
	if cmd == nil {
		t.Fatal("startConnect returned no preflight command")
	}
	if m.connecting != p.ID {
		t.Fatalf("connecting = %q, want %q", m.connecting, p.ID)
	}
	if !m.spinnerActive() {
		t.Error("spinner should run during preflight")
	}
	if !strings.Contains(m.statusMsg, "connecting to unreachable-host") {
		t.Errorf("statusMsg = %q, want connecting note", m.statusMsg)
	}

	// Preflight fails: back to idle, error in the status bar, still on the list.
	m.dispatch(preflightMsg{p.ID, errors.New("connection timed out (host down or firewalled?)")})
	if m.connecting != "" || m.pending != nil {
		t.Error("connect state not cleared after failed preflight")
	}
	if m.screen != scrList {
		t.Errorf("screen = %v, want scrList", m.screen)
	}
	if m.statusType != statusErr || !strings.Contains(m.statusMsg, "unreachable-host") {
		t.Errorf("status = %q (type %v), want error naming the host", m.statusMsg, m.statusType)
	}
}

func TestConnectPreflightSuccessHandsOver(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	p := addPasswordProfile(t, m, "live-host")

	if cmd := m.startConnect(*p); cmd == nil {
		t.Fatal("startConnect returned no preflight command")
	}
	_, cmd := m.dispatch(preflightMsg{p.ID, nil})
	if cmd == nil {
		t.Fatal("successful preflight must produce the terminal-handover command")
	}
	if m.connecting != "" {
		t.Error("connecting flag should clear on handover")
	}
}

// A stale preflight result (profile deleted, or superseded) must be a no-op.
func TestConnectPreflightStaleResultIgnored(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	p := addPasswordProfile(t, m, "host-a")

	if cmd := m.startConnect(*p); cmd == nil {
		t.Fatal("startConnect returned no preflight command")
	}
	_, cmd := m.dispatch(preflightMsg{"someone-else", nil})
	if cmd != nil {
		t.Error("stale preflight produced a handover command")
	}
	if m.connecting != p.ID {
		t.Error("stale preflight cleared an unrelated in-flight connect")
	}
}

// Enter is ignored while a connect is already in flight — no double preflight.
func TestEnterIgnoredWhileConnecting(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	p := addPasswordProfile(t, m, "host-a")

	if cmd := m.startConnect(*p); cmd == nil {
		t.Fatal("startConnect returned no preflight command")
	}
	pending := m.pending
	_, cmd := m.updateList(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Error("enter during an in-flight connect produced a command")
	}
	if m.pending != pending {
		t.Error("enter during an in-flight connect replaced the pending connect")
	}
}
