package tui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/armtch-dev/clavis/internal/fido2"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	tea "github.com/charmbracelet/bubbletea"
)

// Hardware moved to commands must not hold shutdown open or publish an
// enrollment after cancellation. Only fake tools and a temporary vault run.
func TestPhase5CloseCancelsHardwareBeforePublication(t *testing.T) {
	dir := installFido2Fakes(t)
	started := filepath.Join(dir, "started")
	writeFakeTool(t, dir, "fido2-token", "#!/bin/sh\ntouch '"+started+"'\nexec sleep 30\n")
	m := newTestModel(t)
	id, err := m.vault.Identity()
	if err != nil {
		t.Fatal(err)
	}
	cmd := m.hardwareCmd(&hardwareRequest{action: "enroll"}, id)
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fake hardware never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown blocked on hardware")
	}
	result := (<-done).(hardwareDoneMsg)
	if result.err == nil || fido2.Enrolled(m.cfgDir) {
		t.Fatal("canceled hardware succeeded or published enrollment")
	}
}

// A retained executable draft must neither disappear on Back nor inherit a
// different list selection (or a retargeted version of its original profile).
func TestPhase5DraftRetainsContentAndActionTarget(t *testing.T) {
	m := newTestModel(t)
	m.screen, m.width, m.height = scrList, 80, 24
	p := addPasswordProfile(t, m, "original")
	id := p.ID
	m.dispatch(keyRunes("r"))
	m.dispatch(keyRunes("n"))
	draft := m.scriptsUI
	draft.area.SetValue("printf 'retained draft\\n'")
	m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
	m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
	other := addPasswordProfile(t, m, "other")
	m.selectedID = other.ID
	m.dispatch(keyRunes("D"))
	if m.scriptsUI != draft || draft.profileID != id || draft.area.Value() != "printf 'retained draft\\n'" {
		t.Fatal("resuming lost the draft or changed its target")
	}
	m.store.ByID(id).Host = "different.invalid"
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
	if m.pending != nil || !draft.editing || draft.errs == "" || m.scriptDraft != draft {
		t.Fatal("retargeted draft ran or was discarded")
	}
}

// Reloading a same-ID replacement must not authorize the retained picker to run.
func TestPhase5RetainedPickerRejectsSameIDRetarget(t *testing.T) {
	m := newTestModel(t)
	m.screen, m.width, m.height = scrList, 80, 24
	p := addPasswordProfile(t, m, "original")
	if err := m.store.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.scripts.Add(script.Script{Name: "saved", Content: "uptime"}); err != nil {
		t.Fatal(err)
	}
	if err := m.scripts.Save(); err != nil {
		t.Fatal(err)
	}
	m.dispatch(keyRunes("r"))
	m.dispatch(keyRunes("n"))
	picker := m.scriptsUI
	picker.area.SetValue("unsaved draft")
	m.dispatch(tea.KeyMsg{Type: tea.KeyEsc}) // retain the draft in its run picker
	disk, err := profile.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	changed := *disk.ByID(p.ID)
	changed.Host = "replacement.invalid"
	if err := disk.Update(changed); err != nil {
		t.Fatal(err)
	}
	if err := disk.Save(); err != nil {
		t.Fatal(err)
	}
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter}) // external-change reload consumes this key
	if m.store.ByID(p.ID).Host != changed.Host || m.scriptsUI != picker {
		t.Fatal("fixture did not reload the replacement endpoint with the picker retained")
	}
	_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil || m.pending != nil || m.connecting != "" {
		t.Fatal("retained picker launched a script on the same-ID replacement endpoint")
	}
	if m.screen != scrScripts || m.scriptsUI != picker || picker.errs == "" ||
		m.scriptDraft != picker || picker.area.Value() != "unsaved draft" {
		t.Fatal("target rejection lost the picker, error, or retained draft")
	}
}

// Recover-as-copy must preserve the original script's concurrent disk edit.
func TestPhase5StaleDraftRecoveryCreatesCopy(t *testing.T) {
	m := newTestModel(t)
	m.screen, m.width, m.height = scrList, 80, 24
	sc, err := m.scripts.Add(script.Script{Name: "original", Content: "old"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.scripts.Save(); err != nil {
		t.Fatal(err)
	}
	m.dispatch(keyRunes("m"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	draft := m.scriptsUI
	draft.area.SetValue("unsaved")
	m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
	m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
	disk, err := script.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	changed := *disk.ByID(sc.ID)
	changed.Content = "concurrent"
	if err := disk.Update(changed); err != nil {
		t.Fatal(err)
	}
	if err := disk.Save(); err != nil {
		t.Fatal(err)
	}
	m.dispatch(keyRunes("D")) // reload consumes this intent; retry explicitly
	m.dispatch(keyRunes("D"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlS})
	if !draft.editing || draft.area.Value() != "unsaved" {
		t.Fatal("stale save lost the draft")
	}
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlN})
	draft.name.SetValue("recovered copy")
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlS})
	disk, err = script.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	copy := disk.ByName("recovered copy")
	if disk.ByID(sc.ID).Content != "concurrent" || copy == nil || copy.Content != "unsaved" || copy.ID == sc.ID {
		t.Fatal("copy recovery overwrote the original or lost draft content")
	}
}
