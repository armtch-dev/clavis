package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/profile"
)

// "c" opens an inline prompt that sets the selected host's category without
// the wizard, persists it, and category-sort groups by it (not by tags).
func TestInlineCategoryPromptAndGrouping(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	m.width, m.height = 100, 30
	p := addPasswordProfile(t, m, "docker-vm")
	p.Tags = []string{"prod"} // tags must stay separate from the category

	m.dispatch(keyRunes("c"))
	if m.catTarget != p.ID {
		t.Fatal("c did not open the category prompt for the selected host")
	}
	m.dispatch(keyRunes("#local"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if m.catTarget != "" {
		t.Fatal("enter did not close the prompt")
	}
	if got := m.store.ByID(p.ID).Category; got != "local" {
		t.Errorf("category = %q, want %q (\"#\" stripped)", got, "local")
	}

	reloaded, err := profile.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ByID(p.ID).Category != "local" {
		t.Error("category not persisted to profiles.json")
	}

	// Grouping uses the category, not the tag.
	m.sortMode = sortCategory
	out := m.View()
	if !strings.Contains(out, "— local —") {
		t.Error("category heading missing")
	}
	if strings.Contains(out, "— prod —") {
		t.Error("grouped by tag, not category")
	}

	// esc cancels without changing anything.
	m.dispatch(keyRunes("c"))
	m.dispatch(keyRunes("x"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyEsc})
	if m.store.ByID(p.ID).Category != "local" {
		t.Error("esc changed the category")
	}
}
