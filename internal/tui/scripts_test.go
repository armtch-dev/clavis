package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/script"
)

func keyRunes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// "r" on the list opens the script picker for the selected host; running a
// saved script goes through the same preflight as a connect, with the script
// riding in the pending handover.
func TestRunSavedScriptPreflightsWithScriptPending(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	m.width, m.height = 100, 30
	p := addPasswordProfile(t, m, "docker-vm")
	if _, err := m.scripts.Add(script.Script{Name: "disk check", Content: "df -h"}); err != nil {
		t.Fatal(err)
	}

	m.dispatch(keyRunes("r"))
	if m.screen != scrScripts || m.scriptsUI == nil {
		t.Fatal("r did not open the script picker")
	}
	if m.scriptsUI.profileID != p.ID {
		t.Errorf("picker targets %q, want %q", m.scriptsUI.profileID, p.ID)
	}
	if out := m.View(); !strings.Contains(out, "disk check") || !strings.Contains(out, "docker-vm") {
		t.Error("picker view missing script name or target host")
	}

	_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enter on a script produced no preflight command")
	}
	if m.screen != scrList || m.scriptsUI != nil {
		t.Error("run should close the picker")
	}
	if m.pending == nil || m.pending.script == nil {
		t.Fatal("pending connect has no script payload")
	}
	if m.pending.script.name != "disk check" || m.pending.script.content != "df -h" {
		t.Errorf("pending script = %+v", m.pending.script)
	}
	if m.connecting != p.ID {
		t.Error("connecting flag not set for script run")
	}
	if !strings.Contains(m.statusMsg, "disk check") {
		t.Errorf("statusMsg = %q, want running note", m.statusMsg)
	}

	// Successful preflight must hand over via the script path.
	_, cmd = m.dispatch(preflightMsg{p.ID, nil})
	if cmd == nil {
		t.Fatal("successful preflight must produce the script handover command")
	}

	// Done message restores probing and reports the summary.
	m.dispatch(scriptDoneMsg{profileID: p.ID, summary: "“disk check” on docker-vm finished (1s)", ok: true})
	if m.statusType != statusOK || !strings.Contains(m.statusMsg, "finished") {
		t.Errorf("script done not surfaced: %q", m.statusMsg)
	}
}

// The paste-and-go path: "n" opens the editor with the textarea focused,
// pasted content runs once via ctrl+r without touching the store.
func TestPastedScriptRunsWithoutSaving(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	m.width, m.height = 100, 30
	addPasswordProfile(t, m, "docker-vm")

	m.dispatch(keyRunes("r"))
	m.dispatch(keyRunes("n"))
	if !m.scriptsUI.editing {
		t.Fatal("n did not open the editor")
	}
	m.dispatch(keyRunes("uptime"))
	_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlR})
	if cmd == nil {
		t.Fatal("ctrl+r produced no preflight command")
	}
	if m.pending == nil || m.pending.script == nil || m.pending.script.content != "uptime" {
		t.Fatalf("pending script wrong: %+v", m.pending)
	}
	if m.pending.script.name != "pasted script" {
		t.Errorf("unnamed paste should run as %q, got %q", "pasted script", m.pending.script.name)
	}
	if len(m.scripts.Scripts) != 0 {
		t.Error("ctrl+r must not save the script")
	}
}

// ctrl+d in the editor saves (name required) and persists to scripts.json.
func TestEditorSavePersists(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	m.width, m.height = 100, 30
	addPasswordProfile(t, m, "docker-vm")

	m.dispatch(keyRunes("r"))
	m.dispatch(keyRunes("n"))
	m.dispatch(keyRunes("free -m"))
	// No name yet: save must refuse, stay in the editor.
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlD})
	if !m.scriptsUI.editing || m.scriptsUI.errs == "" {
		t.Fatal("save without a name should fail in place")
	}
	m.dispatch(tea.KeyMsg{Type: tea.KeyTab}) // focus the name field
	m.dispatch(keyRunes("memory"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlD})
	if m.scriptsUI.editing {
		t.Fatal("save with a name should close the editor")
	}
	sc := m.scripts.ByName("memory")
	if sc == nil || sc.Content != "free -m" {
		t.Fatalf("script not in store: %+v", sc)
	}
	reloaded, err := script.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ByName("memory") == nil {
		t.Error("saved script not persisted to scripts.json")
	}
}

// The picker only offers scripts whose tags match the target host: untagged
// scripts everywhere, tagged scripts on hosts sharing a tag. Enter runs the
// script the cursor is actually on in the filtered list.
func TestPickerFiltersByHostTags(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	m.width, m.height = 100, 30
	p := addPasswordProfile(t, m, "docker-vm")
	p.Tags = []string{"prod"}

	for _, sc := range []script.Script{
		{Name: "anywhere", Content: "uptime"},
		{Name: "prod only", Content: "systemctl status app", Tags: []string{"Prod"}},
		{Name: "dev only", Content: "make test", Tags: []string{"dev"}},
	} {
		if _, err := m.scripts.Add(sc); err != nil {
			t.Fatal(err)
		}
	}

	m.dispatch(keyRunes("r"))
	vis := m.scriptsUI.applicable()
	if len(vis) != 2 {
		t.Fatalf("applicable = %d scripts, want 2 (universal + tag match)", len(vis))
	}
	out := m.View()
	if !strings.Contains(out, "anywhere") || !strings.Contains(out, "prod only") {
		t.Error("matching scripts missing from the picker")
	}
	if strings.Contains(out, "dev only") {
		t.Error("tag-mismatched script shown in the picker")
	}
	if !strings.Contains(out, "hidden") {
		t.Error("picker does not mention the hidden script")
	}

	// Cursor row 1 in the filtered list is "prod only" — enter must run it,
	// not whatever sits at index 1 of the raw store.
	m.dispatch(keyRunes("j"))
	_, cmd := m.dispatch(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || m.pending == nil || m.pending.script == nil {
		t.Fatal("enter did not start a script run")
	}
	if m.pending.script.name != "prod only" {
		t.Errorf("ran %q, want %q", m.pending.script.name, "prod only")
	}
}

// Tags typed in the editor are saved with the script and persist.
func TestEditorSavesTags(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	m.width, m.height = 100, 30
	addPasswordProfile(t, m, "docker-vm")

	m.dispatch(keyRunes("r"))
	m.dispatch(keyRunes("n"))
	m.dispatch(keyRunes("df -h"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyTab}) // content -> name
	m.dispatch(keyRunes("disk"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyTab}) // name -> tags
	m.dispatch(keyRunes("#prod web"))
	m.dispatch(tea.KeyMsg{Type: tea.KeyCtrlD})
	if m.scriptsUI.editing {
		t.Fatalf("save did not close the editor (err %q)", m.scriptsUI.errs)
	}
	sc := m.scripts.ByName("disk")
	if sc == nil || len(sc.Tags) != 2 || sc.Tags[0] != "prod" || sc.Tags[1] != "web" {
		t.Fatalf("tags not saved: %+v", sc)
	}
	reloaded, err := script.LoadStore(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.ByName("disk"); got == nil || len(got.Tags) != 2 {
		t.Errorf("tags not persisted to scripts.json: %+v", got)
	}
}

// Delete asks for a one-key confirmation; any other key cancels.
func TestPickerDeleteConfirms(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	m.width, m.height = 100, 30
	addPasswordProfile(t, m, "docker-vm")
	if _, err := m.scripts.Add(script.Script{Name: "victim", Content: "true"}); err != nil {
		t.Fatal(err)
	}

	m.dispatch(keyRunes("r"))
	m.dispatch(keyRunes("d"))
	m.dispatch(keyRunes("x")) // cancel
	if len(m.scripts.Scripts) != 1 {
		t.Fatal("cancelled delete removed the script")
	}
	m.dispatch(keyRunes("d"))
	m.dispatch(keyRunes("y"))
	if len(m.scripts.Scripts) != 0 {
		t.Error("confirmed delete left the script")
	}
}

// The picker and editor render inside the frame at a spread of sizes.
func TestScriptsViewResponsive(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	addPasswordProfile(t, m, "docker-vm")
	for _, name := range []string{"one", "two", "three", "four", "five", "six"} {
		if _, err := m.scripts.Add(script.Script{Name: name, Content: "echo " + name}); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range [][2]int{{40, 10}, {60, 15}, {80, 24}, {100, 30}, {140, 45}} {
		m.width, m.height = s[0], s[1]
		m.dispatch(keyRunes("r"))
		_ = m.View()
		m.dispatch(keyRunes("n"))
		_ = m.View()
		m.dispatch(tea.KeyMsg{Type: tea.KeyEsc}) // editor -> picker
		m.dispatch(tea.KeyMsg{Type: tea.KeyEsc}) // picker -> list
		if m.screen != scrList {
			t.Fatalf("%dx%d: esc did not return to the list", s[0], s[1])
		}
	}
}
