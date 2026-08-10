package tui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/theme"
)

// scriptsModel is both script screens, told apart by profileID:
//   - run mode ("r" on a host, profileID set): pick one of the scripts that
//     apply to that host and run it, or paste something ad hoc. Run-only —
//     no editing or deleting here.
//   - manage mode ("m" on the list, profileID empty): the full library —
//     every script regardless of tags, with create/edit/delete.
type scriptsModel struct {
	app                    *Model
	profileID, profileName string // empty in manage mode
	profileTags            []string

	cursor     int
	confirmDel bool

	editing bool   // editor pane active (new / edit / paste)
	editID  string // "" while creating
	name    textinput.Model
	tags    textinput.Model
	area    textarea.Model
	focus   int // one of focusContent/focusName/focusTags
	errs    string
}

// Editor focus cycle: the script body first (paste target), then the metadata.
const (
	focusContent = iota
	focusName
	focusTags
)

func newScripts(app *Model, p *profile.Profile) *scriptsModel {
	return &scriptsModel{app: app, profileID: p.ID, profileName: p.Name, profileTags: p.Tags}
}

func newScriptsManager(app *Model) *scriptsModel {
	return &scriptsModel{app: app}
}

// manage reports whether this is the library screen (no target host).
func (s *scriptsModel) manage() bool { return s.profileID == "" }

// applicable is the picker's view of the store. In run mode: only scripts
// whose tags match the target host (untagged scripts are universal) — that's
// what scopes a script to a set of hosts. In manage mode: everything.
func (s *scriptsModel) applicable() []script.Script {
	if s.manage() {
		return s.app.scripts.Scripts
	}
	var out []script.Script
	for _, sc := range s.app.scripts.Scripts {
		if sc.MatchesTags(s.profileTags) {
			out = append(out, sc)
		}
	}
	return out
}

func (s *scriptsModel) openEditor(sc *script.Script) {
	s.editing, s.errs = true, ""
	s.editID = ""

	ti := textinput.New()
	ti.Prompt = "› "
	ti.PromptStyle = theme.Accent
	ti.TextStyle = theme.Value
	ti.Cursor.Style = theme.Accent
	ti.Placeholder = "script name"

	tg := textinput.New()
	tg.Prompt = "› "
	tg.PromptStyle = theme.Accent
	tg.TextStyle = theme.Value
	tg.Cursor.Style = theme.Accent
	tg.Placeholder = "tags (space-separated; empty = any host)"

	ta := textarea.New()
	ta.Placeholder = "#!/usr/bin/env bash\n…type or paste the script here…"
	ta.ShowLineNumbers = false
	ta.SetWidth(clamp(s.app.width-16, 28, 72))
	ta.SetHeight(clamp(s.app.height-17, 4, 14))
	ta.CharLimit = 0

	if sc != nil {
		s.editID = sc.ID
		ti.SetValue(sc.Name)
		tg.SetValue(strings.Join(sc.Tags, " "))
		ta.SetValue(sc.Content)
	}
	// Content is where the pasting happens — focus it first; the name and
	// tags can be filled in on save.
	ta.Focus()
	s.name, s.tags, s.area, s.focus = ti, tg, ta, focusContent
}

func (m *Model) updateScripts(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := m.scriptsUI
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		if s.editing && s.focus == focusContent {
			var cmd tea.Cmd
			s.area, cmd = s.area.Update(msg)
			return m, cmd
		}
		return m, nil
	}
	if s.editing {
		return m.updateScriptEditor(key)
	}
	return m.updateScriptPicker(key)
}

func (m *Model) updateScriptPicker(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := m.scriptsUI
	list := s.applicable()

	if s.confirmDel {
		if key.String() == "y" || key.String() == "Y" {
			if s.cursor < len(list) {
				if err := m.scripts.Remove(list[s.cursor].ID); err == nil {
					m.setStatus(statusOK, "deleted script")
				}
			}
			if n := len(s.applicable()); s.cursor >= n {
				s.cursor = max(0, n-1)
			}
			s.confirmDel = false
			return m, m.saveScripts("delete script")
		}
		s.confirmDel = false
		return m, nil
	}

	switch key.String() {
	case "esc", "q":
		m.scriptsUI = nil
		m.screen = scrList
	case "up", "k":
		if s.cursor > 0 {
			s.cursor--
		}
	case "down", "j":
		if s.cursor < len(list)-1 {
			s.cursor++
		}
	case "n", "p":
		s.openEditor(nil)
	case "e":
		// Editing lives in the manager; the run picker stays run-only.
		if s.manage() && s.cursor < len(list) {
			s.openEditor(m.scripts.ByID(list[s.cursor].ID))
		}
	case "d":
		if s.manage() && s.cursor < len(list) {
			s.confirmDel = true
		}
	case "enter":
		if s.cursor >= len(list) {
			break
		}
		if s.manage() {
			s.openEditor(m.scripts.ByID(list[s.cursor].ID))
			break
		}
		if m.connecting == "" {
			sc := list[s.cursor]
			m.scriptsUI = nil
			m.screen = scrList
			return m, m.startRunScript(s.profileID, sc.Name, sc.Content)
		}
	}
	return m, nil
}

func (m *Model) updateScriptEditor(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := m.scriptsUI
	switch key.Type {
	case tea.KeyEsc:
		s.editing, s.errs = false, ""
		return m, nil
	case tea.KeyTab:
		s.area.Blur()
		s.name.Blur()
		s.tags.Blur()
		s.focus = (s.focus + 1) % 3
		switch s.focus {
		case focusContent:
			s.area.Focus()
		case focusName:
			s.name.Focus()
		case focusTags:
			s.tags.Focus()
		}
		return m, nil
	case tea.KeyCtrlD:
		sc := script.Script{ID: s.editID, Name: s.name.Value(), Content: s.area.Value(),
			Tags: script.ParseTags(s.tags.Value())}
		var err error
		if s.editID != "" {
			err = m.scripts.Update(sc)
		} else {
			_, err = m.scripts.Add(sc)
		}
		if err != nil {
			s.errs = err.Error()
			return m, nil
		}
		s.editing = false
		m.setStatus(statusOK, "saved script "+sc.Name)
		return m, m.saveScripts("save script " + sc.Name)
	case tea.KeyCtrlR:
		// Run what's in the buffer once, without saving — the paste-and-go
		// path. Only meaningful with a target host, i.e. not in the manager.
		if s.manage() {
			return m, nil
		}
		content := s.area.Value()
		if strings.TrimSpace(content) == "" {
			s.errs = "script is empty"
			return m, nil
		}
		if m.connecting != "" {
			return m, nil
		}
		name := strings.TrimSpace(s.name.Value())
		if name == "" {
			name = "pasted script"
		}
		profileID := s.profileID
		m.scriptsUI = nil
		m.screen = scrList
		return m, m.startRunScript(profileID, name, content)
	}
	var cmd tea.Cmd
	switch s.focus {
	case focusContent:
		s.area, cmd = s.area.Update(key)
	case focusName:
		s.name, cmd = s.name.Update(key)
	case focusTags:
		s.tags, cmd = s.tags.Update(key)
	}
	return m, cmd
}

// --- view ---

func (s *scriptsModel) view(width, height int) string {
	if s.editing {
		return s.viewEditor(width, height)
	}
	return s.viewPicker(width, height)
}

func (s *scriptsModel) viewPicker(width, height int) string {
	inner := clamp(width-6, 44, 76)
	cw := inner - 6
	list := s.applicable()
	hidden := len(s.app.scripts.Scripts) - len(list)

	var b strings.Builder
	var title string
	if s.manage() {
		title = theme.Title.Render("Scripts") +
			theme.Dim.Render(fmt.Sprintf("  %d in the library", len(list)))
	} else {
		title = theme.Title.Render("Run a script") +
			theme.Dim.Render("  on ") + theme.Accent.Render(s.profileName)
		if len(s.profileTags) > 0 {
			title += theme.Tag.Render("  #" + strings.Join(s.profileTags, " #"))
		}
	}
	// Long names/tags must clip, not wrap: a wrapped line inside the panel
	// pushes every line below it down and breaks the height budget.
	b.WriteString(ansi.Truncate(title, cw, "…"))
	b.WriteString("\n\n")

	if len(list) == 0 {
		switch {
		case !s.manage() && hidden > 0:
			b.WriteString(theme.Hint.Render("No scripts apply to this host. Press ") + theme.Key("n") +
				theme.Hint.Render(" to paste one, or manage tags via ") + theme.Key("m") +
				theme.Hint.Render(" on the list.") + "\n")
		case s.manage():
			b.WriteString(theme.Hint.Render("No scripts yet. Press ") + theme.Key("n") +
				theme.Hint.Render(" to create one.") + "\n")
		default:
			b.WriteString(theme.Hint.Render("No scripts yet. Press ") + theme.Key("n") +
				theme.Hint.Render(" to write or paste one.") + "\n")
		}
	}
	maxRows := clamp(height-12, 3, 12)
	start := 0
	if s.cursor >= maxRows {
		start = s.cursor - maxRows + 1
	}
	for i := start; i < len(list) && i < start+maxRows; i++ {
		sc := list[i]
		line := theme.Value.Render(truncTo(sc.Name, cw/2))
		if len(sc.Tags) > 0 {
			line += theme.Tag.Render("  #" + strings.Join(sc.Tags, " #"))
		}
		if fl := firstLine(sc.Content); fl != "" && cw-lipgloss.Width(line)-3 > 6 {
			line += theme.Dim.Render("  " + truncTo(fl, cw-lipgloss.Width(line)-3))
		}
		// Same selection treatment as the profile list (▎ + bg fill) — one
		// selection language across the app.
		if i == s.cursor {
			b.WriteString(theme.Accent.Render("▎") + selFill(ansi.Truncate(" "+line, cw-1, "…"), cw-1) + "\n")
		} else {
			b.WriteString("  " + ansi.Truncate(line, cw-2, "…") + "\n")
		}
	}
	if len(list) > maxRows {
		b.WriteString(theme.Dim.Render(fmt.Sprintf("  %d–%d of %d", start+1, min(start+maxRows, len(list)), len(list))) + "\n")
	}
	if !s.manage() && hidden > 0 {
		b.WriteString(ansi.Truncate(
			theme.Dim.Render(fmt.Sprintf("  %d more in the library don't apply to this host", hidden)), cw, "…") + "\n")
	}

	if s.confirmDel && s.cursor < len(list) {
		b.WriteString("\n" + ansi.Truncate(theme.StatusErr.Render("delete “"+list[s.cursor].Name+"”? ")+
			hintKeys([][2]string{{"y", "delete"}, {"any", "cancel"}}), cw, "…") + "\n")
	}

	b.WriteString("\n" + theme.Divider(cw) + "\n")
	if s.manage() {
		b.WriteString(fitHints(cw,
			[][2]string{{"enter", "edit"}, {"n", "new"}, {"d", "delete"}, {"esc", "back"}},
			[][2]string{{"enter", "edit"}, {"n", "new"}, {"d", "del"}, {"esc", "back"}}))
	} else {
		b.WriteString(fitHints(cw,
			[][2]string{{"enter", "run"}, {"n", "paste & run"}, {"esc", "back"}},
			[][2]string{{"enter", "run"}, {"n", "paste"}, {"esc", "back"}}))
	}
	return center(theme.Panel.Width(inner).Render(b.String()), width, height)
}

func (s *scriptsModel) viewEditor(width, height int) string {
	inner := clamp(width-6, 44, 80)
	cw := inner - 6

	title := "New script"
	if s.editID != "" {
		title = "Edit script"
	}
	// Fit the frame to the space the footer leaves us: the fixed lines around
	// the textarea (title, name/tags fields, script label, divider, hints,
	// panel border+padding) total 16, plus 2 when the error line is showing.
	// Sizing here rather than in openEditor keeps the panel correct when the
	// footer grows a status line mid-edit.
	overhead := 16
	if s.errs != "" {
		overhead += 2
	}
	s.area.SetHeight(clamp(height-overhead, 3, 14))

	var b strings.Builder
	// Composed lines clip rather than wrap — a wrap inside the panel breaks
	// the height budget the textarea was sized against.
	head := theme.Title.Render(title)
	if !s.manage() {
		head += theme.Dim.Render("  runs on ") + theme.Accent.Render(s.profileName)
	}
	b.WriteString(ansi.Truncate(head, cw, "…") + "\n\n")
	b.WriteString(theme.Label.Render("name") + "\n" + s.name.View() + "\n\n")
	b.WriteString(ansi.Truncate(theme.Label.Render("tags")+
		theme.Hint.Render("  (runs on hosts sharing a tag; empty = any host)"), cw, "…") + "\n" + s.tags.View() + "\n\n")
	b.WriteString(theme.Label.Render("script") + theme.Hint.Render("  (paste works here)") + "\n")
	b.WriteString(s.area.View())
	if s.errs != "" {
		b.WriteString("\n\n" + ansi.Truncate(theme.StatusErr.Render("✗ "+s.errs), cw, "…"))
	}
	b.WriteString("\n\n" + theme.Divider(cw) + "\n")
	if s.manage() {
		b.WriteString(fitHints(cw,
			[][2]string{{"ctrl+d", "save"}, {"tab", "next field"}, {"esc", "back"}},
			[][2]string{{"^d", "save"}, {"tab", "next"}, {"esc", "back"}}))
	} else {
		b.WriteString(fitHints(cw,
			[][2]string{{"ctrl+r", "run without saving"}, {"ctrl+d", "save"}, {"tab", "next field"}, {"esc", "back"}},
			[][2]string{{"^r", "run"}, {"^d", "save"}, {"tab", "next"}, {"esc", "back"}}))
	}
	return center(theme.Panel.Width(inner).Render(b.String()), width, height)
}

// fitHints renders the full hint row when it fits the panel's content width,
// falling back to the compact wording — a wrapped hint line inside a panel
// breaks the height budget the rest of the layout was sized against.
func fitHints(cw int, full, compact [][2]string) string {
	if s := hintKeys(full); lipgloss.Width(s) <= cw {
		return s
	}
	return ansi.Truncate(hintKeys(compact), cw, "…")
}

func firstLine(content string) string {
	for _, l := range strings.Split(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		return l
	}
	return ""
}

// --- run flow ---

// startRunScript mirrors startConnect: resolve creds, preflight in the TUI,
// and only hand the terminal over once the host answers. The pending script
// rides along in pendingConnect.
func (m *Model) startRunScript(profileID, name, content string) tea.Cmd {
	p := m.store.ByID(profileID)
	if p == nil {
		m.setStatus(statusErr, "profile no longer exists")
		return nil
	}
	if p.ProxyJump != "" {
		m.setStatus(statusErr, "script runs through a ProxyJump are not supported yet")
		return nil
	}
	creds, err := m.credsFor(p)
	if err != nil {
		m.setStatus(statusErr, err.Error())
		return nil
	}
	m.connecting = p.ID
	m.pending = &pendingConnect{p: *p, creds: creds, script: &runScript{name: name, content: content}}
	m.monitor.Suspend(p.ID, true)
	m.setStatus(statusInfo, "running “"+name+"” on "+p.Name+"…")
	addr := p.Addr()
	return func() tea.Msg {
		return preflightMsg{p.ID, sshx.Preflight(addr, preflightTimeout)}
	}
}

// runScript is the script payload attached to a pending connect.
type runScript struct {
	name, content string
}

type scriptDoneMsg struct {
	profileID   string
	hostKeyFP   string
	hostKeyLine string
	summary     string
	ok          bool
}

// scriptSessionCmd hands the terminal over to run the script; like a normal
// session, probing stays suspended until the done message.
func (m *Model) scriptSessionCmd(pc pendingConnect) tea.Cmd {
	sess := &scriptSession{p: pc.p, creds: pc.creds, name: pc.script.name, content: pc.script.content}
	return tea.Exec(sess, func(error) tea.Msg {
		return scriptDoneMsg{pc.p.ID, sess.fp, sess.keyLine, sess.summary, sess.ok}
	})
}

// scriptSession runs outside bubbletea's raw-mode/altscreen (tea.Exec): it
// streams the script's output to the real terminal, then blocks on a single
// keypress so the user can read the output before the TUI repaints over it.
type scriptSession struct {
	p             profile.Profile
	creds         sshx.Credentials
	name, content string

	fp, keyLine string
	summary     string
	ok          bool
}

func (s *scriptSession) Run() error {
	defer func() { s.creds = sshx.Credentials{} }()
	width := 60
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		width = clamp(w-2, 20, 100)
	}
	target := fmt.Sprintf("%s@%s:%d", s.p.User, s.p.Host, s.p.Port)
	fmt.Println(theme.Accent.Render("◇ "+s.name) + theme.Dim.Render("  "+target))
	fmt.Println(theme.Divider(width))

	start := time.Now()
	fp, line, code, err := sshx.RunScript(s.p, s.creds, s.content, os.Stdout, os.Stderr, preflightTimeout*2)
	s.fp, s.keyLine = fp, line
	elapsed := time.Since(start).Round(10 * time.Millisecond)

	fmt.Println(theme.Divider(width))
	switch {
	case err != nil:
		s.summary = fmt.Sprintf("“%s” on %s failed: %s", s.name, s.p.Name, err)
		fmt.Println(theme.StatusErr.Render("✗ " + err.Error()))
	case code != 0:
		s.summary = fmt.Sprintf("“%s” on %s exited %d (%s)", s.name, s.p.Name, code, elapsed)
		fmt.Println(theme.StatusErr.Render(fmt.Sprintf("✗ exit %d", code)) + theme.Dim.Render("  "+elapsed.String()))
	default:
		s.ok = true
		s.summary = fmt.Sprintf("“%s” on %s finished (%s)", s.name, s.p.Name, elapsed)
		fmt.Println(theme.StatusOK.Render("✓ exit 0") + theme.Dim.Render("  "+elapsed.String()))
	}

	fmt.Println(theme.Hint.Render("press any key to return to clavis"))
	waitAnyKey(os.Stdin)
	return nil // failures are reported via summary; not an exec error
}

// waitAnyKey blocks until one byte arrives from the terminal. Raw mode so a
// bare keypress (no enter) suffices; skipped silently when stdin isn't a tty.
func waitAnyKey(in *os.File) {
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		return
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return
	}
	defer term.Restore(fd, old)
	buf := make([]byte, 1)
	in.Read(buf)
}

// The session writes to the real TTY; bubbletea's redirects are moot.
func (s *scriptSession) SetStdin(io.Reader)  {}
func (s *scriptSession) SetStdout(io.Writer) {}
func (s *scriptSession) SetStderr(io.Writer) {}

// saveScripts persists scripts.json and, when autosync is on, syncs it along.
func (m *Model) saveScripts(what string) tea.Cmd {
	if err := m.scripts.Save(); err != nil {
		m.setStatus(statusErr, "save failed: "+err.Error())
		return nil
	}
	if m.cfg.Sync.AutoSync && m.cfg.Sync.Remote != "" {
		return m.syncCmd("clavis: " + what)
	}
	return nil
}
