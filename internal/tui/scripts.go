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
	"golang.org/x/term"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/theme"
)

// scriptsModel is the "run a script" flow for one target host: a picker over
// the saved scripts, with an inline editor for new/pasted ones. Opened with
// "r" on the list; running hands the terminal over like a normal connect.
type scriptsModel struct {
	app                    *Model
	profileID, profileName string

	cursor     int
	confirmDel bool

	editing   bool   // editor pane active (new / edit / paste)
	editID    string // "" while creating
	name      textinput.Model
	area      textarea.Model
	areaFocus bool
	errs      string
}

func newScripts(app *Model, p *profile.Profile) *scriptsModel {
	return &scriptsModel{app: app, profileID: p.ID, profileName: p.Name}
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

	ta := textarea.New()
	ta.Placeholder = "#!/usr/bin/env bash\n…type or paste the script here…"
	ta.ShowLineNumbers = false
	ta.SetWidth(clamp(s.app.width-16, 28, 72))
	ta.SetHeight(clamp(s.app.height-14, 5, 14))
	ta.CharLimit = 0

	if sc != nil {
		s.editID = sc.ID
		ti.SetValue(sc.Name)
		ta.SetValue(sc.Content)
	}
	// Content is where the pasting happens — focus it first; the name can be
	// filled in on save.
	ta.Focus()
	s.name, s.area, s.areaFocus = ti, ta, true
}

func (m *Model) updateScripts(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := m.scriptsUI
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		if s.editing && s.areaFocus {
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
	list := m.scripts.Scripts

	if s.confirmDel {
		if key.String() == "y" || key.String() == "Y" {
			if s.cursor < len(list) {
				if err := m.scripts.Remove(list[s.cursor].ID); err == nil {
					m.setStatus(statusOK, "deleted script")
				}
			}
			if s.cursor >= len(m.scripts.Scripts) {
				s.cursor = max(0, len(m.scripts.Scripts)-1)
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
		if s.cursor < len(list) {
			s.openEditor(&list[s.cursor])
		}
	case "d":
		if s.cursor < len(list) {
			s.confirmDel = true
		}
	case "enter":
		if s.cursor < len(list) && m.connecting == "" {
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
		if s.areaFocus {
			s.area.Blur()
			s.name.Focus()
		} else {
			s.name.Blur()
			s.area.Focus()
		}
		s.areaFocus = !s.areaFocus
		return m, nil
	case tea.KeyCtrlD:
		sc := script.Script{ID: s.editID, Name: s.name.Value(), Content: s.area.Value()}
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
		// Run what's in the buffer once, without saving — the paste-and-go path.
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
	if s.areaFocus {
		s.area, cmd = s.area.Update(key)
	} else {
		s.name, cmd = s.name.Update(key)
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
	list := s.app.scripts.Scripts

	var b strings.Builder
	b.WriteString(theme.Title.Render("Run a script") +
		theme.Dim.Render("  on ") + theme.Accent.Render(s.profileName) + "\n\n")

	if len(list) == 0 {
		b.WriteString(theme.Hint.Render("No scripts yet. Press ") + theme.Key("n") +
			theme.Hint.Render(" to write or paste one.") + "\n")
	}
	maxRows := clamp(height-12, 3, 12)
	start := 0
	if s.cursor >= maxRows {
		start = s.cursor - maxRows + 1
	}
	for i := start; i < len(list) && i < start+maxRows; i++ {
		sc := list[i]
		line := theme.Value.Render(truncTo(sc.Name, cw/2))
		if fl := firstLine(sc.Content); fl != "" {
			line += theme.Dim.Render("  " + truncTo(fl, cw-lipgloss.Width(line)-3))
		}
		if i == s.cursor {
			b.WriteString(theme.SelTick.Render(theme.IconPointer) + " " + line + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	if len(list) > maxRows {
		b.WriteString(theme.Dim.Render(fmt.Sprintf("  %d–%d of %d", start+1, min(start+maxRows, len(list)), len(list))) + "\n")
	}

	if s.confirmDel && s.cursor < len(list) {
		b.WriteString("\n" + theme.StatusErr.Render("delete “"+list[s.cursor].Name+"”? ") +
			hintKeys([][2]string{{"y", "delete"}, {"any", "cancel"}}) + "\n")
	}

	b.WriteString("\n" + theme.Divider(cw) + "\n")
	b.WriteString(hintKeys([][2]string{
		{"enter", "run"}, {"n", "new/paste"}, {"e", "edit"}, {"d", "delete"}, {"esc", "back"},
	}))
	return center(theme.Panel.Width(inner).Render(b.String()), width, height)
}

func (s *scriptsModel) viewEditor(width, height int) string {
	inner := clamp(width-6, 44, 80)
	cw := inner - 6

	title := "New script"
	if s.editID != "" {
		title = "Edit script"
	}
	var b strings.Builder
	b.WriteString(theme.Title.Render(title) +
		theme.Dim.Render("  runs on ") + theme.Accent.Render(s.profileName) + "\n\n")
	b.WriteString(theme.Label.Render("name") + "\n" + s.name.View() + "\n\n")
	b.WriteString(theme.Label.Render("script") + theme.Hint.Render("  (paste works here)") + "\n")
	b.WriteString(s.area.View())
	if s.errs != "" {
		b.WriteString("\n\n" + theme.StatusErr.Render("✗ "+s.errs))
	}
	b.WriteString("\n\n" + theme.Divider(cw) + "\n")
	b.WriteString(hintKeys([][2]string{
		{"ctrl+r", "run without saving"}, {"ctrl+d", "save"}, {"tab", "name/script"}, {"esc", "back"},
	}))
	return center(theme.Panel.Width(inner).Render(b.String()), width, height)
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
