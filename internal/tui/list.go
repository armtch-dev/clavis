package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshconfig"
	"github.com/armtch-dev/clavis/internal/theme"
)

// visible returns the filtered profile list (case-insensitive substring on
// name, host, user, tags — sshs-style).
func (m *Model) visible() []profile.Profile {
	if m.filter == "" {
		return m.store.Profiles
	}
	q := strings.ToLower(m.filter)
	var out []profile.Profile
	for _, p := range m.store.Profiles {
		hay := strings.ToLower(p.Name + " " + p.Host + " " + p.User + " " + strings.Join(p.Tags, " "))
		if strings.Contains(hay, q) {
			out = append(out, p)
		}
	}
	return out
}

func (m *Model) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	if m.filtering {
		switch key.Type {
		case tea.KeyEsc:
			m.filtering, m.filter = false, ""
		case tea.KeyEnter:
			m.filtering = false
		case tea.KeyBackspace:
			if len(m.filter) > 0 {
				m.filter = m.filter[:len(m.filter)-1]
			}
		case tea.KeyRunes:
			m.filter += string(key.Runes)
		}
		m.clampCursor()
		return m, nil
	}

	vis := m.visible()
	switch key.String() {
	case "q", "ctrl+c":
		m.quiting = true
		m.monitor.Stop()
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(vis)-1 {
			m.cursor++
		}
	case "g":
		m.settings = newSettings(m)
		m.screen = scrSettings
	case "/":
		m.filtering = true
		m.filter = ""
	case "?":
		m.help = true
	case "a":
		m.wizard = newWizard(m, nil)
		m.screen = scrWizard
	case "e":
		if p := m.selected(vis); p != nil {
			m.wizard = newWizard(m, p)
			m.screen = scrWizard
		}
	case "d":
		if p := m.selected(vis); p != nil {
			m.confirm = confirmModel{profileID: p.ID, name: p.Name}
			m.screen = scrConfirmDelete
		}
	case "t":
		if p := m.selected(vis); p != nil && !m.testing[p.ID] {
			m.testing[p.ID] = true
			m.setStatus(statusInfo, "testing "+p.Name+"…")
			return m, m.testCmd(*p)
		}
	case "s":
		return m, m.syncCmd("manual sync")
	case "i":
		m.importSSHConfig()
		return m, m.saveAll("import from ssh_config")
	case "enter":
		if p := m.selected(vis); p != nil {
			return m, m.connectCmd(*p)
		}
	}
	return m, nil
}

func (m *Model) selected(vis []profile.Profile) *profile.Profile {
	if len(vis) == 0 || m.cursor >= len(vis) {
		return nil
	}
	return m.store.ByID(vis[m.cursor].ID)
}

func (m *Model) clampCursor() {
	if n := len(m.visible()); m.cursor >= n {
		m.cursor = max(0, n-1)
	}
}

// importSSHConfig pulls non-wildcard hosts from ~/.ssh/config, storing
// identity files into the vault (works even while locked).
func (m *Model) importSSHConfig() {
	home, err := os.UserHomeDir()
	if err != nil {
		m.setStatus(statusErr, err.Error())
		return
	}
	entries, err := sshconfig.ParseFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		m.setStatus(statusErr, "import: "+err.Error())
		return
	}
	added, skipped := 0, 0
	for _, e := range entries {
		if m.store.ByName(e.Alias) != nil {
			skipped++
			continue
		}
		user := e.User
		if user == "" {
			user = os.Getenv("USER")
		}
		p := profile.Profile{
			Name: e.Alias, Host: e.HostName, Port: e.Port, User: user,
			ProxyJump: e.ProxyJump, Auth: []profile.AuthKind{profile.AuthKey},
			Tags: []string{"imported"},
		}
		np, err := m.store.Add(p)
		if err != nil {
			skipped++
			continue
		}
		if e.IdentityFile != "" {
			if raw, err := os.ReadFile(e.IdentityFile); err == nil {
				m.vault.Put(np.KeySecret(), raw)
			}
		}
		added++
	}
	m.setStatus(statusOK, fmt.Sprintf("imported %d host(s), skipped %d (duplicate/invalid)", added, skipped))
}

// --- confirm delete ---

type confirmModel struct {
	profileID, name string
}

func (m *Model) updateConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "y", "Y":
		secrets, err := m.store.Remove(m.confirm.profileID)
		if err == nil {
			for _, s := range secrets {
				m.vault.Delete(s)
			}
			m.setStatus(statusOK, "deleted "+m.confirm.name)
		}
		m.screen = scrList
		m.clampCursor()
		return m, m.saveAll("delete " + m.confirm.name)
	default:
		m.screen = scrList
	}
	return m, nil
}

func (c confirmModel) view(w, h int) string {
	box := theme.PanelBorder.Padding(1, 3).Render(
		theme.StatusErr.Bold(true).Render("Delete "+c.name+"?") + "\n\n" +
			theme.Value.Render("Its password/key will be removed from the vault.") + "\n\n" +
			theme.MutedText.Render("y = delete   any other key = cancel"))
	return center(box, w, h)
}

// --- list rendering ---

func (m *Model) viewList() string {
	title := " clavis ⚿ ssh "
	titleStyle := theme.TitleFocused
	var b strings.Builder

	head := titleStyle.Render(title)
	if m.filtering || m.filter != "" {
		head += theme.Accent.Render("  /" + m.filter)
		if m.filtering {
			head += theme.Accent.Render("▌")
		}
	}
	if m.cfg.Sync.Remote != "" {
		head += theme.MutedText.Render("  ⇅ " + shortRemote(m.cfg.Sync.Remote))
	}
	if !m.vault.Unlocked() {
		head += theme.StatusWarn.Render("  🔒 locked")
	}
	b.WriteString(head + "\n")
	b.WriteString(theme.MutedText.Render(strings.Repeat("─", max(m.width-1, 10))) + "\n")

	vis := m.visible()
	if len(vis) == 0 {
		empty := "no profiles yet — press a to add one, or i to import from ~/.ssh/config"
		if m.filter != "" {
			empty = "nothing matches /" + m.filter
		}
		b.WriteString("\n" + theme.MutedText.Render("  "+empty) + "\n")
		return b.String()
	}

	rows := m.height - 5 // header + rule + status bar + margin
	if rows < 3 {
		rows = 3
	}
	start := 0
	if m.cursor >= rows {
		start = m.cursor - rows + 1
	}
	nameW := 24
	for i := start; i < len(vis) && i < start+rows; i++ {
		p := vis[i]
		b.WriteString(m.renderRow(p, i == m.cursor, nameW) + "\n")
	}
	if len(vis) > rows {
		b.WriteString(theme.MutedText.Render(fmt.Sprintf("  … %d/%d", m.cursor+1, len(vis))))
	}
	return b.String()
}

func (m *Model) renderRow(p profile.Profile, selected bool, nameW int) string {
	st, have := m.statuses[p.ID]

	dot, latency := theme.MutedText.Render("●"), theme.MutedText.Render("   …  ")
	if have {
		if st.Reachable {
			c := lipgloss.NewStyle().Foreground(theme.LatencyColor(st.LatencyMs))
			dot = c.Render("●")
			latency = c.Render(fmt.Sprintf("%5.0fms", st.LatencyMs))
		} else {
			dot = theme.StatusErr.Render("○")
			latency = theme.StatusErr.Render("  down ")
		}
	}
	spark := sparkline(st.History, 12)

	name := p.Name
	if len(name) > nameW {
		name = name[:nameW-1] + "…"
	}
	target := fmt.Sprintf("%s@%s", p.User, p.Host)
	if p.Port != 22 {
		target += fmt.Sprintf(":%d", p.Port)
	}
	auth := ""
	if p.HasAuth(profile.AuthKey) {
		auth += "⚿"
	}
	if p.HasAuth(profile.AuthPassword) {
		auth += "🔑"
	}
	tags := ""
	if len(p.Tags) > 0 {
		tags = " #" + strings.Join(p.Tags, " #")
	}
	testing := ""
	if m.testing[p.ID] {
		testing = theme.Accent.Render(" testing…")
	}

	line := fmt.Sprintf(" %s %s %s  %-*s %s %s%s%s",
		dot, latency, spark, nameW, name,
		theme.MutedText.Render(auth), theme.Value.Render(target),
		theme.MutedText.Render(tags), testing)

	if selected {
		return theme.Selected.MaxWidth(max(m.width, 20)).Render("▸" + line)
	}
	return " " + line
}

var sparkBlocks = []rune("▁▂▃▄▅▆▇█")

// sparkline renders the last n latency samples; failures show as red ×.
func sparkline(hist []float64, n int) string {
	if len(hist) > n {
		hist = hist[len(hist)-n:]
	}
	var maxV float64
	for _, v := range hist {
		if v > maxV {
			maxV = v
		}
	}
	var b strings.Builder
	for _, v := range hist {
		if v < 0 {
			b.WriteString(theme.StatusErr.Render("×"))
			continue
		}
		idx := 0
		if maxV > 0 {
			idx = int(v / maxV * float64(len(sparkBlocks)-1))
		}
		b.WriteString(lipgloss.NewStyle().Foreground(theme.LatencyColor(v)).Render(string(sparkBlocks[idx])))
	}
	for i := len(hist); i < n; i++ {
		b.WriteString(" ")
	}
	return b.String()
}

func shortRemote(r string) string {
	r = strings.TrimSuffix(r, ".git")
	r = strings.TrimPrefix(r, "https://github.com/")
	return r
}

func center(s string, w, h int) string {
	if w <= 0 {
		return s
	}
	return lipgloss.Place(w, max(h-1, 1), lipgloss.Center, lipgloss.Center, s)
}

func (m *Model) viewHelp() string {
	rows := [][2]string{
		{"enter", "connect to the selected host"},
		{"a", "add a profile (step-by-step wizard)"},
		{"e", "edit the selected profile"},
		{"d", "delete the selected profile (and its vault secrets)"},
		{"t", "test the connection (dial → handshake → auth → exec)"},
		{"s", "sync now (guarded, encrypted git push)"},
		{"g", "settings: GitHub token, repo, autosync, keychain"},
		{"i", "import hosts from ~/.ssh/config"},
		{"/", "filter profiles"},
		{"j/k ↑/↓", "move"},
		{"q", "quit"},
	}
	var b strings.Builder
	b.WriteString(theme.TitleFocused.Render(" clavis — keys ") + "\n\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("  %s  %s\n",
			theme.Accent.Width(10).Render(r[0]), theme.Value.Render(r[1])))
	}
	b.WriteString("\n" + theme.MutedText.Render("  status dots: ● <50ms green · <200ms yellow · slower red · ○ unreachable"))
	b.WriteString("\n" + theme.MutedText.Render("  any key to close"))
	return theme.PanelBorder.Padding(1, 2).Render(b.String())
}
