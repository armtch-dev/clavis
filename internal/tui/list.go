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
	box := theme.Panel.Width(46).Render(
		theme.StatusErr.Render("Delete "+c.name) + "\n\n" +
			theme.Value.Render("Its password and key will be removed from the vault.") + "\n\n" +
			theme.Divider(40) + "\n" +
			hintKeys([][2]string{{"y", "delete"}, {"esc", "cancel"}}))
	return center(box, w, h)
}

// --- list rendering ---

func (m *Model) viewList() string {
	width := max(m.width, 40)
	var b strings.Builder

	// Header: title on the left, quiet meta on the right.
	left := theme.Title.Render("clavis")
	if m.filtering || m.filter != "" {
		cursor := ""
		if m.filtering {
			cursor = theme.Accent.Render("▌")
		}
		left += theme.Dim.Render("  filter ") + theme.Value.Render(m.filter) + cursor
	}
	var meta []string
	if !m.vault.Unlocked() {
		meta = append(meta, theme.StatusWarn.Render("locked"))
	}
	if m.cfg.Sync.Remote != "" {
		meta = append(meta, theme.Dim.Render("sync ")+theme.Value.Render(shortRemote(m.cfg.Sync.Remote)))
	}
	b.WriteString(spread(left, strings.Join(meta, theme.Dim.Render("  ·  ")), width) + "\n")
	b.WriteString(theme.Divider(width) + "\n")

	vis := m.visible()
	if len(vis) == 0 {
		empty := "No profiles yet.  Press " + theme.Key("a") + theme.Dim.Render(" to add one, or ") +
			theme.Key("i") + theme.Dim.Render(" to import from ~/.ssh/config.")
		if m.filter != "" {
			empty = theme.Dim.Render("Nothing matches “" + m.filter + "”.")
		}
		b.WriteString("\n" + theme.Dim.Render("  ") + empty + "\n")
		return b.String()
	}

	rows := m.height - 5
	if rows < 3 {
		rows = 3
	}
	start := 0
	if m.cursor >= rows {
		start = m.cursor - rows + 1
	}
	nameW := 22
	for i := start; i < len(vis) && i < start+rows; i++ {
		b.WriteString(m.renderRow(vis[i], i == m.cursor, nameW, width) + "\n")
	}
	if len(vis) > rows {
		b.WriteString(theme.Dim.Render(fmt.Sprintf("  %d–%d of %d", start+1, min(start+rows, len(vis)), len(vis))))
	}
	return b.String()
}

func (m *Model) renderRow(p profile.Profile, selected bool, nameW, width int) string {
	st, have := m.statuses[p.ID]

	dotColor, dot, latency := theme.Muted, "•", "     ·"
	if have {
		if st.Reachable {
			dotColor = theme.LatencyColor(st.LatencyMs)
			dot = "•"
			latency = fmt.Sprintf("%4.0fms", st.LatencyMs)
		} else {
			dotColor, dot, latency = theme.Red, "◦", "  down"
		}
	}
	dotCell := lipgloss.NewStyle().Foreground(dotColor).Render(dot)
	latCell := lipgloss.NewStyle().Foreground(dotColor).Width(6).Align(lipgloss.Right).Render(latency)
	sparkCell := lipgloss.NewStyle().Width(12).Render(sparkline(st.History, 12))

	name := p.Name
	if len(name) > nameW {
		name = name[:nameW-1] + "…"
	}
	nameCell := theme.Value.Width(nameW).Render(name)

	target := fmt.Sprintf("%s@%s", p.User, p.Host)
	if p.Port != 22 {
		target += fmt.Sprintf(":%d", p.Port)
	}
	endpointCell := theme.Dim.Width(26).Render(target)

	var auth []string
	if p.HasAuth(profile.AuthKey) {
		auth = append(auth, "key")
	}
	if p.HasAuth(profile.AuthPassword) {
		auth = append(auth, "pwd")
	}
	authCell := theme.Chip.Width(9).Render(strings.Join(auth, " "))

	trailing := ""
	if len(p.Tags) > 0 {
		trailing = theme.Tag.Render("#" + strings.Join(p.Tags, " #"))
	}
	if m.testing[p.ID] {
		trailing = theme.Accent.Render("testing…")
	}

	cells := []string{dotCell, latCell, sparkCell, nameCell, endpointCell, authCell, trailing}
	line := "  " + strings.Join(cells, "  ")

	if selected {
		body := lipgloss.NewStyle().Background(theme.SelBg).Foreground(theme.White).
			Width(max(width-1, 20)).Render(line)
		return theme.SelTick.Render("▎") + body
	}
	return " " + line
}

// spread lays out left and right on one line padded to width.
func spread(left, right string, width int) string {
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
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
			b.WriteString(theme.Dim.Render("╵"))
			continue
		}
		idx := 0
		if maxV > 0 {
			idx = int(v / maxV * float64(len(sparkBlocks)-1))
		}
		// Matte: a single muted foreground for the trend, not a heat ramp —
		// the dot + latency already carry the colour signal.
		b.WriteString(theme.Chip.Render(string(sparkBlocks[idx])))
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
		{"d", "delete the selected profile and its vault secrets"},
		{"t", "test the connection (dial, handshake, auth, exec)"},
		{"s", "sync now (guarded, encrypted git push)"},
		{"g", "settings — GitHub token, repo, autosync, keychain"},
		{"i", "import hosts from ~/.ssh/config"},
		{"/", "filter profiles"},
		{"j k ↑ ↓", "move"},
		{"q", "quit"},
	}
	var b strings.Builder
	b.WriteString(theme.Title.Render("Keys") + "\n\n")
	for _, r := range rows {
		b.WriteString("  " + theme.Accent.Width(9).Render(r[0]) + theme.Value.Render(r[1]) + "\n")
	}
	b.WriteString("\n" + theme.Divider(62) + "\n")
	b.WriteString(theme.Dim.Render("reachability  ") +
		lipgloss.NewStyle().Foreground(theme.Green).Render("• ") + theme.Dim.Render("<50ms   ") +
		lipgloss.NewStyle().Foreground(theme.BrYellow).Render("• ") + theme.Dim.Render("<200ms   ") +
		lipgloss.NewStyle().Foreground(theme.Red).Render("• ") + theme.Dim.Render("slower   ") +
		lipgloss.NewStyle().Foreground(theme.Red).Render("◦ ") + theme.Dim.Render("down") + "\n")
	b.WriteString(theme.Hint.Render("any key to close"))
	return theme.Panel.Width(68).Render(b.String())
}
