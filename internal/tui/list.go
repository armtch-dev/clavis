package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshconfig"
	"github.com/armtch-dev/clavis/internal/theme"
)

// sortMode cycles on "o": stored order, latency (fastest reachable first),
// or grouped by first tag.
type sortMode int

const (
	sortDefault sortMode = iota
	sortLatency
	sortTags
)

func (s sortMode) String() string {
	switch s {
	case sortLatency:
		return "latency"
	case sortTags:
		return "tag groups"
	default:
		return "default order"
	}
}

// visible returns the filtered profile list (case-insensitive substring on
// name, host, user, tags — sshs-style), in the current sort order.
func (m *Model) visible() []profile.Profile {
	base := m.store.Profiles
	if m.filter != "" {
		q := strings.ToLower(m.filter)
		var out []profile.Profile
		for _, p := range base {
			hay := strings.ToLower(p.Name + " " + p.Host + " " + p.User + " " + strings.Join(p.Tags, " "))
			if strings.Contains(hay, q) {
				out = append(out, p)
			}
		}
		base = out
	}
	return m.sortProfiles(base)
}

// sortProfiles reorders a copy of in according to m.sortMode; the stored
// order is left untouched.
func (m *Model) sortProfiles(in []profile.Profile) []profile.Profile {
	if m.sortMode == sortDefault || len(in) < 2 {
		return in
	}
	out := append([]profile.Profile(nil), in...)
	switch m.sortMode {
	case sortLatency:
		// Reachable fastest first, then unknown, then down.
		rank := func(p profile.Profile) (int, float64) {
			st, ok := m.statuses[p.ID]
			switch {
			case ok && st.Reachable:
				return 0, st.LatencyMs
			case !ok:
				return 1, 0
			default:
				return 2, 0
			}
		}
		sort.SliceStable(out, func(i, j int) bool {
			ri, li := rank(out[i])
			rj, lj := rank(out[j])
			if ri != rj {
				return ri < rj
			}
			return li < lj
		})
	case sortTags:
		// Grouped by first tag alphabetically; untagged sinks to the bottom.
		sort.SliceStable(out, func(i, j int) bool {
			ti, tj := len(out[i].Tags) > 0, len(out[j].Tags) > 0
			if ti != tj {
				return ti
			}
			if !ti {
				return false
			}
			return out[i].Tags[0] < out[j].Tags[0]
		})
	}
	return out
}

// groupTag names the tag group a profile belongs to in sortTags mode.
func groupTag(p profile.Profile) string {
	if len(p.Tags) == 0 {
		return "untagged"
	}
	return p.Tags[0]
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
	case "o":
		m.sortMode = (m.sortMode + 1) % 3
		m.clampCursor()
		m.setStatus(statusInfo, "sort: "+m.sortMode.String())
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
		if p := m.selected(vis); p != nil && m.connecting == "" {
			return m, m.startConnect(*p)
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

// listLayout captures everything about the list that adapts to the terminal
// size: horizontal padding, column widths, which columns fit at all, and
// whether there is vertical room for breathing space and column headers.
type listLayout struct {
	width, pad  int    // total width, left/right padding
	listW       int    // width of the row region (== width unless showDetail)
	nameW, endW int    // name and user@host column widths
	sparkW      int    // sparkline sample count / cell width
	detailW     int    // detail pane width (content, excl. its left border)
	gap         string // inter-column gap, wider on large terminals
	showSpark   bool
	showTags    bool
	showColHead bool
	showDetail  bool // very wide terminal: detail side panel on the right
	roomy       bool // tall terminal: extra blank line under the header
}

func (m *Model) layoutList() listLayout {
	w := max(m.width, 40)
	l := listLayout{width: w, listW: w, gap: "  "}
	switch {
	case w < 60:
		l.pad = 1
	case w < 90:
		l.pad = 2
	default:
		l.pad = 3
	}
	if w >= 100 {
		l.gap = "   "
	}
	l.roomy = m.height >= 22
	l.showSpark = w >= 80
	l.showTags = w >= 96
	l.showColHead = m.height >= 16 && w >= 70
	if w >= 130 {
		l.showDetail = true
		l.detailW = clamp(w/4, 36, 40)
		l.listW = w - l.detailW - 1 // -1 for the pane's left hairline
	}
	l.nameW = clamp(l.listW/5, 14, 28)
	l.endW = clamp(l.listW/4+4, 20, 38)
	l.sparkW = 12
	if l.listW >= 110 {
		l.sparkW = 16
	}
	return l
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (m *Model) viewList() string {
	l := m.layoutList()
	pad := strings.Repeat(" ", l.pad)
	var b strings.Builder

	// Header: title on the left, quiet meta on the right.
	left := pad + theme.Title.Render("clavis")
	if m.filtering || m.filter != "" {
		cursor := ""
		if m.filtering {
			cursor = theme.Accent.Render("▌")
		}
		left += theme.Dim.Render("  filter ") + theme.Value.Render(m.filter) + cursor
	}
	var meta []string
	if n := len(m.store.Profiles); n > 0 {
		up := 0
		for _, p := range m.store.Profiles {
			if st, ok := m.statuses[p.ID]; ok && st.Reachable {
				up++
			}
		}
		count := fmt.Sprintf("%d host", n)
		if n != 1 {
			count += "s"
		}
		if up > 0 {
			count = fmt.Sprintf("%s · %d up", count, up)
		}
		meta = append(meta, theme.Dim.Render(count))
	}
	if !m.vault.Unlocked() {
		meta = append(meta, theme.StatusWarn.Render(theme.IconLock+" locked"))
	}
	if m.cfg.Sync.Remote != "" {
		meta = append(meta, theme.Dim.Render(theme.IconSync+" ")+theme.Value.Render(shortRemote(m.cfg.Sync.Remote)))
	}
	b.WriteString(spread(left, strings.Join(meta, theme.Dim.Render("  ·  "))+pad, l.width) + "\n")
	b.WriteString(theme.Divider(l.width) + "\n")
	headerH := 2
	if l.roomy {
		b.WriteString("\n")
		headerH++
	}

	vis := m.visible()
	avail := m.height - headerH - m.footerHeight()
	if len(vis) == 0 {
		empty := "No profiles yet.  Press " + theme.Key("a") + theme.Dim.Render(" to add one, or ") +
			theme.Key("i") + theme.Dim.Render(" to import from ~/.ssh/config.")
		if m.filter != "" {
			empty = theme.Dim.Render("Nothing matches “" + m.filter + "”.")
		}
		if avail > 4 {
			b.WriteString(lipgloss.Place(l.width, avail, lipgloss.Center, lipgloss.Center, empty))
		} else {
			b.WriteString("\n" + pad + " " + empty + "\n")
		}
		return b.String()
	}

	region := m.renderRowRegion(vis, l, avail)
	if l.showDetail {
		left := lipgloss.NewStyle().Width(l.listW).MaxHeight(max(avail, 1)).Render(region)
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, m.renderDetail(m.selected(vis), l, avail)))
	} else {
		b.WriteString(region)
	}
	return b.String()
}

// listEntry is one display line of the row region: either a profile row
// (idx into vis) or, in tag-grouped mode, a muted group heading.
type listEntry struct {
	heading string // non-empty for a group heading line
	idx     int
}

// listEntries expands vis into display lines, inserting a heading before
// each tag group when sortTags is active.
func (m *Model) listEntries(vis []profile.Profile) []listEntry {
	if m.sortMode != sortTags {
		out := make([]listEntry, len(vis))
		for i := range vis {
			out[i] = listEntry{idx: i}
		}
		return out
	}
	out := make([]listEntry, 0, len(vis)+4)
	prev := ""
	for i, p := range vis {
		if g := groupTag(p); i == 0 || g != prev {
			out = append(out, listEntry{heading: g})
			prev = g
		}
		out = append(out, listEntry{idx: i})
	}
	return out
}

// renderRowRegion renders the column header, the visible window of rows
// (and group headings), and the scroll indicator — at most avail lines.
func (m *Model) renderRowRegion(vis []profile.Profile, l listLayout, avail int) string {
	var b strings.Builder
	if l.showColHead {
		b.WriteString(m.colHeader(l) + "\n")
		avail--
	}

	entries := m.listEntries(vis)
	rows := avail
	if rows < 3 {
		rows = 3
	}
	if len(entries) > rows {
		rows = max(rows-1, 2) // reserve a line for the scroll indicator
	}
	cursorEnt := 0
	for i, e := range entries {
		if e.heading == "" && e.idx == m.cursor {
			cursorEnt = i
			break
		}
	}
	start := 0
	if cursorEnt >= rows {
		start = cursorEnt - rows + 1
	}
	end := min(start+rows, len(entries))
	lead := strings.Repeat(" ", max(l.pad-1, 0))
	first, last := -1, -1
	for i := start; i < end; i++ {
		e := entries[i]
		if e.heading != "" {
			b.WriteString(lead + "  " + theme.Hint.Render("— "+e.heading+" —") + "\n")
			continue
		}
		if first < 0 {
			first = e.idx
		}
		last = e.idx
		b.WriteString(m.renderRow(vis[e.idx], e.idx == m.cursor, l) + "\n")
	}
	if len(entries) > rows && first >= 0 {
		pad := strings.Repeat(" ", l.pad)
		b.WriteString(pad + " " + theme.Dim.Render(fmt.Sprintf("%d–%d of %d", first+1, last+1, len(vis))))
	}
	return b.String()
}

// renderDetail draws the right-hand side panel for the selected profile on
// very wide terminals: a matte pane separated by a thin left hairline,
// sharing the row region's vertical space exactly.
func (m *Model) renderDetail(p *profile.Profile, l listLayout, avail int) string {
	avail = max(avail, 1)
	pane := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(theme.Border).
		Padding(0, 2).
		Width(l.detailW).
		Height(avail).
		MaxHeight(avail)
	cw := l.detailW - 4 // content width inside the padding
	if p == nil {
		return pane.Render(theme.Hint.Render("no profile selected"))
	}

	label := func(s string) string { return theme.Label.Width(6).Render(s) }
	var b strings.Builder
	b.WriteString(theme.Accent.Render(truncTo(p.Name, cw)) + "\n")
	target := fmt.Sprintf("%s@%s:%d", p.User, p.Host, p.Port)
	b.WriteString(theme.Value.Render(truncTo(target, cw)) + "\n")
	b.WriteString(theme.Divider(cw) + "\n")

	var auth []string
	if p.HasAuth(profile.AuthKey) {
		auth = append(auth, theme.IconKey+" key")
	}
	if p.HasAuth(profile.AuthPassword) {
		auth = append(auth, theme.IconPwd+" password")
	}
	if len(auth) == 0 {
		auth = append(auth, "none")
	}
	b.WriteString(label("auth") + theme.Value.Render(strings.Join(auth, "  ")) + "\n")
	if len(p.Tags) > 0 {
		b.WriteString(label("tags") + theme.Tag.Render(truncTo("#"+strings.Join(p.Tags, " #"), cw-6)) + "\n")
	}
	if p.ProxyJump != "" {
		b.WriteString(label("jump") + theme.Value.Render(truncTo(p.ProxyJump, cw-6)) + "\n")
	}

	st, have := m.statuses[p.ID]
	state := theme.Dim.Render(theme.IconIdle + " unknown")
	switch {
	case have && st.Reachable:
		up := lipgloss.NewStyle().Foreground(theme.LatencyColor(st.LatencyMs))
		state = up.Render(fmt.Sprintf("%s up · %.0fms", theme.IconUp, st.LatencyMs))
	case have:
		down := theme.IconDown + " down"
		if !st.LastSeen.IsZero() {
			down += " · ↓ " + relDur(time.Since(st.LastSeen))
		}
		state = lipgloss.NewStyle().Foreground(theme.Red).Render(down)
	}
	b.WriteString(label("state") + state + "\n")

	seen := theme.Hint.Render("never")
	if have && !st.LastSeen.IsZero() {
		seen = theme.Value.Render(st.LastSeen.Format("Jan 2 15:04"))
	}
	b.WriteString(label("seen") + seen + "\n")

	// Latency spread over the probe history, ignoring failed (-1) samples.
	var lo, hi, sum float64
	n := 0
	if have {
		for _, v := range st.History {
			if v < 0 {
				continue
			}
			if n == 0 || v < lo {
				lo = v
			}
			if v > hi {
				hi = v
			}
			sum += v
			n++
		}
	}
	ping := theme.Hint.Render("–")
	if n > 0 {
		ping = theme.Value.Render(fmt.Sprintf("%.0f / %.0f / %.0f ms", lo, sum/float64(n), hi))
	}
	b.WriteString(label("ping") + ping + "\n")

	if p.HostKeyFP != "" {
		b.WriteString(label("key"))
		for i, ln := range wrapTo(p.HostKeyFP, cw-6) {
			if i > 0 {
				b.WriteString(strings.Repeat(" ", 6))
			}
			b.WriteString(theme.Dim.Render(ln) + "\n")
		}
	}
	return pane.Render(strings.TrimRight(b.String(), "\n"))
}

// truncTo shortens s to at most w runes with an ellipsis.
func truncTo(s string, w int) string {
	if w < 2 {
		w = 2
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	return string(r[:w-1]) + "…"
}

// wrapTo hard-wraps s into chunks of at most w runes.
func wrapTo(s string, w int) []string {
	if w < 4 {
		w = 4
	}
	r := []rune(s)
	var out []string
	for len(r) > w {
		out = append(out, string(r[:w]))
		r = r[w:]
	}
	return append(out, string(r))
}

// relDur formats a duration since last contact, compact: 42s, 7m, 3h, 2d.
func relDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// colHeader labels the columns; alignment mirrors renderRow exactly.
func (m *Model) colHeader(l listLayout) string {
	h := theme.Hint
	cells := []string{
		" ",
		h.Width(6).Align(lipgloss.Right).Render("ping"),
	}
	if l.showSpark {
		cells = append(cells, h.Width(l.sparkW).Render("trend"))
	}
	cells = append(cells,
		h.Width(l.nameW).Render("name"),
		h.Width(l.endW).Render("host"),
		h.Render("auth"),
	)
	return strings.Repeat(" ", max(l.pad-1, 0)) + "  " + strings.Join(cells, l.gap)
}

func (m *Model) renderRow(p profile.Profile, selected bool, l listLayout) string {
	st, have := m.statuses[p.ID]

	dotColor, dot, latency := theme.Muted, theme.IconIdle, "     ·"
	if have {
		if st.Reachable {
			dotColor = theme.LatencyColor(st.LatencyMs)
			dot = theme.IconUp
			latency = fmt.Sprintf("%4.0fms", st.LatencyMs)
		} else {
			dotColor, dot, latency = theme.Red, theme.IconDown, "  down"
			if !st.LastSeen.IsZero() {
				latency = "↓ " + relDur(time.Since(st.LastSeen))
			}
		}
	}
	cells := []string{
		lipgloss.NewStyle().Foreground(dotColor).Render(dot),
		lipgloss.NewStyle().Foreground(dotColor).Width(6).Align(lipgloss.Right).Render(latency),
	}
	if l.showSpark {
		cells = append(cells, lipgloss.NewStyle().Width(l.sparkW).Render(sparkline(st.History, l.sparkW)))
	}

	name := p.Name
	if len(name) > l.nameW {
		name = name[:l.nameW-1] + "…"
	}
	cells = append(cells, theme.Value.Width(l.nameW).Render(name))

	target := fmt.Sprintf("%s@%s", p.User, p.Host)
	if p.Port != 22 {
		target += fmt.Sprintf(":%d", p.Port)
	}
	if len(target) > l.endW {
		target = target[:l.endW-1] + "…"
	}
	cells = append(cells, theme.Dim.Width(l.endW).Render(target))

	var auth []string
	if p.HasAuth(profile.AuthKey) {
		auth = append(auth, theme.IconKey)
	}
	if p.HasAuth(profile.AuthPassword) {
		auth = append(auth, theme.IconPwd)
	}
	cells = append(cells, theme.Chip.Width(5).Render(strings.Join(auth, " ")))

	trailing := ""
	if l.showTags && len(p.Tags) > 0 {
		trailing = theme.Tag.Render("#" + strings.Join(p.Tags, " #"))
	}
	if m.testing[p.ID] {
		trailing = m.spin.View() + theme.Accent.Render(" testing")
	}
	if m.connecting == p.ID {
		trailing = m.spin.View() + theme.Accent.Render(" connecting")
	}
	if trailing != "" {
		cells = append(cells, trailing)
	}

	line := strings.Join(cells, l.gap)
	lead := strings.Repeat(" ", max(l.pad-1, 0))
	rowW := max(l.listW-l.pad, 20)
	// Clip to the row budget: lipgloss.Width wraps overflow onto a second
	// line, which tears the selection highlight on narrow terminals.
	line = ansi.Truncate(line, rowW-1, "…")
	if selected {
		body := lipgloss.NewStyle().Background(theme.SelBg).Foreground(theme.White).
			Width(rowW).Render(" " + line)
		return lead + theme.SelTick.Render(theme.IconPointer) + body
	}
	return lead + "  " + line
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
	return lipgloss.Place(w, max(h, 1), lipgloss.Center, lipgloss.Center, s)
}

func (m *Model) viewHelp() string {
	pw := clamp(m.width-8, 44, 68)
	dw := pw - 6
	rows := [][2]string{
		{"enter", "connect to the selected host"},
		{"a", "add a profile (step-by-step wizard)"},
		{"e", "edit the selected profile"},
		{"d", "delete the selected profile and its vault secrets"},
		{"t", "test the connection (dial, handshake, auth, exec)"},
		{"s", "sync now (guarded, encrypted git push)"},
		{"g", "settings — GitHub token, repo, autosync, keychain"},
		{"i", "import hosts from ~/.ssh/config"},
		{"o", "cycle sort: stored order / latency / tag groups"},
		{"/", "filter profiles"},
		{"j k ↑ ↓", "move"},
		{"q", "quit"},
	}
	var b strings.Builder
	b.WriteString(theme.Title.Render("Keys") + "\n\n")
	for _, r := range rows {
		b.WriteString("  " + theme.Accent.Width(9).Render(r[0]) + theme.Value.Render(r[1]) + "\n")
	}
	b.WriteString("\n" + theme.Divider(dw) + "\n")
	dot := func(c lipgloss.Color) string { return lipgloss.NewStyle().Foreground(c).Render(theme.IconUp) }
	b.WriteString(theme.Dim.Render("reach  ") +
		dot(theme.Green) + theme.Dim.Render(" <50ms  ") +
		dot(theme.BrYellow) + theme.Dim.Render(" <200ms  ") +
		dot(theme.Red) + theme.Dim.Render(" slower  ") +
		lipgloss.NewStyle().Foreground(theme.Red).Render(theme.IconDown) + theme.Dim.Render(" down") + "\n")
	b.WriteString(theme.Dim.Render("auth   ") +
		theme.Chip.Render(theme.IconKey) + theme.Dim.Render(" key    ") +
		theme.Chip.Render(theme.IconPwd) + theme.Dim.Render(" password") + "\n")
	b.WriteString(theme.Hint.Render("any key to close"))
	return theme.Panel.Width(pw).Render(b.String())
}
