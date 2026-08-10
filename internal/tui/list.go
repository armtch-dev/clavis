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

// sortMode toggles on "o": within each category group, hosts follow either
// their stored order or latency (fastest reachable first). Category grouping
// itself is always active — it is not a sort mode.
type sortMode int

const (
	sortDefault sortMode = iota
	sortLatency
)

func (s sortMode) String() string {
	if s == sortLatency {
		return "latency"
	}
	return "default order"
}

// visible returns the filtered profile list (case-insensitive substring on
// name, host, user, tags — sshs-style), in the current sort order.
func (m *Model) visible() []profile.Profile {
	base := m.store.Profiles
	if m.filter != "" {
		q := strings.ToLower(m.filter)
		var out []profile.Profile
		for _, p := range base {
			hay := strings.ToLower(p.Name + " " + p.Host + " " + p.User + " " + p.Category + " " + strings.Join(p.Tags, " "))
			if strings.Contains(hay, q) {
				out = append(out, p)
			}
		}
		base = out
	}
	return m.sortProfiles(base)
}

// sortProfiles reorders a copy of in: always grouped by category first
// (case-insensitive alphabetical, uncategorized sinks to the bottom), then
// within each group by stored order (sortDefault) or by latency rank
// (sortLatency: reachable fastest first, then unknown, then down). The
// stored order is left untouched.
func (m *Model) sortProfiles(in []profile.Profile) []profile.Profile {
	if len(in) < 2 {
		return in
	}
	out := append([]profile.Profile(nil), in...)
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
		ci, cj := out[i].Category != "", out[j].Category != ""
		if ci != cj {
			return ci // categorized before uncategorized
		}
		if gi, gj := strings.ToLower(out[i].Category), strings.ToLower(out[j].Category); gi != gj {
			return gi < gj
		}
		if m.sortMode == sortLatency {
			ri, li := rank(out[i])
			rj, lj := rank(out[j])
			if ri != rj {
				return ri < rj
			}
			return li < lj
		}
		return false // stable sort keeps the stored order within the group
	})
	return out
}

// groupCategory names the category group a profile belongs to.
func groupCategory(p profile.Profile) string {
	if p.Category == "" {
		return "uncategorized"
	}
	return p.Category
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
			m.filter = trimLastRune(m.filter)
		case tea.KeyRunes:
			m.filter += string(key.Runes)
		}
		m.clampCursor()
		return m, nil
	}

	// Inline category prompt ("c"): retag the selected host without walking
	// the whole edit wizard.
	if m.catTarget != "" {
		switch key.Type {
		case tea.KeyEsc:
			m.catTarget, m.catInput = "", ""
		case tea.KeyEnter:
			if p := m.store.ByID(m.catTarget); p != nil {
				p.Category = strings.TrimPrefix(strings.TrimSpace(m.catInput), "#")
				name := p.Name
				m.catTarget, m.catInput = "", ""
				if p.Category == "" {
					m.setStatus(statusOK, name+" is now uncategorized")
				} else {
					m.setStatus(statusOK, name+" → "+p.Category)
				}
				return m, m.saveAll("set category on " + name)
			}
			m.catTarget, m.catInput = "", ""
		case tea.KeyBackspace:
			m.catInput = trimLastRune(m.catInput)
		case tea.KeyRunes:
			m.catInput += string(key.Runes)
		}
		return m, nil
	}

	vis := m.visible()
	switch key.String() {
	case "q":
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
	case "pgup", "ctrl+u":
		m.cursor = max(m.cursor-10, 0)
	case "pgdown", "ctrl+d":
		if len(vis) > 0 {
			m.cursor = min(m.cursor+10, len(vis)-1)
		}
	case "home":
		m.cursor = 0
	case "end", "G":
		m.cursor = max(len(vis)-1, 0)
	case "g":
		m.settings = newSettings(m)
		m.screen = scrSettings
	case "/":
		m.filtering = true
		m.filter = ""
	case "c":
		if p := m.selected(vis); p != nil {
			m.catTarget, m.catInput = p.ID, p.Category
		}
	case "o":
		if m.sortMode == sortDefault {
			m.sortMode = sortLatency
		} else {
			m.sortMode = sortDefault
		}
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
	case "r":
		if p := m.selected(vis); p != nil && m.connecting == "" {
			m.scriptsUI = newScripts(m, p)
			m.screen = scrScripts
		}
	case "m":
		m.scriptsUI = newScriptsManager(m)
		m.screen = scrScripts
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
		// Grows to 56 on ultrawides so the host-key fingerprint and ping
		// spread fit on one line instead of leaving a dead zone.
		l.detailW = clamp(w/4, 36, 56)
		l.listW = w - l.detailW - 1 // -1 for the pane's left hairline
	}
	l.nameW = clamp(l.listW/5, 14, 28)
	l.endW = clamp(l.listW/4+4, 20, 38)
	l.sparkW = 16
	if l.listW >= 110 {
		l.sparkW = 20
	}
	// The fixed columns must fit the row budget (rowW-1, the clip applied in
	// renderRow) or every row gets chopped mid-auth-cell with a stray "…".
	// Give the overflow back from the host column — the widest, and the one
	// that truncates most gracefully.
	gaps := 4
	fixed := 1 + 6 + l.nameW + l.endW + 5 // dot, ping, name, host, auth
	if l.showSpark {
		gaps++
		fixed += l.sparkW
	}
	fixed += gaps * len(l.gap)
	if over := fixed - (max(l.listW-l.pad, 20) - 1); over > 0 {
		d := min(over, l.endW-14)
		l.endW -= d
		l.nameW = max(l.nameW-(over-d), 10)
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
	vis := m.visible()
	var b strings.Builder

	// Header: title on the left, quiet meta on the right.
	left := pad + theme.Title.Render("clavis")
	if m.catTarget != "" {
		name := ""
		if p := m.store.ByID(m.catTarget); p != nil {
			name = p.Name
		}
		left += theme.Dim.Render("  category for ") + theme.Value.Render(name) +
			theme.Dim.Render("  ") + theme.Value.Render(m.catInput) + theme.Accent.Render("▌") +
			theme.Hint.Render("  enter set · esc cancel")
	}
	if m.filtering || m.filter != "" {
		cursor := ""
		if m.filtering {
			cursor = theme.Accent.Render("▌")
		}
		left += theme.Dim.Render("  filter ") + theme.Value.Render(m.filter) + cursor +
			theme.Dim.Render(fmt.Sprintf("  %d/%d", len(vis), len(m.store.Profiles)))
	}
	var meta []string
	if m.sortMode != sortDefault {
		meta = append(meta, theme.Dim.Render("sort ")+theme.Sub.Render(m.sortMode.String()))
	}
	if n := len(m.store.Profiles); n > 0 {
		up, down := 0, 0
		for _, p := range m.store.Profiles {
			if st, ok := m.statuses[p.ID]; ok {
				if st.Reachable {
					up++
				} else {
					down++
				}
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
		// A down host can scroll out of view on a long list — keep the fact
		// that something is down glanceable at the top level.
		if down > 0 {
			meta = append(meta, theme.StatusErr.Render(fmt.Sprintf("%d down", down)))
		}
	}
	if !m.vault.Unlocked() {
		meta = append(meta, theme.StatusWarn.Render(theme.IconLock+" locked"))
	}
	if m.cfg.Sync.Remote != "" {
		meta = append(meta, theme.Dim.Render(theme.IconSync+" ")+theme.Value.Render(shortRemote(m.cfg.Sync.Remote)))
	}
	// The meta side must never push the header past the terminal width: an
	// overflowing line wraps, shifting the whole frame down a row. Drop
	// entries front-first (sort indicator, then counts — the warnings at the
	// tail matter most), then clip as a last resort.
	sep := theme.Dim.Render("  ·  ")
	for len(meta) > 0 &&
		lipgloss.Width(left)+lipgloss.Width(strings.Join(meta, sep)+pad)+1 > l.width {
		meta = meta[1:]
	}
	// The tinted bar is the header's frame — no divider underneath, the line
	// is reclaimed for the row region.
	header := spread(left, strings.Join(meta, sep)+pad, l.width)
	b.WriteString(chromeFill(header, l.width) + "\n")
	headerH := 1
	if l.roomy {
		b.WriteString("\n")
		headerH++
	}

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

	region := strings.TrimRight(m.renderRowRegion(vis, l, avail), "\n")
	// Fleet summary strip: ambient totals anchored to the bottom of the
	// content area, rendered only when at least 3 spare lines remain (a
	// breathing line + hairline + summary) so tight frames never pay for it.
	strip := m.fleetSummary(l)
	showStrip := strip != "" && avail-lipgloss.Height(region) >= 3
	contentH := avail
	if showStrip {
		contentH = avail - 2 // hairline + summary live in the reclaimed rows
	}
	var content string
	if l.showDetail {
		left := lipgloss.NewStyle().Width(l.listW).MaxHeight(max(contentH, 1)).Render(region)
		content = lipgloss.JoinHorizontal(lipgloss.Top, left, m.renderDetail(m.selected(vis), l, contentH))
	} else {
		content = region
	}
	b.WriteString(content)
	if showStrip {
		gap := contentH - lipgloss.Height(content) // pad so the strip hugs the footer
		b.WriteString(strings.Repeat("\n", max(gap, 0)+1))
		b.WriteString(theme.Divider(l.width) + "\n")
		b.WriteString(strip)
	}
	return b.String()
}

// fleetSummary builds the one-line ambient fleet strip: up/down totals, the
// average latency over reachable hosts, and the sync remote. Segments that
// don't apply are omitted; an empty result suppresses the strip entirely.
// Deliberately quiet — dimmed status dots, muted text.
func (m *Model) fleetSummary(l listLayout) string {
	up, down := 0, 0
	var sum float64
	for _, p := range m.store.Profiles {
		st, ok := m.statuses[p.ID]
		if !ok {
			continue
		}
		if st.Reachable {
			up++
			sum += st.LatencyMs
		} else {
			down++
		}
	}
	var counts []string
	if up > 0 {
		counts = append(counts, fleetUpDot.Render(theme.IconUp)+theme.Dim.Render(fmt.Sprintf(" %d up", up)))
	}
	if down > 0 {
		counts = append(counts, fleetDownDot.Render(theme.IconDown)+theme.Dim.Render(fmt.Sprintf(" %d down", down)))
	}
	var segs []string
	if len(counts) > 0 {
		segs = append(segs, strings.Join(counts, theme.Dim.Render(" · ")))
	}
	if up > 0 {
		segs = append(segs, theme.Dim.Render("avg ")+theme.Sub.Render(fmt.Sprintf("%.0fms", sum/float64(up))))
	}
	if m.cfg.Sync.Remote != "" {
		segs = append(segs, theme.Dim.Render(theme.IconSync+" "+shortRemote(m.cfg.Sync.Remote)))
	}
	if len(segs) == 0 {
		return ""
	}
	line := strings.Repeat(" ", l.pad) + strings.Join(segs, "    ")
	return ansi.Truncate(line, l.width, "")
}

// Status dots for the fleet strip, pulled toward the background so the strip
// stays ambient rather than echoing the full-brightness row indicators.
var (
	fleetUpDot = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.BlendHex(theme.HexGreen, theme.HexBg, 0.35)))
	fleetDownDot = lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.BlendHex(theme.HexRed, theme.HexBg, 0.35)))
)

// listEntry is one display line of the row region: either a profile row
// (idx into vis) or a category group heading.
type listEntry struct {
	heading string // non-empty for a group heading line
	idx     int
}

// listEntries expands vis into display lines, inserting a heading before
// each category group (grouping is always active).
func (m *Model) listEntries(vis []profile.Profile) []listEntry {
	out := make([]listEntry, 0, len(vis)+4)
	prev := ""
	for i, p := range vis {
		if g := groupCategory(p); i == 0 || g != prev {
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
	first, last := -1, -1
	for i := start; i < end; i++ {
		e := entries[i]
		if e.heading != "" {
			b.WriteString(m.groupHeading(e.heading, vis, l) + "\n")
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

// groupHeading renders a category section header as a full-width rule that
// carries data: `─ cloud · 2 hosts · 2 up ───────`, the dashes filling the
// remaining row width exactly. Counts come from the group's visible rows.
func (m *Model) groupHeading(name string, vis []profile.Profile, l listLayout) string {
	total, up, down := 0, 0, 0
	for _, p := range vis {
		if groupCategory(p) != name {
			continue
		}
		total++
		if st, ok := m.statuses[p.ID]; ok {
			if st.Reachable {
				up++
			} else {
				down++
			}
		}
	}
	hosts := fmt.Sprintf("%d host", total)
	if total != 1 {
		hosts += "s"
	}
	upSeg, downSeg := "", ""
	if up > 0 {
		upSeg = fmt.Sprintf("%d up", up)
	}
	if down > 0 {
		downSeg = fmt.Sprintf("%d down", down)
	}

	lead := strings.Repeat(" ", max(l.pad-1, 0))
	budget := max(l.listW-len(lead)-1, 10)

	// Plain widths first so the dash fill lands exactly on the budget.
	sep := " · "
	plainW := lipgloss.Width(sep + hosts)
	if upSeg != "" {
		plainW += lipgloss.Width(sep + upSeg)
	}
	if downSeg != "" {
		plainW += lipgloss.Width(sep + downSeg)
	}
	name = truncTo(name, max(budget-plainW-6, 4)) // 6: rule prefix + min tail
	fill := budget - 2 - lipgloss.Width(name) - plainW - 1

	var b strings.Builder
	b.WriteString(lead + theme.Hint.Render("─ "))
	b.WriteString(theme.Sub.Render(name))
	b.WriteString(theme.Dim.Render(sep + hosts))
	if upSeg != "" {
		b.WriteString(theme.Dim.Render(sep) + theme.StatusOK.Render(upSeg))
	}
	if downSeg != "" {
		b.WriteString(theme.Dim.Render(sep) + theme.StatusErr.Render(downSeg))
	}
	if fill > 0 {
		b.WriteString(theme.Hint.Render(" " + strings.Repeat("─", fill)))
	}
	// Safety net: the width invariant is load-bearing (overflow wraps the frame).
	return ansi.Truncate(b.String(), l.listW-1, "")
}

// trimLastRune removes the final rune (not byte — multibyte input must not
// be corrupted by backspace).
func trimLastRune(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return string(r[:len(r)-1])
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

// midTrunc shortens s to at most w runes by eliding the middle, keeping a
// longer head than tail (fingerprint prefixes carry the algorithm name).
func midTrunc(s string, w int) string {
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w < 8 {
		return truncTo(s, w)
	}
	head := (w - 1) * 3 / 5
	tail := w - 1 - head
	return string(r[:head]) + "…" + string(r[len(r)-tail:])
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
// Muted, not Hint: headers are navigation, not decoration — Faint is kept
// for hairlines only.
func (m *Model) colHeader(l listLayout) string {
	h := theme.Dim
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
	latCell := ""
	if have {
		if st.Reachable {
			dotColor = theme.LatencyColor(st.LatencyMs)
			dot = theme.IconUp
			// Digits carry the data, the repeated unit is noise: dim the "ms".
			latCell = lipgloss.NewStyle().Foreground(dotColor).Render(fmt.Sprintf("%4.0f", st.LatencyMs)) +
				theme.Dim.Render("ms")
		} else {
			dotColor, dot, latency = theme.Red, theme.IconDown, "  down"
			if !st.LastSeen.IsZero() {
				latency = "↓ " + relDur(time.Since(st.LastSeen))
			}
		}
	}
	if latCell == "" {
		latCell = lipgloss.NewStyle().Foreground(dotColor).Width(6).Align(lipgloss.Right).Render(latency)
	}
	cells := []string{
		lipgloss.NewStyle().Foreground(dotColor).Render(dot),
		latCell,
	}
	if l.showSpark {
		cells = append(cells, lipgloss.NewStyle().Width(l.sparkW).Render(sparkline(st.History, l.sparkW)))
	}

	cells = append(cells, theme.Value.Width(l.nameW).Render(truncTo(p.Name, l.nameW)))

	target := fmt.Sprintf("%s@%s", p.User, p.Host)
	if p.Port != 22 {
		target += fmt.Sprintf(":%d", p.Port)
	}
	target = truncTo(target, l.endW)
	// Subtle, not Muted: the target is real data, a step above chrome.
	cells = append(cells, theme.Sub.Width(l.endW).Render(target))

	var auth []string
	if p.HasAuth(profile.AuthKey) {
		auth = append(auth, theme.IconKey)
	}
	if p.HasAuth(profile.AuthPassword) {
		auth = append(auth, theme.IconPwd)
	}
	cells = append(cells, theme.Chip.Width(5).Render(strings.Join(auth, " ")))

	lead := strings.Repeat(" ", max(l.pad-1, 0))
	rowW := max(l.listW-l.pad, 20)

	trailing := ""
	switch {
	case m.testing[p.ID]:
		trailing = m.spin.View() + theme.Accent.Render(" testing")
	case m.connecting == p.ID:
		trailing = m.spin.View() + theme.Accent.Render(" connecting")
	case l.showTags && len(p.Tags) > 0:
		// Tags are garnish: only append them when enough of the row budget
		// remains for them to be legible — a clipped "#clou…" stub is noise.
		remain := rowW - 1 - lipgloss.Width(strings.Join(cells, l.gap)) - len(l.gap)
		if remain >= 10 {
			trailing = theme.Tag.Render(truncTo("#"+strings.Join(p.Tags, " #"), remain))
		}
	}
	if trailing != "" {
		cells = append(cells, trailing)
	}

	line := strings.Join(cells, l.gap)
	// Clip to the row budget: lipgloss.Width wraps overflow onto a second
	// line, which tears the selection highlight on narrow terminals. The "…"
	// marker only appears when real content is clipped — losing nothing but a
	// cell's trailing pad spaces shouldn't stamp an ellipsis on every row.
	if lipgloss.Width(line) > rowW-1 {
		tail := ""
		if plain := []rune(ansi.Strip(line)); rowW-1 < len(plain) &&
			strings.TrimSpace(string(plain[rowW-1:])) != "" {
			tail = "…"
		}
		line = ansi.Truncate(line, rowW-1, tail)
	}
	if selected {
		return lead + theme.Accent.Render("▎") + selFill(" "+line, rowW)
	}
	return lead + "  " + line
}

// selFill paints the selection background under a line whose cells are
// already foreground-styled. Wrapping the joined line in a Background style
// doesn't work: every cell's SGR reset kills the background mid-row, so only
// the unstyled tail gets filled (the highlight visibly "tears"). Instead the
// background sequence is re-opened after each reset, keeping the per-cell
// colours (green dot, blue tags) on top of the fill.
func selFill(line string, width int) string {
	return bgFill(line, width, theme.SelBg)
}

// chromeFill tints the fixed chrome bars (header, footer legend) with the
// theme surface colour, exactly `width` cells wide — same reset-survival
// mechanics as selFill.
func chromeFill(line string, width int) string {
	return bgFill(line, width, theme.Surface)
}

// bgFill clips/pads line to exactly width cells and paints bg underneath,
// re-opening the background SGR after every per-cell reset (see selFill).
func bgFill(line string, width int, bg lipgloss.Color) string {
	line = ansi.Truncate(line, width, "")
	if pad := width - lipgloss.Width(line); pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	// Derive the bg sequence for the active colour profile from a probe
	// render, rather than hardcoding a truecolour escape.
	marker := lipgloss.NewStyle().Background(bg).Render("|")
	i := strings.Index(marker, "|")
	if i <= 0 {
		return line // colourless profile: nothing to paint
	}
	seq := marker[:i]
	const reset = "\x1b[0m"
	return seq + strings.ReplaceAll(line, reset, reset+seq) + reset
}

// spread lays out left and right on one line padded to width.
func spread(left, right string, width int) string {
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

// Capped at ▆ so adjacent rows can never fuse into a solid slab.
var sparkBlocks = []rune("▁▂▃▄▅▆")

// sparkFail marks a failed probe sample: red pulled toward the background so
// a bad patch reads as a scar in the trend, not a full-brightness siren.
var sparkFail = lipgloss.NewStyle().
	Foreground(lipgloss.Color(theme.BlendHex(theme.HexRed, theme.HexBg, 0.35)))

// sparkline renders the last n latency samples as a gradient trend: every
// sample takes its own latency-band colour (green → yellow → red), failures
// show as a dim red ╳. With fewer than 3 valid samples a lone block would
// read as data where there is none — render a dim ⋯ placeholder instead.
func sparkline(hist []float64, n int) string {
	if len(hist) > n {
		hist = hist[len(hist)-n:]
	}
	valid, maxV := 0, 0.0
	for _, v := range hist {
		if v >= 0 {
			valid++
			if v > maxV {
				maxV = v
			}
		}
	}
	if valid < 3 {
		return theme.Dim.Render("⋯") + strings.Repeat(" ", max(n-1, 0))
	}
	var b strings.Builder
	for _, v := range hist {
		if v < 0 {
			b.WriteString(sparkFail.Render("╳"))
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
	return lipgloss.Place(w, max(h, 1), lipgloss.Center, lipgloss.Center, s)
}

func (m *Model) viewHelp() string {
	pw := clamp(m.width-8, 44, 68)
	dw := pw - 6
	rows := [][2]string{
		{"enter", "connect to the selected host"},
		{"r", "run a script on the selected host (only ones that apply)"},
		{"m", "manage the script library (create, edit, delete)"},
		{"a", "add a profile (step-by-step wizard)"},
		{"e", "edit the selected profile"},
		{"d", "delete the selected profile and its vault secrets"},
		{"t", "test the connection (dial, handshake, auth, exec)"},
		{"s", "sync now (guarded, encrypted git push)"},
		{"g", "settings — GitHub token, repo, autosync, keychain"},
		{"i", "import hosts from ~/.ssh/config"},
		{"c", "set the selected host's category (list grouping)"},
		{"o", "toggle latency ordering within groups"},
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
