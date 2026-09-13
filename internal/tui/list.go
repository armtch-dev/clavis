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

	"github.com/armtch-dev/clavis/internal/fstxn"
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
	c := &m.listCache
	if c.valid && c.store == m.store && c.length == len(m.store.Profiles) && c.filter == m.filter && c.mode == m.sortMode {
		return c.profiles
	}
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
	c.profiles = m.sortProfiles(base)
	c.valid, c.store, c.length, c.filter, c.mode = true, m.store, len(m.store.Profiles), m.filter, m.sortMode
	c.groups, c.entries = nil, nil
	return c.profiles
}

type groupCount struct{ total, up, down int }
type visibleCache struct {
	valid    bool
	store    *profile.Store
	length   int
	filter   string
	mode     sortMode
	profiles []profile.Profile
	entries  []listEntry
	groups   map[string]groupCount
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
			target, category := m.catTarget, strings.TrimPrefix(strings.TrimSpace(m.catInput), "#")
			err := m.mutate(func(s *diskState, l *fstxn.Lock) ([]fstxn.Change, error) {
				p := s.store.ByID(target)
				if p == nil {
					return nil, fmt.Errorf("profile no longer exists")
				}
				p.Category = category
				if err := s.store.Update(*p); err != nil {
					return nil, err
				}
				c, err := s.store.Change()
				return []fstxn.Change{c}, err
			})
			if err != nil {
				m.setStatus(statusErr, "category save failed: "+err.Error())
				return m, nil
			}
			m.catTarget, m.catInput = "", ""
			m.setStatus(statusOK, "category saved")
			return m, m.afterMutation("set category")
		case tea.KeyBackspace:
			m.catInput = trimLastRune(m.catInput)
		case tea.KeyRunes:
			m.catInput += string(key.Runes)
		}
		return m, nil
	}

	vis := m.visible()
	m.reconcileSelection(vis)
	switch key.String() {
	case "q":
		m.quiting = true
		m.cancelWork()
		m.monitor.Stop()
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
		m.rememberSelection(vis)
	case "down", "j":
		if m.cursor < len(vis)-1 {
			m.cursor++
		}
		m.rememberSelection(vis)
	case "pgup", "ctrl+u":
		m.cursor = max(m.cursor-10, 0)
		m.rememberSelection(vis)
	case "pgdown", "ctrl+d":
		if len(vis) > 0 {
			m.cursor = min(m.cursor+10, len(vis)-1)
		}
		m.rememberSelection(vis)
	case "home":
		m.cursor = 0
		m.rememberSelection(vis)
	case "end", "G":
		m.cursor = max(len(vis)-1, 0)
		m.rememberSelection(vis)
	case "g":
		m.settings = newSettings(m)
		m.screen = scrSettings
		return m, m.localSnapshotCmd(m.settings)
	case "v":
		if p := m.selected(vis); p != nil {
			m.detailID, m.panelScroll = p.ID, 0
		}
	case "u":
		if !m.vault.Unlocked() {
			m.unlock = newUnlock(m.vault, m.cfgDir)
			m.screen = scrUnlock
		}
	case "/":
		m.filtering = true
		m.filter = ""
		m.clampCursor()
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
	case "h":
		if p := m.selected(vis); p != nil {
			if result, ok := m.mismatches[p.ID]; ok && sameTestTarget(m.effective(*p), result.endpoint) {
				m.openTrust(result.endpoint, result.result, nil)
			} else {
				m.setStatus(statusWarn, "test this profile first; h reviews a changed host key")
			}
		}
	case "s":
		return m, m.syncCmd("manual sync")
	case "i":
		m.importSSHConfig()
		if m.statusType == statusOK && m.cfg.Sync.AutoSync && m.cfg.Sync.Remote != "" {
			return m, m.syncCmd("import from ssh_config")
		}
		return m, nil
	case "r":
		if p := m.selected(vis); p != nil && m.connecting == "" {
			m.scriptsUI = newScripts(m, p)
			m.screen = scrScripts
		}
	case "m":
		m.scriptsUI = newScriptsManager(m)
		m.screen = scrScripts
	case "D":
		if m.scriptDraft != nil {
			m.scriptsUI = m.scriptDraft
			m.scriptsUI.editing = true
			m.screen = scrScripts
		}
	case "X":
		if m.scriptDraft != nil {
			m.scriptDraft = nil
			m.setStatus(statusInfo, "retained script draft discarded")
		}
	case "y":
		m.identsUI = &identsModel{}
		m.screen = scrIdentities
	case "enter":
		if p := m.selected(vis); p != nil && m.connecting == "" {
			return m, m.startConnect(*p)
		}
	}
	return m, nil
}

func (m *Model) selected(vis []profile.Profile) *profile.Profile {
	if m.selectedID != "" {
		for _, p := range vis {
			if p.ID == m.selectedID {
				return m.store.ByID(p.ID)
			}
		}
	}
	if len(vis) == 0 || m.cursor < 0 || m.cursor >= len(vis) {
		return nil
	}
	return m.store.ByID(vis[m.cursor].ID)
}

func (m *Model) clampCursor() {
	m.reconcileSelection(m.visible())
}

func (m *Model) rememberSelection(vis []profile.Profile) {
	m.selectedID = ""
	if m.cursor >= 0 && m.cursor < len(vis) {
		m.selectedID = vis[m.cursor].ID
	}
}

func (m *Model) reconcileSelection(vis []profile.Profile) {
	for i, p := range vis {
		if p.ID == m.selectedID {
			m.cursor = i
			return
		}
	}
	// Removed/filtered selection falls to the same row, or the preceding last row.
	m.cursor = clamp(m.cursor, 0, max(0, len(vis)-1))
	m.rememberSelection(vis)
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
	if err := m.importSSHEntries(entries); err != nil {
		m.setStatus(statusErr, "import: "+err.Error())
	}
}

// Retain one directory owner and one Apply for imported metadata and ciphertext.
// Publish a fresh Locked load only after success, preserving optimistic revisions.
func (m *Model) importSSHEntries(entries []sshconfig.Entry) error {
	if m.selectedID == "" {
		m.rememberSelection(m.visible())
	}
	if m.syncing || m.persistenceErr != nil {
		return fmt.Errorf("import paused during sync/storage recovery")
	}
	release, err := m.mutationLock()
	if err != nil {
		return err
	}
	defer release()
	if err := m.store.CheckCurrentLocked(m.uiLock); err != nil {
		return err
	}
	if err := m.vault.CheckCurrentLocked(m.uiLock); err != nil {
		return err
	}
	store, err := profile.LoadStoreLocked(m.uiLock)
	if err != nil {
		return err
	}
	var changes []fstxn.Change
	added, skipped, keyless := 0, 0, 0
	for _, e := range entries {
		if store.ByName(e.Alias) != nil {
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
		np, err := store.Add(p)
		if err != nil {
			skipped++
			continue
		}
		if raw, rerr := os.ReadFile(e.IdentityFile); e.IdentityFile != "" && rerr == nil {
			change, err := m.vault.SecretChangeLocked(m.uiLock, np.KeySecret(), raw, false)
			if err != nil {
				return err
			}
			changes = append(changes, change)
		} else {
			keyless++ // no IdentityFile, or unreadable — profile works once a key is added via edit
		}
		added++
	}
	if added > 0 {
		metadata, err := store.Change()
		if err != nil {
			return err
		}
		if err := m.uiLock.Apply(append(changes, metadata)); err != nil {
			return m.noteWrite(err)
		}
		store, err = profile.LoadStoreLocked(m.uiLock)
		if err != nil {
			return m.noteWrite(err)
		}
		m.store = store
		m.syncState.Dirty = true
		m.syncTargets()
		m.clampCursor()
	}
	msg := fmt.Sprintf("imported %d host(s), skipped %d (duplicate/invalid)", added, skipped)
	if keyless > 0 {
		msg += fmt.Sprintf(", %d without keys (add via e)", keyless)
	}
	m.setStatus(statusOK, msg)
	return nil
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
		release, err := m.mutationLock()
		if err != nil {
			m.setStatus(statusErr, err.Error())
			return m, nil
		}
		defer release()
		if m.syncing || m.persistenceErr != nil {
			m.setStatus(statusWarn, "deletion paused — retry after sync/storage recovery")
			return m, nil
		}
		if err := m.store.CheckCurrentLocked(m.uiLock); err != nil {
			m.setStatus(statusErr, err.Error())
			return m, nil
		}
		if err := m.vault.CheckCurrentLocked(m.uiLock); err != nil {
			m.setStatus(statusErr, err.Error())
			return m, nil
		}
		if m.confirm.profileID == "" || m.store.ByID(m.confirm.profileID) == nil {
			m.setStatus(statusWarn, "profile target changed — select it again")
			return m, nil
		}
		target, name := m.confirm.profileID, m.confirm.name
		err = m.mutate(func(s *diskState, l *fstxn.Lock) ([]fstxn.Change, error) {
			secrets, err := s.store.Remove(target)
			if err != nil {
				return nil, err
			}
			changes, err := secretDeletes(secrets)
			if err != nil {
				return nil, err
			}
			c, err := s.store.Change()
			return append(changes, c), err
		})
		if err != nil {
			m.setStatus(statusErr, "delete failed: "+err.Error())
			return m, nil
		}
		m.setStatus(statusOK, "deleted "+name)
		m.screen = scrList
		m.clampCursor()
		return m, m.afterMutation("delete " + name)
	default:
		m.screen = scrList
	}
	return m, nil
}

func (c confirmModel) view(w, h int, scroll ...int) string {
	pw := min(46, w-2)
	body := (theme.StatusErr.Render("Delete "+c.name) + "\n\n" +
		theme.Value.Render("Its password and key will be removed from the vault.") + "\n\n" +
		theme.Divider(pw-6) + "\n" +
		hintKeys([][2]string{{"y", "delete"}, {"esc", "cancel"}}))
	return panelView(body, w, h, pw, scrollOffset(scroll))
}

// --- list rendering ---

// listLayout captures everything about the list that adapts to the terminal
// size: horizontal padding, column widths, which columns fit at all, and
// whether there is vertical room for breathing space and column headers.
type listLayout struct {
	width, pad  int    // total width, left/right padding
	listW       int    // width of the row region (== width unless showDetail)
	nameW, endW int    // name and user@host column widths
	detailW     int    // detail pane width (content, excl. its left border)
	gap         string // inter-column gap, wider on large terminals
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
	l.showColHead = m.height >= 16 && w >= 70
	if w >= 130 {
		l.showDetail = true
		// Grows to 56 on ultrawides so the host-key fingerprint and ping
		// spread fit on one line instead of leaving a dead zone.
		l.detailW = clamp(w/4, 36, 56)
		l.listW = w - l.detailW - 1 // -1 for the pane's left hairline
	}
	l.nameW = clamp(l.listW/5, 14, 28)
	l.endW = clamp(l.listW/2, 20, 60)
	// Reserve status and latency before distributing the target/name budget.
	gaps := 3
	fixed := 12 + 9 + l.nameW + l.endW // status, latency, name, target
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

	// Header: the app chip on the left, quiet meta on the right. The chip is
	// the one background-filled mark in the chrome — identity, not a bar.
	left := pad + theme.ChipAccent.Render(theme.IconKey+" clavis")
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
	if m.catTarget != "" {
		left = pad + theme.Label.Render("category › ") + theme.Value.Render(inputTail(m.catInput, l.width-14-l.pad)) + theme.Accent.Render("▌")
	}
	if m.filtering || m.filter != "" {
		left = pad + theme.Label.Render("filter › ") + theme.Value.Render(inputTail(m.filter, l.width-12-l.pad)) + theme.Accent.Render("▌")
	}
	var meta []string
	// The sort indicator lives on the ping column (colHeader); repeat it here
	// only when the column header row is hidden, so the state stays visible.
	if m.sortMode != sortDefault && !l.showColHead {
		meta = append(meta, theme.Dim.Render("sort ")+theme.Sub.Render(m.sortMode.String()))
	}
	// Up counts, averages, and the remote live in the fleet strip — the
	// header keeps only what must stay glanceable from the top: size,
	// trouble, and vault state.
	if n := len(m.store.Profiles); n > 0 {
		down := 0
		for _, p := range m.store.Profiles {
			if st, ok := m.statuses[p.ID]; ok && !st.Reachable {
				down++
			}
		}
		count := fmt.Sprintf("%d host", n)
		if n != 1 {
			count += "s"
		}
		meta = append(meta, theme.Dim.Render(count))
		// A down host can scroll out of view on a long list — keep the fact
		// that something is down glanceable at the top level.
		if down > 0 {
			meta = append(meta, theme.StatusErr.Render(fmt.Sprintf("%d down", down)))
		}
	}
	if !m.vault.Unlocked() {
		meta = append(meta, theme.ChipWarn.Render(theme.IconLock+" locked"))
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
	b.WriteString(spread(left, strings.Join(meta, sep)+pad, l.width) + "\n")
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
		empty = ansi.Truncate(empty, max(1, l.width-2*l.pad), "…")
		if avail > 4 {
			b.WriteString(lipgloss.Place(l.width, avail, lipgloss.Center, lipgloss.Center, empty))
		} else {
			b.WriteString("\n" + pad + " " + empty + "\n")
		}
		return b.String()
	}

	region := strings.TrimRight(m.renderRowRegion(vis, l, avail), "\n")
	// Fleet summary strip: ambient totals anchored just above the footer,
	// rendered only when at least 3 spare lines remain (breathing room +
	// summary) so tight frames never pay for it. No hairline of its own —
	// the footer's divider right below already separates it, and two rules
	// a row apart read as double chrome.
	strip := m.fleetSummary(l)
	showStrip := strip != "" && avail-lipgloss.Height(region) >= 3
	contentH := avail
	if showStrip {
		contentH = avail - 1 // the summary line lives in the reclaimed row
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
		counts = append(counts, theme.StatusOK.Render(theme.IconUp)+theme.Dim.Render(fmt.Sprintf(" %d up", up)))
	}
	if down > 0 {
		counts = append(counts, theme.StatusErr.Render(theme.IconDown)+theme.Dim.Render(fmt.Sprintf(" %d down", down)))
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

// listEntry is one display line of the row region: either a profile row
// (idx into vis) or a category group heading.
type listEntry struct {
	heading string // non-empty for a group heading line
	idx     int
}

// listEntries expands vis into display lines, inserting a heading before
// each category group (grouping is always active).
func (m *Model) listEntries(vis []profile.Profile) []listEntry {
	if m.listCache.entries != nil {
		return m.listCache.entries
	}
	out := make([]listEntry, 0, len(vis)+4)
	prev := ""
	for i, p := range vis {
		if g := groupCategory(p); i == 0 || g != prev {
			if i > 0 {
				out = append(out, listEntry{idx: -1})
			}
			out = append(out, listEntry{heading: g})
			prev = g
		}
		out = append(out, listEntry{idx: i})
	}
	m.listCache.entries = out
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
		if e.idx == -1 {
			b.WriteString("\n")
			continue
		}
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

// groupHeading renders a category section header as a quiet data line:
// `cloud · 2 hosts · 2 up` — whitespace does the separating, no rule fill.
// Counts come from the group's visible rows.
func (m *Model) groupHeading(name string, vis []profile.Profile, l listLayout) string {
	if m.listCache.groups == nil {
		m.listCache.groups = map[string]groupCount{}
		for _, p := range vis {
			g := groupCategory(p)
			c := m.listCache.groups[g]
			c.total++
			if st, ok := m.statuses[p.ID]; ok {
				if st.Reachable {
					c.up++
				} else {
					c.down++
				}
			}
			m.listCache.groups[g] = c
		}
	}
	c := m.listCache.groups[name]
	total, up, down := c.total, c.up, c.down
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

	lead := strings.Repeat(" ", max(l.pad-1, 0)) + "  "
	budget := max(l.listW-lipgloss.Width(lead)-1, 10)

	sep := " · "
	plainW := lipgloss.Width(sep + hosts)
	if upSeg != "" {
		plainW += lipgloss.Width(sep + upSeg)
	}
	if downSeg != "" {
		plainW += lipgloss.Width(sep + downSeg)
	}
	name = truncTo(name, max(budget-plainW, 4))

	var b strings.Builder
	b.WriteString(lead + theme.Sub.Render(name))
	b.WriteString(theme.Dim.Render(sep + hosts))
	if upSeg != "" {
		b.WriteString(theme.Dim.Render(sep) + theme.StatusOK.Render(upSeg))
	}
	if downSeg != "" {
		b.WriteString(theme.Dim.Render(sep) + theme.StatusErr.Render(downSeg))
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

// truncTo budgets terminal cells, including wide/combining graphemes.
func truncTo(s string, w int) string {
	return ansi.Truncate(s, max(0, w), "…")
}

// midTrunc shortens s to at most w runes by eliding the middle, keeping a
// longer head than tail (fingerprint prefixes carry the algorithm name).
func midTrunc(s string, w int) string {
	n := ansi.StringWidth(s)
	if n <= w {
		return s
	}
	if w < 8 {
		return truncTo(s, w)
	}
	head := (w - 1) * 3 / 5
	tail := w - 1 - head
	return ansi.Cut(s, 0, head) + "…" + ansi.Cut(s, n-tail, n)
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
	ping := "Latency"
	if m.sortMode == sortLatency {
		ping = "Latency ▲"
	}
	cells := []string{h.Width(l.nameW).Render("Name"), h.Width(l.endW).Render("Target"),
		h.Width(12).Render("Status"), h.Width(9).Align(lipgloss.Right).Render(ping)}
	return strings.Repeat(" ", max(l.pad-1, 0)) + "  " + strings.Join(cells, l.gap)
}

func (m *Model) renderRow(p profile.Profile, selected bool, l listLayout) string {
	p = m.effective(p) // identity-backed rows show the identity's user + auth
	st, have := m.statuses[p.ID]
	if l.listW < 60 {
		state := theme.IconIdle
		if have {
			if st.Reachable {
				state = theme.IconUp
			} else {
				state = theme.IconDown
			}
		}
		if p.ProxyJump != "" {
			state = "via jump"
		}
		rowW := l.listW - l.pad - 1
		prefix := state + " " + truncTo(p.Name, 10) + " "
		line := theme.Value.Render(prefix) + theme.Sub.Render(truncTo(p.User+"@"+p.Addr(), rowW-ansi.StringWidth(prefix)))
		lead := strings.Repeat(" ", l.pad)
		if selected {
			return lead + theme.Accent.Render("▎") + selFill(line, rowW)
		}
		return lead + " " + line
	}

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
	if p.ProxyJump != "" {
		latCell = theme.Dim.Render("via jump")
		dot = theme.IconIdle
		dotColor = theme.Muted
	}
	state := "Unchecked"
	if have {
		state = "Down"
		if st.Reachable {
			state = "Reachable"
		}
	}
	if p.ProxyJump != "" {
		state, latCell = "Via jump", theme.Dim.Render("—")
	}
	status := lipgloss.NewStyle().Foreground(dotColor).Width(12).Render(dot + " " + state)
	var cells []string

	// Bold on the selected name: the typographic weight reverse-video would
	// give, on the cell the eye lands on.
	nameStyle := theme.Value
	if selected {
		nameStyle = nameStyle.Bold(true)
	}
	cells = append(cells, nameStyle.Width(l.nameW).Render(truncTo(p.Name, l.nameW)))

	target := fmt.Sprintf("%s@%s", p.User, p.Host)
	if p.Port != 22 {
		target += fmt.Sprintf(":%d", p.Port)
	}
	target = truncTo(target, l.endW)
	// Subtle, not Muted: the target is real data, a step above chrome.
	cells = append(cells, theme.Sub.Width(l.endW).Render(target))

	cells = append(cells, status, lipgloss.NewStyle().Width(9).Align(lipgloss.Right).Render(latCell))
	if strings.HasPrefix(m.authReadiness(p), "missing") {
		cells[len(cells)-2] = theme.StatusWarn.Width(12).Render("! Credentials")
	}

	lead := strings.Repeat(" ", max(l.pad-1, 0))
	rowW := max(l.listW-l.pad, 20)

	trailing := ""
	switch {
	case m.testing[p.ID]:
		trailing = m.spin.View() + theme.Accent.Render(" testing")
	case m.connecting == p.ID:
		trailing = m.spin.View() + theme.Accent.Render(" connecting")
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
	left = ansi.Truncate(left, max(0, width), "…")
	if lipgloss.Width(left)+lipgloss.Width(right) >= width {
		return ansi.Truncate(left+" "+right, width, "")
	}
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

// Capped at ▆ so adjacent rows can never fuse into a solid slab.
var sparkBlocks = []rune("▁▂▃▄▅▆")

// sparkline renders the last n latency samples as an ambient monochrome
// trend — the shape carries the information; the latency band is already
// encoded twice on the row (dot colour, ping cell), a third voice here was
// noise. Failures show as a dim red ╳. With fewer than 3 valid samples a
// lone block would read as data where there is none — a dim ⋯ instead.
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
			b.WriteString(theme.StatusErr.Render("╳"))
			continue
		}
		idx := 0
		if maxV > 0 {
			idx = int(v / maxV * float64(len(sparkBlocks)-1))
		}
		b.WriteString(theme.Spark.Render(string(sparkBlocks[idx])))
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
	pw := panelWidth(m.width, 68)
	dw := pw - 6
	sections := []struct {
		name string
		rows [][2]string
	}{
		{"connect", [][2]string{
			{"v", "full details; c copies target, f fingerprint"},
			{"h", "review changed host key after testing"},
			{"enter", "connect to the selected host"},
			{"t", "test the connection (dial, handshake, auth, exec)"},
			{"r", "run a script (only ones that apply)"},
			{"m", "manage the script library"},
		}},
		{"organize", [][2]string{
			{"ctrl+f", "editor: jump to field; ctrl+s saves"},
			{"D", "resume retained script draft (session only)"},
			{"X", "discard retained script draft"},
			{"ctrl+n", "script editor: recover draft as a new copy"},
			{"tab ⇧tab", "editor: next / previous field"},
			{"a", "add a profile (step-by-step wizard)"},
			{"e", "edit the selected profile"},
			{"d", "delete the profile and its vault secrets"},
			{"c", "set the host's category (list grouping)"},
			{"i", "import hosts from ~/.ssh/config"},
			{"o", "toggle latency ordering within groups"},
			{"/", "filter profiles"},
		}},
		{"vault & sync", [][2]string{
			{"ctrl+e", "full error; c copy, d dismiss"},
			{"ctrl+r", "recover storage when blocked; then retry"},
			{"u", "unlock the vault (when locked)"},
			{"y", "identities — reusable credentials for many hosts"},
			{"s", "sync now (guarded, encrypted git push)"},
			{"g", "settings — token, repo, autosync, keychain"},
		}},
		{"navigate", [][2]string{
			{"j k ↑ ↓", "move"},
			{"pgup pgdn", "page up / down (also ctrl+u / ctrl+d)"},
			{"home end G", "jump to top / bottom"},
			{"q", "quit"},
		}},
	}
	// Blank separators only when the terminal is tall enough for them —
	// the overlay is clipped from the bottom, and losing rows costs more
	// than losing breathing space.
	sep := "\n"
	if m.height < 32 {
		sep = ""
	}
	var b strings.Builder
	b.WriteString(theme.Title.Render("Keys") + "\n\n")
	for i, sec := range sections {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(theme.Hint.Render(sec.name) + "\n")
		for _, r := range sec.rows {
			b.WriteString("  " + theme.Accent.Width(11).Render(r[0]) + theme.Value.Render(r[1]) + "\n")
		}
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
	b.WriteString(theme.Hint.Render("pgup/pgdn scroll · esc close\nCharts: samples, not uniform time; auto-scaled per host.\nScript: ctrl+s/ctrl+d save; ctrl+r run without save.\nEscape retains one draft; D on list resumes its original target."))
	return panelView(b.String(), m.width, m.height-m.footerHeight(), pw, m.panelScroll)
}
