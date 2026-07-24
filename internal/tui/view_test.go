package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/armtch-dev/clavis/internal/probe"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/theme"
)

// Status messages fade: a matching statusExpireMsg clears the message, a
// stale-generation one must not clear a newer message, and each message
// schedules exactly one expiry tick.
func TestStatusExpiry(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList

	m.setStatus(statusInfo, "first")
	if _, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24}); cmd == nil {
		t.Fatal("expected an expiry tick to be scheduled after setStatus")
	}
	if _, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24}); cmd != nil {
		t.Error("second pass scheduled another tick for the same message")
	}

	// Matching expiry clears the message.
	seq := m.statusSeq
	m.Update(statusExpireMsg{seq})
	if m.statusMsg != "" {
		t.Errorf("matching expiry left statusMsg = %q", m.statusMsg)
	}

	// A stale expiry (scheduled for an older message) must not clear a newer one.
	m.setStatus(statusInfo, "older")
	stale := m.statusSeq
	m.setStatus(statusOK, "newer")
	m.Update(statusExpireMsg{stale})
	if m.statusMsg != "newer" {
		t.Errorf("stale expiry cleared newer message, statusMsg = %q", m.statusMsg)
	}
	m.Update(statusExpireMsg{m.statusSeq})
	if m.statusMsg != "" {
		t.Errorf("current expiry left statusMsg = %q", m.statusMsg)
	}

	// While syncing the footer keeps its line; expiry leaves the message alone.
	m.setStatus(statusOK, "held")
	m.syncing = true
	m.Update(statusExpireMsg{m.statusSeq})
	if m.statusMsg != "held" {
		t.Errorf("expiry during sync cleared statusMsg, got %q", m.statusMsg)
	}
	m.syncing = false
}

// While work is in flight the footer (and testing rows) animate: the view
// must contain the current spinner frame, and Update must start/stop the
// spinner tick loop with the work.
func TestSpinnerActive(t *testing.T) {
	m := newTestModel(t)
	m.screen = scrList
	m.width, m.height = 80, 24

	m.syncing = true
	if out := m.View(); !strings.Contains(out, spinner.MiniDot.Frames[0]) {
		t.Error("syncing view is missing the spinner frame")
	}
	if _, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24}); cmd == nil {
		t.Fatal("expected a spinner tick to be scheduled while syncing")
	}
	if !m.spinning {
		t.Error("spinning flag not set while active")
	}

	// Work done: the next TickMsg is swallowed and the loop marked stopped.
	m.syncing = false
	if _, cmd := m.Update(spinner.TickMsg{ID: m.spin.ID()}); cmd != nil {
		t.Error("tick after work finished should be swallowed")
	}
	if m.spinning {
		t.Error("spinning flag still set after work finished")
	}
}

// The selected row's background fill must survive the SGR resets that end
// every foreground-styled cell: after each inner reset the background
// sequence has to be re-opened, or the highlight tears and only the unstyled
// tail of the row gets filled (the original bug, visible on any colour
// terminal). Tests run colourless by default, so force a profile.
func TestSelectionFillNotTorn(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(old)

	const reset = "\x1b[0m"
	marker := lipgloss.NewStyle().Background(theme.SelBg).Render("|")
	seq := marker[:strings.Index(marker, "|")]
	if seq == "" {
		t.Fatal("no background sequence produced under TrueColor profile")
	}

	in := " " + theme.StatusOK.Render("●") + " name " + theme.Sub.Render("root@host") + " tail"
	out := selFill(in, 40)

	if lipgloss.Width(out) != 40 {
		t.Errorf("selFill width = %d, want 40", lipgloss.Width(out))
	}
	if !strings.HasPrefix(out, seq) {
		t.Error("selFill output does not open with the background sequence")
	}
	if !strings.HasSuffix(out, reset) {
		t.Error("selFill output does not end with a reset")
	}
	// Every reset except the final one must immediately re-open the bg.
	body := strings.TrimSuffix(out, reset)
	if n, m := strings.Count(body, reset), strings.Count(body, reset+seq); n != m {
		t.Errorf("%d of %d inner resets re-open the selection background", m, n)
	}
}

// chromeFill (header/footer chrome tint) must emit exactly `width` cells —
// clipping over-wide input, padding short input — and re-open the surface
// background after every per-cell reset, like selFill.
func TestChromeFillWidth(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(old)

	const reset = "\x1b[0m"
	marker := lipgloss.NewStyle().Background(theme.Surface).Render("|")
	seq := marker[:strings.Index(marker, "|")]
	if seq == "" {
		t.Fatal("no background sequence produced under TrueColor profile")
	}

	short := theme.Title.Render("clavis") + "  " + theme.Dim.Render("meta")
	long := strings.Repeat("x", 80)
	for _, tc := range []struct {
		in string
		w  int
	}{{short, 40}, {long, 40}, {"", 12}} {
		out := chromeFill(tc.in, tc.w)
		if got := lipgloss.Width(out); got != tc.w {
			t.Errorf("chromeFill(%q, %d) width = %d", tc.in, tc.w, got)
		}
	}
	out := chromeFill(short, 40)
	body := strings.TrimSuffix(out, reset)
	if n, m := strings.Count(body, reset), strings.Count(body, reset+seq); n != m {
		t.Errorf("%d of %d inner resets re-open the chrome background", m, n)
	}
}

// The fleet summary strip: segments appear only when they apply, and the
// whole strip disappears when there is nothing to say.
func TestFleetSummary(t *testing.T) {
	m := newTestModel(t)
	m.width, m.height = 100, 30
	l := m.layoutList()

	// Nothing probed, no remote: no strip at all.
	if s := m.fleetSummary(l); s != "" {
		t.Errorf("empty fleet produced a strip: %q", s)
	}

	add := func(name string) *profile.Profile {
		p, err := m.store.Add(profile.Profile{
			Name: name, Host: name + ".example.com", Port: 22, User: "root",
			Auth: []profile.AuthKind{profile.AuthKey},
		})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	up1, up2 := add("u1"), add("u2")
	m.statuses[up1.ID] = probe.Status{ProfileID: up1.ID, Reachable: true, LatencyMs: 10}
	m.statuses[up2.ID] = probe.Status{ProfileID: up2.ID, Reachable: true, LatencyMs: 30}

	s := m.fleetSummary(l)
	if !strings.Contains(s, "2 up") || !strings.Contains(s, "avg 20ms") {
		t.Errorf("strip missing up/avg segments: %q", s)
	}
	if strings.Contains(s, "down") || strings.Contains(s, theme.IconSync) {
		t.Errorf("strip has segments that don't apply: %q", s)
	}

	dn := add("d1")
	m.statuses[dn.ID] = probe.Status{ProfileID: dn.ID, Reachable: false}
	m.cfg.Sync.Remote = "https://github.com/yshah/clavis-sync.git"
	s = m.fleetSummary(l)
	if !strings.Contains(s, "1 down") || !strings.Contains(s, "yshah/clavis-sync") {
		t.Errorf("strip missing down/remote segments: %q", s)
	}
	if w := lipgloss.Width(s); w > l.width {
		t.Errorf("strip is %d cells wide, frame is %d", w, l.width)
	}

	// In a tall frame the strip is anchored just above the footer.
	m.screen = scrList
	lines := strings.Split(m.View(), "\n")
	if len(lines) != 30 {
		t.Fatalf("frame height = %d, want 30", len(lines))
	}
	if !strings.Contains(lines[len(lines)-3], "avg") {
		t.Errorf("strip not anchored above the footer, line = %q", lines[len(lines)-3])
	}
}

// The host-key fingerprint wraps in full across two lines; only when two
// lines can't hold it (or the pane is too short to wrap) does it mid-truncate.
func TestFingerprintLines(t *testing.T) {
	label := func(s string) string { return s }
	fp := "SHA256:Qcvfy5RXG3sVdD2Yb3D5bDT0FhSqYRTYUn+aZLDGCfk" // 50 runes
	got := fingerprintLines(fp, 30+6, true, label)             // w=30: needs 2 lines
	if len(got) != 2 {
		t.Fatalf("expected a 2-line wrap, got %d line(s): %q", len(got), got)
	}
	joined := strings.TrimPrefix(stripAnsi(got[0]), "key") + strings.TrimLeft(stripAnsi(got[1]), " ")
	if joined != fp {
		t.Errorf("wrapped fingerprint = %q, want the full %q", joined, fp)
	}
	// wrap disabled (short pane): one mid-truncated line.
	if got := fingerprintLines(fp, 36, false, label); len(got) != 1 || !strings.Contains(stripAnsi(got[0]), "…") {
		t.Errorf("no-wrap tier should mid-truncate to one line, got %q", got)
	}
	// Absurdly long fingerprint: two lines can't hold it — mid-truncate.
	if got := fingerprintLines(strings.Repeat("a", 200), 36, true, label); len(got) != 1 {
		t.Errorf("overlong fingerprint should fall back to one line, got %d", len(got))
	}
}

func stripAnsi(s string) string {
	for {
		i := strings.Index(s, "\x1b[")
		if i < 0 {
			return s
		}
		j := strings.IndexByte(s[i:], 'm')
		if j < 0 {
			return s
		}
		s = s[:i] + s[i+j+1:]
	}
}

// Render the list at a spread of terminal sizes: no panics, the key legend is
// always present, and the frame never exceeds the terminal height.
func TestViewListResponsive(t *testing.T) {
	m := newTestModel(t)
	for _, name := range []string{"alpha", "a-fairly-long-profile-name-here", "gamma"} {
		p, err := m.store.Add(profile.Profile{
			Name: name, Host: name + ".example.com", Port: 22, User: "root",
			Auth: []profile.AuthKind{profile.AuthKey}, Tags: []string{"prod", "eu"},
			Category: "prod",
		})
		if err != nil {
			t.Fatal(err)
		}
		m.statuses[p.ID] = probe.Status{ProfileID: p.ID, Reachable: true, LatencyMs: 42,
			History: []float64{10, 20, -1, 40}}
	}
	m.screen = scrList

	sizes := [][2]int{{40, 10}, {60, 15}, {80, 24}, {100, 30}, {140, 45}}
	for _, s := range sizes {
		m.width, m.height = s[0], s[1]
		out := m.View()
		if !strings.Contains(out, "quit") {
			t.Errorf("%dx%d: key legend missing", s[0], s[1])
		}
		if h := lipgloss.Height(out); h > s[1] {
			t.Errorf("%dx%d: frame is %d lines tall", s[0], s[1], h)
		}
	}

	// Wide terminal: detail side panel plus both in-group orderings (with the
	// always-on category headings) must render without panics and stay within
	// the terminal height. Give one host a down status with a LastSeen so the
	// relative "↓ …" cell and the detail pane's down state render too.
	vis := m.visible()
	down := vis[len(vis)-1]
	m.statuses[down.ID] = probe.Status{ProfileID: down.ID, Reachable: false,
		LastSeen: time.Now().Add(-7 * time.Minute), History: []float64{10, -1, -1}}
	if _, err := m.store.Add(profile.Profile{
		Name: "untagged-host", Host: "u.example.com", Port: 2222, User: "ops",
		Auth: []profile.AuthKind{profile.AuthPassword},
	}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []sortMode{sortDefault, sortLatency} {
		m.sortMode = mode
		for _, s := range [][2]int{{140, 45}, {140, 12}, {130, 20}} {
			m.width, m.height = s[0], s[1]
			for c := range m.visible() {
				m.cursor = c
				out := m.View()
				if h := lipgloss.Height(out); h > s[1] {
					t.Errorf("sort=%v %dx%d cursor=%d: frame is %d lines tall", mode, s[0], s[1], c, h)
				}
			}
		}
	}
	m.width, m.height = 140, 45
	m.cursor = 0
	if out := m.View(); !strings.Contains(out, "↓ 7m") {
		t.Errorf("down host with LastSeen should show relative age, got frame without \"↓ 7m\"")
	}
	// Category group headings render always, carrying host/up counts.
	if out := m.View(); !strings.Contains(out, "prod · ") || !strings.Contains(out, "uncategorized · ") {
		t.Errorf("category group headings with counts should always render")
	}
	m.sortMode = sortDefault
	m.cursor = 0

	// No display line may exceed the terminal width: overflow wraps in the
	// terminal and tears the selection highlight across two lines. Long
	// tags at tag-showing widths (>=96) are the regression case.
	if _, err := m.store.Add(profile.Profile{
		Name: "hetzner reverse proxy", Host: "5.78.159.33", Port: 22, User: "root",
		Auth: []profile.AuthKind{profile.AuthKey}, Tags: []string{"cloud", "hetzner", "proxy"},
	}); err != nil {
		t.Fatal(err)
	}
	// Crowd the header meta too: an active sort indicator, a down host, and a
	// sync remote all compete with the title for one line — at 70-90 cols the
	// meta must drop entries rather than overflow and wrap the frame.
	m.cfg.Sync.Remote = "https://github.com/yshah/clavis-sync.git"
	for _, mode := range []sortMode{sortDefault, sortLatency} {
		m.sortMode = mode
		for _, s := range [][2]int{{70, 24}, {80, 24}, {90, 24}, {96, 24}, {100, 24}, {110, 24}, {129, 24}} {
			m.width, m.height = s[0], s[1]
			for c := range m.visible() {
				m.cursor = c
				for _, line := range strings.Split(m.View(), "\n") {
					if w := lipgloss.Width(line); w > s[0] {
						t.Errorf("sort=%v %dx%d cursor=%d: line is %d cells wide: %q", mode, s[0], s[1], c, w, line)
					}
				}
			}
		}
	}
	m.cfg.Sync.Remote = ""
	m.sortMode = sortDefault
	m.cursor = 0

	// Overlay screens should render without panicking at any size.
	for _, s := range sizes {
		m.width, m.height = s[0], s[1]
		m.help = true
		_ = m.View()
		m.help = false
		m.wizard = newWizard(m, nil)
		m.screen = scrWizard
		_ = m.View()
		m.settings = newSettings(m)
		m.screen = scrSettings
		_ = m.View()
		m.screen = scrList
	}
}
