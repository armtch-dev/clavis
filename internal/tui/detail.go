package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/armtch-dev/clavis/internal/probe"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/theme"
)

// Short panes shed charts, section labels, then blank lines.
type detailTier struct {
	chart  bool
	labels bool
	rules  bool
}

// renderDetail shares the host panel's height and preserves the details hint.
func (m *Model) renderDetail(p *profile.Profile, l listLayout, avail int) string {
	avail = max(avail, 1)
	pane := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.Faint).
		Padding(0, 2).
		Width(l.detailW).
		Height(max(avail-2, 1)).
		MaxHeight(avail)
	cw := l.detailW - 4     // content width inside the padding
	rows := max(avail-3, 1) // borders and title
	if p == nil {
		return pane.Render(theme.Hint.Render("no profile selected"))
	}
	ep := m.effective(*p)
	p = &ep

	tiers := []detailTier{
		{chart: true, labels: true, rules: true},
		{labels: true, rules: true},
		{rules: true},
		{},
	}
	lines := m.detailLines(p, cw, tiers[len(tiers)-1])
	for _, t := range tiers {
		if cand := m.detailLines(p, cw, t); len(cand) <= rows {
			lines = cand
			break
		}
	}
	if len(lines) > rows {
		lines = append(lines[:rows-1], theme.Hint.Render("v Full details / copy"))
	}
	return pane.Render(theme.Sub.Render("Details") + "\n" + strings.Join(lines, "\n"))
}

// detailLines assembles the card's display lines for one degradation tier.
func (m *Model) detailLines(p *profile.Profile, cw int, t detailTier) []string {
	label := func(s string) string { return theme.Label.Width(15).Render(s) }
	st, have := m.statuses[p.ID]

	lines := []string{
		theme.Value.Bold(true).Render(truncTo(p.Name, cw)),
		theme.Sub.Render(truncTo(fmt.Sprintf("%s@%s:%d", p.User, p.Host, p.Port), cw)),
	}
	section := func(name string) {
		if t.rules { // "rules" tier now buys breathing room, not hairlines
			lines = append(lines, "")
		}
		if t.labels {
			lines = append(lines, theme.Hint.Render(name))
		}
	}

	// connection
	section("CONNECTION")
	network := theme.Dim.Render("· Unchecked")
	if have {
		network = theme.StatusErr.Render("○ Down")
		if st.Reachable {
			network = theme.StatusOK.Render("● Reachable")
		}
	}
	if p.ProxyJump != "" {
		network = theme.Dim.Render("· Via jump")
	}
	authTest := "Not tested"
	if result, ok := m.authResults[p.ID]; ok && sameTestTarget(*p, result.endpoint) {
		authTest = "Failed · t retry"
		if result.result.OK {
			authTest = "Passed"
		}
	}
	lines = append(lines, label("Network")+network, label("Authentication")+theme.Value.Render(authTest))
	var auth []string
	if p.HasAuth(profile.AuthKey) {
		auth = append(auth, theme.IconKey+" key")
	}
	if p.HasAuth(profile.AuthPassword) {
		auth = append(auth, "password")
	}
	if len(auth) == 0 {
		auth = append(auth, "none")
	}
	lines = append(lines, label("Method")+theme.Value.Render(strings.Join(auth, "  ")))
	if !strings.HasPrefix(m.authReadiness(*p), "last auth test") {
		lines = append(lines, label("Credentials")+theme.Value.Render(truncTo(m.authReadiness(*p), cw-15)))
	}
	if p.IdentityID != "" {
		name := "(deleted)"
		if id := m.idents.ByID(p.IdentityID); id != nil {
			name = id.Name
		}
		lines = append(lines, label("Identity")+theme.Value.Render(truncTo(name, cw-15)))
	}
	trust := "Not pinned"
	if p.HostKeyFP != "" {
		trust = "Pinned"
	}
	lines = append(lines, label("Host key")+theme.Value.Render(trust))
	if p.Category != "" {
		lines = append(lines, label("Group")+theme.Value.Render(truncTo(p.Category, cw-15)))
	}
	if len(p.Tags) > 0 {
		lines = append(lines, label("Tags")+theme.Tag.Render(truncTo("#"+strings.Join(p.Tags, " #"), cw-15)))
	}
	if p.ProxyJump != "" {
		lines = append(lines, label("Jump")+theme.Value.Render(truncTo(p.ProxyJump, cw-15)))
	}

	// health
	section("LATENCY")
	current := theme.Hint.Render("—")
	if have && st.Reachable && p.ProxyJump == "" {
		current = lipgloss.NewStyle().Foreground(theme.LatencyColor(st.LatencyMs)).Render(fmt.Sprintf("%.0f ms", st.LatencyMs))
	}
	lines = append(lines, label("Current")+current, theme.Label.Render("Min / Avg / Max"), pingSpread(st, have, 0))
	if !st.CheckedAt.IsZero() {
		lines = append(lines, theme.Dim.Render("checked "+relDur(time.Since(st.CheckedAt))+" ago"))
	}
	if t.chart {
		lines = append(lines, latencyChart(st.History, cw)...)
	}
	// "seen" only matters for a down host — for an up host it is just "now".
	if have && !st.Reachable {
		seen := theme.Hint.Render("never")
		if !st.LastSeen.IsZero() {
			seen = theme.Value.Render(st.LastSeen.Format("Jan 2 15:04"))
		}
		lines = append(lines, label("Last seen")+seen)
	}

	lines = append(lines, theme.Hint.Render("v Full details / copy"))
	return strings.Split(ansi.Hardwrap(strings.Join(lines, "\n"), cw, true), "\n")
}

// statusBadge renders the reachability state as a bold coloured badge line:
// `● UP · 13ms` in the latency band colour, `○ DOWN · ↓ 7m` in red, or a dim
// `· UNKNOWN` when no probe has answered yet.
func statusBadge(st probe.Status, have, viaJump bool) string {
	// Jump hosts are deliberately unprobed (only reachable via the hop) —
	// that's different information from "no data yet".
	if viaJump {
		return theme.Dim.Render(theme.IconIdle + " VIA JUMP · not probed")
	}
	switch {
	case have && st.Reachable:
		return theme.StatusOK.Bold(true).Render(theme.IconUp+" UP") + theme.Dim.Render(" · ") +
			lipgloss.NewStyle().Foreground(theme.LatencyColor(st.LatencyMs)).Render(fmt.Sprintf("%.0fms", st.LatencyMs))
	case have:
		txt := theme.IconDown + " DOWN"
		if !st.LastSeen.IsZero() {
			txt += " · ↓ " + relDur(time.Since(st.LastSeen))
		}
		return lipgloss.NewStyle().Foreground(theme.Red).Bold(true).Render(txt)
	default:
		return theme.Dim.Render(theme.IconIdle + " UNKNOWN")
	}
}

// pingSpread is the min/avg/max row over the probe history, ignoring failed
// (-1) samples; the legend rides along when the row has room for it.
func pingSpread(st probe.Status, have bool, cw int) string {
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
	if n == 0 {
		return theme.Hint.Render("–")
	}
	vals := fmt.Sprintf("%.0f / %.0f / %.0f ms", lo, sum/float64(n), hi)
	ping := theme.Value.Render(vals)
	// Three bare numbers force the reader to guess the convention.
	if legend := "  min·avg·max"; len(vals)+len(legend)+6 <= cw {
		ping += theme.Hint.Render(legend)
	}
	return ping
}

// Half-block ramp for the two-row chart; the full set split across two rows
// gives double vertical resolution per column.
var chartBlocks = []rune("▁▂▃▄▅▆█")

// latencyChart renders the probe history as a two-row column chart: each
// sample is one column coloured by its own latency band; the bottom row
// carries the lower half of the bar and the top row the upper half. Failed
// samples are a dim ╳ on the bottom row. Returns nil (chart omitted) with
// fewer than 3 valid samples — a lone bar would read as data where there is
// none.
func latencyChart(hist []float64, w int) []string {
	if len(hist) > w {
		hist = hist[len(hist)-w:]
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
		return nil
	}
	n := len(chartBlocks)
	var top, bot strings.Builder
	for _, v := range hist {
		if v < 0 {
			top.WriteString(" ")
			bot.WriteString(theme.StatusErr.Render("╳"))
			continue
		}
		level := 0 // 0 .. 2n-1 across both rows
		if maxV > 0 {
			level = int(v / maxV * float64(2*n-1))
		}
		fg := lipgloss.NewStyle().Foreground(theme.LatencyColor(v))
		if level < n {
			top.WriteString(" ")
			bot.WriteString(fg.Render(string(chartBlocks[level])))
		} else {
			top.WriteString(fg.Render(string(chartBlocks[level-n])))
			bot.WriteString(fg.Render(string(chartBlocks[n-1])))
		}
	}
	return []string{top.String(), bot.String(), theme.Hint.Render(fmt.Sprintf("0–%.0f ms · samples", maxV))}
}

// fingerprintLines renders the pinned host-key fingerprint in full, wrapped
// across up to two lines at the content width (fingerprints are verified end
// to end — a truncated middle hides exactly the part an attacker would vary).
// It falls back to midTrunc when even two lines can't hold it, or when the
// pane is too short for the wrap (wrap=false).
func fingerprintLines(fp string, cw int, wrap bool, label func(string) string) []string {
	w := max(cw-6, 8)
	r := []rune(fp)
	switch {
	case len(r) <= w:
		return []string{label("key") + theme.Dim.Render(fp)}
	case wrap && len(r) <= 2*w:
		return []string{
			label("key") + theme.Dim.Render(string(r[:w])),
			strings.Repeat(" ", 6) + theme.Dim.Render(string(r[w:])),
		}
	default:
		return []string{label("key") + theme.Dim.Render(midTrunc(fp, w))}
	}
}
