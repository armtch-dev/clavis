package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/armtch-dev/clavis/internal/probe"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/theme"
)

// detailTier controls graceful degradation of the detail card when the pane
// is short: the chart goes first, then the tiny section labels, then the
// hairlines between blocks, and last the fingerprint's two-line wrap (a
// clipped fingerprint is worse than a mid-truncated one).
type detailTier struct {
	chart  bool
	labels bool
	rules  bool
	fpWrap bool
}

// renderDetail draws the right-hand side panel for the selected profile on
// very wide terminals: a matte pane separated by a thin left hairline,
// sharing the row region's vertical space exactly. The card reads top to
// bottom: identity, status badge, connection block, health block (ping
// spread + two-row latency history chart), security block (full host-key
// fingerprint, wrapped).
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
	ep := m.effective(*p)
	p = &ep

	tiers := []detailTier{
		{chart: true, labels: true, rules: true, fpWrap: true},
		{chart: false, labels: true, rules: true, fpWrap: true},
		{chart: false, labels: false, rules: true, fpWrap: true},
		{chart: false, labels: false, rules: false, fpWrap: true},
		{chart: false, labels: false, rules: false, fpWrap: false},
	}
	lines := m.detailLines(p, cw, tiers[len(tiers)-1])
	for _, t := range tiers {
		if cand := m.detailLines(p, cw, t); len(cand) <= avail {
			lines = cand
			break
		}
	}
	// If even the barest tier overflows, MaxHeight clips the tail.
	return pane.Render(strings.Join(lines, "\n"))
}

// detailLines assembles the card's display lines for one degradation tier.
func (m *Model) detailLines(p *profile.Profile, cw int, t detailTier) []string {
	label := func(s string) string { return theme.Label.Width(6).Render(s) }
	st, have := m.statuses[p.ID]

	lines := []string{
		theme.Accent.Render(truncTo(p.Name, cw)),
		theme.Value.Render(truncTo(fmt.Sprintf("%s@%s:%d", p.User, p.Host, p.Port), cw)),
		statusBadge(st, have, p.ProxyJump != ""),
	}
	section := func(name string) {
		if t.rules {
			lines = append(lines, theme.Divider(cw))
		}
		if t.labels {
			lines = append(lines, theme.Hint.Render(name))
		}
	}

	// connection
	section("connection")
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
	lines = append(lines, label("auth")+theme.Value.Render(strings.Join(auth, "  ")))
	if p.IdentityID != "" {
		name := "(deleted)"
		if id := m.idents.ByID(p.IdentityID); id != nil {
			name = id.Name
		}
		lines = append(lines, label("ident")+theme.Value.Render(truncTo(name, cw-6)))
	}
	if p.Category != "" {
		lines = append(lines, label("group")+theme.Value.Render(truncTo(p.Category, cw-6)))
	}
	if len(p.Tags) > 0 {
		lines = append(lines, label("tags")+theme.Tag.Render(truncTo("#"+strings.Join(p.Tags, " #"), cw-6)))
	}
	if p.ProxyJump != "" {
		lines = append(lines, label("jump")+theme.Value.Render(truncTo(p.ProxyJump, cw-6)))
	}

	// health
	section("health")
	lines = append(lines, label("ping")+pingSpread(st, have, cw))
	if t.chart {
		lines = append(lines, latencyChart(st.History, cw)...)
	}
	// "seen" only matters for a down host — for an up host it is just "now".
	if have && !st.Reachable {
		seen := theme.Hint.Render("never")
		if !st.LastSeen.IsZero() {
			seen = theme.Value.Render(st.LastSeen.Format("Jan 2 15:04"))
		}
		lines = append(lines, label("seen")+seen)
	}

	// security
	if p.HostKeyFP != "" {
		section("security")
		lines = append(lines, fingerprintLines(p.HostKeyFP, cw, t.fpWrap, label)...)
	}
	return lines
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
		s := lipgloss.NewStyle().Foreground(theme.LatencyColor(st.LatencyMs)).Bold(true)
		return s.Render(fmt.Sprintf("%s UP · %.0fms", theme.IconUp, st.LatencyMs))
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
			bot.WriteString(sparkFail.Render("╳"))
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
	return []string{top.String(), bot.String()}
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
