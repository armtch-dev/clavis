// Package theme ports the Night Owl palette used by scriptorium
// (powershell-scripts-tui/src/Core.psm1) so both tools share one look.
package theme

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

// Palette — hex values copied verbatim from scriptorium's $script:NightOwl table.
const (
	HexBg       = "#011627"
	HexFg       = "#d6deeb" // canonical Night Owl foreground (soft blue-white)
	HexSelBg    = "#093b5e"
	HexBlack    = "#011627"
	HexRed      = "#ef5350"
	HexGreen    = "#22da6e"
	HexYellow   = "#c5e478"
	HexBlue     = "#82aaff"
	HexMagenta  = "#c792ea"
	HexCyan     = "#21c7a8"
	HexWhite    = "#ffffff"
	HexMuted    = "#637777" // Night Owl comment teal-grey — harmonizes with the bg
	HexBrYellow = "#ffeb95"
	HexBrCyan   = "#7fdbca"
	HexBorder   = "#5f7e97" // Night Owl panel border (steel blue)
)

var (
	Bg       = lipgloss.Color(HexBg)
	Fg       = lipgloss.Color(HexFg)
	SelBg    = lipgloss.Color(HexSelBg)
	Red      = lipgloss.Color(HexRed)
	Green    = lipgloss.Color(HexGreen)
	Yellow   = lipgloss.Color(HexYellow)
	Blue     = lipgloss.Color(HexBlue)
	Magenta  = lipgloss.Color(HexMagenta)
	Cyan     = lipgloss.Color(HexCyan)
	White    = lipgloss.Color(HexWhite)
	Muted    = lipgloss.Color(HexMuted)
	BrYellow = lipgloss.Color(HexBrYellow)
	BrCyan   = lipgloss.Color(HexBrCyan)
	Border   = lipgloss.Color(HexBorder)

	// CardBg sits just above the bg — same 4.5% blend toward white scriptorium uses.
	CardBg = lipgloss.Color(BlendHex(HexBg, HexWhite, 0.045))
)

// Shared styles. Focused panes get BrCyan titles, unfocused Blue — the same
// convention scriptorium's Tui.psm1 follows.
var (
	TitleFocused   = lipgloss.NewStyle().Foreground(BrCyan).Bold(true)
	TitleUnfocused = lipgloss.NewStyle().Foreground(Blue)
	PanelBorder    = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(Border)
	StatusOK       = lipgloss.NewStyle().Foreground(Green)
	StatusWarn     = lipgloss.NewStyle().Foreground(BrYellow)
	StatusErr      = lipgloss.NewStyle().Foreground(Red)
	MutedText      = lipgloss.NewStyle().Foreground(Muted)
	Selected       = lipgloss.NewStyle().Background(SelBg).Foreground(White).Bold(true)
	Label          = lipgloss.NewStyle().Foreground(Blue)
	Value          = lipgloss.NewStyle().Foreground(Fg)
	Accent         = lipgloss.NewStyle().Foreground(BrCyan)
)

// LatencyColor maps a round-trip time in ms onto the palette's heat ramp.
func LatencyColor(ms float64) lipgloss.Color {
	switch {
	case ms < 50:
		return Green
	case ms < 200:
		return BrYellow
	default:
		return Red
	}
}

// BlendHex linearly blends two #rrggbb colors; f is the weight of b.
func BlendHex(a, b string, f float64) string {
	var ar, ag, ab, br, bg, bb int
	fmt.Sscanf(a, "#%02x%02x%02x", &ar, &ag, &ab)
	fmt.Sscanf(b, "#%02x%02x%02x", &br, &bg, &bb)
	mix := func(x, y int) int { return int(float64(x) + (float64(y)-float64(x))*f) }
	return fmt.Sprintf("#%02x%02x%02x", mix(ar, br), mix(ag, bg), mix(ab, bb))
}
