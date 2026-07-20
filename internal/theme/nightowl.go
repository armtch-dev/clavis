// Package theme ports the Night Owl palette used by scriptorium
// (powershell-scripts-tui/src/Core.psm1) so both tools share one look.
//
// The visual language here is deliberately flat and matte: square thin
// borders, muted section headers, no emoji, and colour used sparingly as
// accent rather than decoration.
package theme

import (
	"fmt"
	"strings"

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

	// CardBg sits just above the bg — same 4.5% blend toward white scriptorium
	// uses. Faint is a dimmer steel for dividers and hairlines.
	CardBg = lipgloss.Color(BlendHex(HexBg, HexWhite, 0.045))
	Faint  = lipgloss.Color(BlendHex(HexBorder, HexBg, 0.45))
)

// Core text styles — matte: bold is used only for the single title accent.
var (
	Title = lipgloss.NewStyle().Foreground(BrCyan).Bold(true)
	// Section is a quiet uppercase-ish label for grouping.
	Section = lipgloss.NewStyle().Foreground(Muted)
	Label   = lipgloss.NewStyle().Foreground(Blue)
	Value   = lipgloss.NewStyle().Foreground(Fg)
	Accent  = lipgloss.NewStyle().Foreground(BrCyan)
	Dim     = lipgloss.NewStyle().Foreground(Muted)
	Hint    = lipgloss.NewStyle().Foreground(Faint)

	StatusOK   = lipgloss.NewStyle().Foreground(Green)
	StatusWarn = lipgloss.NewStyle().Foreground(BrYellow)
	StatusErr  = lipgloss.NewStyle().Foreground(Red)

	// MutedText kept for existing callers; equivalent to Dim.
	MutedText = Dim

	// Selected row: matte fill, no bold, paired with SelTick on the left.
	Selected = lipgloss.NewStyle().Background(SelBg).Foreground(White)
	SelTick  = lipgloss.NewStyle().Foreground(BrCyan)

	// Chip is a small metadata tag (auth kind, count) — muted, understated.
	Chip = lipgloss.NewStyle().Foreground(Muted)
	Tag  = lipgloss.NewStyle().Foreground(Blue)

	// Panel is a flat modal container: square thin border, generous padding.
	Panel = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(Border).
		Padding(1, 3)

	// PanelBorder kept for existing callers (square, matte).
	PanelBorder = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(Border)

	// Compatibility aliases.
	TitleFocused   = Title
	TitleUnfocused = lipgloss.NewStyle().Foreground(Blue)
)

// Divider returns a full-width hairline in the faint steel colour.
func Divider(width int) string {
	if width < 1 {
		width = 1
	}
	return lipgloss.NewStyle().Foreground(Faint).Render(strings.Repeat("─", width))
}

// Key renders a keycap-style hint (e.g. the "a" in "a add").
func Key(s string) string { return Accent.Render(s) }

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
