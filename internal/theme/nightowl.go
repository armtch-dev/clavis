// Package theme ports the Night Owl palette used by scriptorium
// (powershell-scripts-tui/src/Core.psm1) so both tools share one look.
//
// The visual language here is flat, matte, and uniform: square thin borders,
// muted section headers, and a single monochrome icon family (no colour
// emoji) drawn from the same dingbat/geometric glyphs scriptorium uses.
package theme

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
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

// Uniform monochrome icon set. The ︎ text-presentation selector forces
// flat (non-emoji) rendering on glyphs that some terminals would colourise.
const (
	IconKey     = "⚷"  // ⚷ key glyph (wider font coverage than ⚿) — key auth
	IconPwd     = "pw" // plain-text chip — password auth; survives any font
	IconGear    = "⚙︎" // ⚙ settings
	IconSync    = "⇅"  // ⇅ sync
	IconLock    = "⚠︎" // ⚠ vault locked
	IconOK      = "✓"  // ✓
	IconErr     = "✗"  // ✗
	IconPointer = "▸"  // ▸ selection pointer
	IconUp      = "●"  // ● reachable
	IconDown    = "○"  // ○ unreachable
	IconIdle    = "·"  // · unknown / no data
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

	// Subtle sits between Fg and Muted: secondary *data* (host column, dates,
	// header meta) — a step brighter than Muted, which is reserved for chrome
	// (icons, group headings). Keeps real data from blending into decoration.
	Subtle = lipgloss.Color(BlendHex(HexFg, HexBg, 0.45))

	// SparkDim is a whisper above the bg for sparkline glyphs: a trend should
	// read as texture, not compete with the data columns.
	SparkDim = lipgloss.Color(BlendHex(HexMuted, HexBg, 0.40))
)

// Init adapts the blended tints (CardBg, Faint, Subtle, SparkDim) to the
// terminal's actual background colour. The blends assume Night Owl's #011627;
// on any other dark theme they land *darker* than the real background and
// lose their intended relationship to it. Call once from main before the tea
// program starts — the OSC query needs the terminal to itself.
//
// Light backgrounds are ignored: the Night Owl foregrounds are unreadable on
// them regardless, so blending toward white would only make things worse.
func Init() {
	out := termenv.NewOutput(os.Stdout)
	c := termenv.ConvertToRGB(out.BackgroundColor())
	if 0.299*c.R+0.587*c.G+0.114*c.B >= 0.5 { // perceived luminance: not dark
		return
	}
	hex := c.Hex()
	// termenv falls back to ANSI black when the terminal can't be queried
	// (tmux/screen, non-TTY, backgrounded process), which is indistinguishable
	// from a real #000000 answer. Skip both: a spurious rebase in the failure
	// case is worse than keeping Night Owl's near-black defaults on a truly
	// black terminal.
	if hex == "#000000" || hex == HexBg {
		return
	}
	rebase(hex)
}

// rebase recomputes every bg-relative tint (and the styles built on them)
// against the given background hex.
func rebase(bgHex string) {
	CardBg = lipgloss.Color(BlendHex(bgHex, HexWhite, 0.045))
	Faint = lipgloss.Color(BlendHex(HexBorder, bgHex, 0.45))
	Subtle = lipgloss.Color(BlendHex(HexFg, bgHex, 0.45))
	SparkDim = lipgloss.Color(BlendHex(HexMuted, bgHex, 0.40))
	Hint = Hint.Foreground(Faint)
	Sub = Sub.Foreground(Subtle)
	Spark = Spark.Foreground(SparkDim)
}

// Core text styles — matte: bold is used only for the single title accent.
var (
	Title   = lipgloss.NewStyle().Foreground(BrCyan).Bold(true)
	Section = lipgloss.NewStyle().Foreground(Muted)
	Label   = lipgloss.NewStyle().Foreground(Blue)
	Value   = lipgloss.NewStyle().Foreground(Fg)
	Accent  = lipgloss.NewStyle().Foreground(BrCyan)
	Sub     = lipgloss.NewStyle().Foreground(Subtle)
	Dim     = lipgloss.NewStyle().Foreground(Muted)
	Hint    = lipgloss.NewStyle().Foreground(Faint)
	Spark   = lipgloss.NewStyle().Foreground(SparkDim)

	StatusOK   = lipgloss.NewStyle().Foreground(Green)
	StatusWarn = lipgloss.NewStyle().Foreground(BrYellow)
	StatusErr  = lipgloss.NewStyle().Foreground(Red)

	// MutedText kept for existing callers; equivalent to Dim.
	MutedText = Dim

	// Selected row: the SelBg fill is painted by the list renderer itself
	// (tui.selFill) so per-cell foregrounds survive on top of it — no forced
	// white. SelTick is the pointer on the left.
	SelTick = lipgloss.NewStyle().Foreground(BrCyan)

	// Chip is a small metadata glyph (auth kind) — muted, understated.
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
