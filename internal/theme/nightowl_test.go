package theme

import (
	"math"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestSemanticPaletteContrast(t *testing.T) {
	defer rebase(HexBg)
	for _, bg := range []string{HexBg, "#ffffff", "#5a5475", "#808080", "#326a80"} {
		rebase(bg)
		for _, fg := range []lipgloss.Color{Fg, Subtle, Muted, Green, Red, BrYellow, BrCyan, Blue, Magenta} {
			for _, surface := range []string{bg, string(SelBg)} {
				a, b := luminance(string(fg)), luminance(surface)
				if ratio := (math.Max(a, b) + .05) / (math.Min(a, b) + .05); ratio < 4.5 {
					t.Errorf("%s on %s: contrast %.2f", fg, surface, ratio)
				}
			}
		}
	}
}

func TestMidToneBackgroundPreservesColor(t *testing.T) {
	defer rebase(HexBg)
	const bg = "#326a80"
	rebase(bg)
	if luminance(string(SelBg)) >= luminance(bg) {
		t.Fatal("selection must not brighten the dark canvas and wash out text")
	}
	for _, pair := range [][2]string{{string(Green), HexGreen}, {string(BrYellow), HexBrYellow}, {string(BrCyan), HexBrCyan}} {
		if want := readable(pair[1], bg, bg); pair[0] != want {
			t.Errorf("selection washed out %s to %s; canvas only needs %s", pair[1], pair[0], want)
		}
	}
	if Label.GetForeground() != Blue || Tag.GetForeground() != Magenta {
		t.Fatal("labels and tags must retain distinct accent colors")
	}
}

func TestInitForcesNightOwl(t *testing.T) {
	old := lipgloss.ColorProfile()
	defer lipgloss.SetColorProfile(old)
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")
	for _, term := range []string{"xterm-256color", "screen", "tmux-256color"} {
		t.Setenv("TERM", term)
		t.Setenv("CLAVIS_BG", "#5a5475")
		lipgloss.SetColorProfile(termenv.ANSI)
		rebase("#ffffff")
		Init()
		if Bg != lipgloss.Color(HexBg) || SelBg != lipgloss.Color(HexSelBg) || Blue != lipgloss.Color(HexBlue) {
			t.Fatalf("%s: Night Owl palette not restored", term)
		}
		if lipgloss.ColorProfile() != termenv.TrueColor {
			t.Fatalf("%s: truecolor not forced", term)
		}
	}
}
