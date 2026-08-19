package theme

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// Inside tmux the background query can't reach the real terminal. Without a
// hint that means the ANSI fallback; with CLAVIS_BG the full tint system
// rebases onto the declared background instead — including the selection
// fill, which must not stay Night Owl navy on a foreign background.
// Order matters: the fallback case runs first because Init mutates globals.
func TestInitTmux(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")

	t.Run("no hint falls back to ANSI", func(t *testing.T) {
		t.Setenv("CLAVIS_BG", "")
		Init()
		if Faint != Muted {
			t.Errorf("Faint = %q, want the ANSI muted slot in the fallback", Faint)
		}
		if SelBg != Muted {
			t.Errorf("SelBg = %q, want the ANSI muted slot", SelBg)
		}
	})

	t.Run("CLAVIS_BG rebases the tints", func(t *testing.T) {
		const bg = "#5a5475" // Fairyfloss
		t.Setenv("CLAVIS_BG", bg)
		Init()
		if want := lipgloss.Color(BlendHex(HexFg, bg, 0.76)); Faint != want {
			t.Errorf("Faint = %q, want %q (rebased onto %s)", Faint, want, bg)
		}
		if SelBg == lipgloss.Color(HexSelBg) || SelBg == Muted {
			t.Errorf("SelBg = %q, want a fill derived from %s", SelBg, bg)
		}
	})
}
