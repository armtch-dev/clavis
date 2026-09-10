package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

func reviewKey(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }
