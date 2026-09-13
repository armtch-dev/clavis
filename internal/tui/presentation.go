package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/theme"
	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// panelWidth includes padding, but excludes the two border cells.
func panelWidth(width, ceiling int) int { return max(8, min(width-2, ceiling)) }
func scrollOffset(offset []int) int {
	if len(offset) > 0 {
		return offset[0]
	}
	return 0
}

// Short panels shed blank space and become scrollable rather than losing
// controls below the root frame. Explicit page navigation overrides selection.
func panelView(body string, width, height, ceiling, offset int) string {
	pw := panelWidth(width, ceiling)
	style := theme.Panel.Width(pw)
	cw, rows := pw-6, height-4
	if height < 14 {
		style = style.Padding(0, 1)
		cw, rows = pw-2, height-2
		var compact []string
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(ansi.Strip(line)) != "" {
				compact = append(compact, line)
			}
		}
		body = strings.Join(compact, "\n")
	}
	lines := strings.Split(ansi.Hardwrap(body, max(cw, 1), true), "\n")
	rows = max(rows, 1)
	if len(lines) > rows {
		rows = max(1, rows-1)
		start := clamp(offset, 0, max(0, len(lines)-rows))
		if offset == 0 {
			for i, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(ansi.Strip(line)), "▎") {
					start = max(0, i-rows+1)
				}
			}
		}
		body = strings.Join(lines[start:min(start+rows, len(lines))], "\n") + "\n" + theme.Hint.Render("pgup/pgdn scroll")
	} else {
		body = strings.Join(lines, "\n")
	}
	return center(style.Render(body), width, height)
}

func inputTail(s string, width int) string {
	w := ansi.StringWidth(s)
	if w <= width {
		return s
	}
	return "‹" + ansi.Cut(s, max(0, w-width+1), w)
}

type copiedMsg struct {
	err    error
	banner string
}

func copyText(text string) tea.Cmd {
	return func() tea.Msg { return copiedMsg{err: clipboard.WriteAll(text)} }
}

func (m *Model) errorText() string {
	if m.persistenceErr != nil {
		return m.persistenceErr.Error() + "\nCtrl+R recovers storage; then retry the save."
	}
	switch m.screen {
	case scrWizard:
		if m.wizard != nil && m.wizard.errs != "" {
			return m.wizard.errs
		}
	case scrSettings:
		if m.settings != nil && m.settings.errs != "" {
			return m.settings.errs
		}
	case scrScripts:
		if m.scriptsUI != nil && m.scriptsUI.errs != "" {
			return m.scriptsUI.errs
		}
	case scrUnlock:
		if m.unlock.errs != "" {
			return m.unlock.errs
		}
	case scrWelcome:
		if m.welcome != nil && m.welcome.errs != "" {
			return m.welcome.errs
		}
	}
	return m.lastError
}

func (m *Model) syncDetails() string {
	s := m.SyncStatus()
	destination := s.Destination
	if destination == "" {
		destination = "not yet contacted"
	}
	last := "never (this session)"
	if !s.LastSuccess.IsZero() {
		last = s.LastSuccess.Format(time.RFC3339)
	}
	return fmt.Sprintf("Configured: %s\nActual destination: %s\nLast success: %s\nLocal dirty: %t · pending: %t · syncing: %t\n%s", m.cfg.Sync.Remote, destination, last, s.Dirty, s.Pending, s.InFlight, s.Error)
}

func (m *Model) detailText(p profile.Profile) string {
	p = m.effective(p)
	id := "per-host credentials"
	if p.IdentityID != "" {
		id = "missing identity: " + p.IdentityID
		if found := m.idents.ByID(p.IdentityID); found != nil {
			id = found.Name + " (" + found.ID + ")"
		}
	}
	fp, err := sshx.HostKeyFingerprint(p)
	if err != nil {
		fp = err.Error()
	}
	if fp == "" {
		fp = "not pinned"
	}
	jump := p.ProxyJump
	if jump == "" {
		jump = "none"
	}
	st, have := m.statuses[p.ID]
	checked := "not checked"
	if !st.CheckedAt.IsZero() {
		checked = st.CheckedAt.Format(time.RFC3339) + " (" + relDur(time.Since(st.CheckedAt)) + " ago)"
	}
	return fmt.Sprintf("%s\nTarget: %s@%s\n\nCONNECTION\nIdentity: %s\nJump: %s\nCredentials / auth test: %s\nReachability: %s\nGroup: %s\nTags: %s\n\nSECURITY\nFingerprint: %s\n\nLATENCY\nLast check: %s\nMin / Avg / Max: %s\nCharts: each host auto-scales 0 to its visible maximum (ms). Columns are samples, not evenly spaced time; × = failure. Failed probes back off up to 5m. Reachable does not mean authenticated; t tests auth.\n\nSYNC\n%s", p.Name, p.User, p.Addr(), id, jump, m.authReadiness(p), ansi.Strip(statusBadge(st, have, p.ProxyJump != "")), p.Category, strings.Join(p.Tags, ", "), fp, checked, ansi.Strip(pingSpread(st, have, 0)), m.syncDetails())
}

// Presence is cached on metadata/credential publication, never read by View.
// Authentication still requires an explicit test; presence alone isn't proof.
func (m *Model) authReadiness(p profile.Profile) string {
	if m.vault == nil || !m.vault.Unlocked() {
		return "locked"
	}
	if p.IdentityID != "" && m.idents.ByID(p.IdentityID) == nil {
		return "missing identity"
	}
	if result, ok := m.authResults[p.ID]; ok && sameTestTarget(m.effective(p), result.endpoint) {
		if result.result.OK {
			return "last auth test passed"
		}
		return "last auth test failed — t retries"
	}
	if state, ok := m.credentialState[p.ID]; ok {
		return state
	}
	return "not checked — t tests auth"
}

func (m *Model) resizeEditors() {
	if w := m.wizard; w != nil {
		w.input.Width = max(1, panelWidth(m.width, 72)-8)
		if w.step == stepKeyPaste {
			width, height := max(1, panelWidth(m.width, 72)-6), clamp(m.height-m.footerHeight()-18, 1, 9)
			if w.area.Width() != width {
				w.area.SetWidth(width)
			}
			if w.area.Height() != height {
				w.area.SetHeight(height)
			}
		}
	}
	if s := m.scriptsUI; s != nil {
		cw := panelWidth(m.width, 80) - 6
		s.name.Width, s.tags.Width = max(1, cw-2), max(1, cw-2)
		if s.editing {
			height := clamp(m.height-m.footerHeight()-20, 1, 14)
			if s.area.Width() != max(1, cw) {
				s.area.SetWidth(max(1, cw))
			}
			if s.area.Height() != height {
				s.area.SetHeight(height)
			}
		}
	}
	if s := m.settings; s != nil {
		s.input.Width = max(1, panelWidth(m.width, 70)-8)
	}
	m.unlock.input.Width = max(1, panelWidth(m.width, 56)-8)
	if w := m.welcome; w != nil {
		w.input.Width = max(1, panelWidth(m.width, 62)-8)
	}
}
