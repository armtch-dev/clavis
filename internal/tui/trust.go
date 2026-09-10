package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/theme"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type trustReview struct {
	endpoint             profile.Profile
	oldFP, newFP, newKey string
	wizard               *wizardModel
	check                func(*fstxn.Lock) error
	input                textinput.Model
	err                  string
	offset               int
}

func sameTestTarget(a, b profile.Profile) bool {
	return a.ID == b.ID && a.Host == b.Host && a.Port == b.Port && a.ProxyJump == b.ProxyJump && a.User == b.User && a.IdentityID == b.IdentityID && slices.Equal(a.Auth, b.Auth) && a.HostKeyFP == b.HostKeyFP && a.HostKey == b.HostKey
}

func observedKey(fp, line string) error {
	if fp == "" || line == "" {
		return fmt.Errorf("server did not supply a complete host key; test again")
	}
	_, err := sshx.HostKeyFingerprint(profile.Profile{HostKeyFP: fp, HostKey: line})
	return err
}

func (m *Model) openTrust(p profile.Profile, r sshx.TestResult, w *wizardModel) {
	if !errors.Is(r.Err, sshx.ErrHostKeyChanged) {
		m.setStatus(statusWarn, "test this profile to review a host-key mismatch first")
		return
	}
	old, err := sshx.HostKeyFingerprint(p)
	if err == nil {
		err = observedKey(r.HostKeyFP, r.HostKeyLine)
	}
	if err != nil || old == "" || old == r.HostKeyFP {
		m.setStatus(statusErr, "no valid changed host key to review")
		return
	}
	snapshot := *m.store
	m.trust = &trustReview{endpoint: p, oldFP: old, newFP: r.HostKeyFP, newKey: r.HostKeyLine, wizard: w, check: snapshot.CheckCurrentLocked, input: newTextInput("type trust to confirm", false)}
}

func (m *Model) updateTrust(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	r := m.trust
	if key.Type == tea.KeyPgDown || key.Type == tea.KeyPgUp {
		delta := max(1, m.height-m.footerHeight()-2)
		if key.Type == tea.KeyPgUp {
			delta = -delta
		}
		r.offset = clamp(r.offset+delta, 0, max(0, len(r.scrollLines(m.width))-max(1, m.height-m.footerHeight()-2)))
		return m, nil
	}
	if key.Type == tea.KeyEsc {
		m.trust = nil
		return m, nil
	}
	if key.Type != tea.KeyEnter {
		var cmd tea.Cmd
		r.input, cmd = r.input.Update(key)
		if key.Type == tea.KeyRunes || key.Type == tea.KeyBackspace {
			r.offset = max(0, len(r.scrollLines(m.width))-max(1, m.height-m.footerHeight()-2))
		}
		return m, cmd
	}
	if r.input.Value() != "trust" {
		r.err = "type trust, then Enter, only after verifying the new fingerprint"
		r.offset = max(0, len(r.scrollLines(m.width))-max(1, m.height-m.footerHeight()-2))
		return m, nil
	}
	if r.wizard != nil {
		w := r.wizard
		if m.wizard != w || !sameTestTarget(m.effective(w.draft), r.endpoint) {
			r.err = "draft endpoint or pin changed — cancel and test again"
			return m, nil
		}
		if !w.canSave(m) {
			r.err = w.errs
			return m, nil
		}
		w.draft.HostKeyFP, w.draft.HostKey = r.newFP, r.newKey
		p := m.effective(w.draft)
		w.trustEndpoint = &p
		w.testResult = nil
		w.errs = "new key approved for this draft — save to persist, or retest"
		m.trust = nil
		return m, nil
	}
	err := m.mutate(func(s *diskState, l *fstxn.Lock) ([]fstxn.Change, error) {
		if err := r.check(l); err != nil {
			return nil, fmt.Errorf("trust review is stale — cancel and test again: %w", err)
		}
		p := s.store.ByID(r.endpoint.ID)
		if p == nil || !sameTestTarget(m.effective(*p), r.endpoint) {
			return nil, fmt.Errorf("endpoint or pin changed — cancel and test again")
		}
		p.HostKeyFP, p.HostKey = r.newFP, r.newKey
		if err := s.store.Update(*p); err != nil {
			return nil, err
		}
		c, err := s.store.Change()
		return []fstxn.Change{c}, err
	})
	if err != nil {
		r.err = err.Error()
		m.setStatus(statusErr, "trust update failed: "+err.Error())
		return m, nil
	}
	delete(m.mismatches, r.endpoint.ID)
	m.trust = nil
	m.setStatus(statusOK, "host key explicitly updated — test again to authenticate")
	return m, m.afterMutation("re-trust host key")
}

func (r *trustReview) lines() []string {
	lines := []string{"Review changed host key", r.endpoint.User + "@" + r.endpoint.Addr(), "Old fingerprint:", r.oldFP, "New fingerprint:", r.newFP, "Verify this change with the server administrator.", "Type trust, then Enter to update the pin.", r.input.View()}
	if r.wizard != nil {
		lines = append(lines, "Draft only: save the profile to persist approval.")
	}
	if r.err != "" {
		lines = append(lines, r.err)
	}
	lines = append(lines, "Esc cancels; no pin changes until confirmation.")
	return lines
}

func (r *trustReview) scrollLines(width int) []string {
	return strings.Split(ansi.Hardwrap(strings.Join(r.lines()[1:], "\n"), max(1, width-2), true), "\n")
}

func (r *trustReview) view(width, height int) string {
	inner := max(30, min(width-6, 88))
	cw := inner - 6
	// Wrap, never truncate fingerprint bytes. Public key is retained in r.newKey
	// for the transaction; the complete SHA256 values are the review identifiers.
	panel := theme.Panel.Width(inner).Render(ansi.Hardwrap(strings.Join(r.lines(), "\n"), cw, true))
	if lipgloss.Height(panel) <= height {
		return center(panel, width, height)
	}
	// At the terminal floor, trade the border for a scrollable review. Every
	// fingerprint byte remains reachable instead of being clipped by the root.
	wrapped := r.scrollLines(width)
	rows := max(1, height-2)
	start := clamp(r.offset, 0, max(0, len(wrapped)-rows))
	return "Host-key review · PgUp/PgDn\n" + strings.Join(wrapped[start:min(len(wrapped), start+rows)], "\n") + "\nEsc cancels · type trust + Enter"
}
