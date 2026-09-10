package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/theme"
)

// --- identities manager ("y" on the list) ---
//
// An identity is a reusable credential set (username + password/key) that
// any number of profiles authenticate with. Creation and editing reuse the
// profile wizard in identity mode; this screen lists, opens, and deletes.

type identsModel struct {
	cursor     int
	confirmDel bool
	deleteID   string
}

// usedBy counts the profiles bound to an identity.
func (m *Model) usedBy(identID string) int {
	return identityUsers(m.store, identID)
}

func identityUsers(store *profile.Store, identID string) int {
	n := 0
	for _, p := range store.Profiles {
		if p.IdentityID == identID {
			n++
		}
	}
	return n
}

func (m *Model) updateIdentities(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := m.identsUI
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	list := m.idents.Identities

	if s.confirmDel {
		target := s.deleteID
		s.confirmDel, s.deleteID = false, ""
		if (key.String() == "y" || key.String() == "Y") && target != "" {
			release, err := m.mutationLock()
			if err != nil {
				m.setStatus(statusErr, err.Error())
				return m, nil
			}
			defer release()
			if m.syncing || m.persistenceErr != nil {
				m.setStatus(statusWarn, "deletion paused — retry after sync/storage recovery")
				return m, nil
			}
			if err := m.idents.CheckCurrentLocked(m.uiLock); err != nil {
				m.setStatus(statusErr, err.Error())
				return m, nil
			}
			current, err := profile.LoadStoreLocked(m.uiLock)
			if err != nil {
				m.setStatus(statusErr, err.Error())
				return m, nil
			}
			id := m.idents.ByID(target)
			if id == nil {
				m.setStatus(statusWarn, "identity no longer exists — select it again")
				return m, nil
			}
			if n := max(m.usedBy(target), identityUsers(current, target)); n > 0 {
				m.setStatus(statusErr, fmt.Sprintf("%s is used by %d profile(s) — edit them first", id.Name, n))
				return m, nil
			}
			if err := m.vault.CheckCurrentLocked(m.uiLock); err != nil {
				m.setStatus(statusErr, err.Error())
				return m, nil
			}
			name := id.Name
			err = m.mutate(func(state *diskState, l *fstxn.Lock) ([]fstxn.Change, error) {
				if identityUsers(state.store, target) > 0 {
					return nil, fmt.Errorf("identity is now in use — rebind profiles first")
				}
				secrets, err := state.idents.Remove(target)
				if err != nil {
					return nil, err
				}
				changes, err := secretDeletes(secrets)
				if err != nil {
					return nil, err
				}
				c, err := state.idents.Change()
				return append(changes, c), err
			})
			if err != nil {
				m.setStatus(statusErr, "delete failed: "+err.Error())
				return m, nil
			}
			m.setStatus(statusOK, "deleted identity "+name)
			if n := len(m.idents.Identities); s.cursor >= n {
				s.cursor = max(0, n-1)
			}
			s.confirmDel = false
			return m, m.afterMutation("delete identity " + name)
		}
		s.confirmDel = false
		return m, nil
	}

	switch key.String() {
	case "esc", "q":
		m.identsUI = nil
		m.screen = scrList
	case "up", "k":
		if s.cursor > 0 {
			s.cursor--
		}
	case "down", "j":
		if s.cursor < len(list)-1 {
			s.cursor++
		}
	case "n":
		m.wizard = newIdentityWizard(m, nil)
		m.screen = scrWizard
	case "e", "enter":
		if s.cursor < len(list) {
			m.wizard = newIdentityWizard(m, m.idents.ByID(list[s.cursor].ID))
			m.screen = scrWizard
		}
	case "d":
		if s.cursor < len(list) {
			// Deleting an identity that profiles depend on would strand them
			// credential-less; rebind those profiles first.
			if n := m.usedBy(list[s.cursor].ID); n > 0 {
				m.setStatus(statusErr, fmt.Sprintf("%s is used by %d profile(s) — edit them first", list[s.cursor].Name, n))
				return m, nil
			}
			s.confirmDel = true
			s.deleteID = list[s.cursor].ID
		}
	}
	return m, nil
}

func (m *Model) viewIdentities(width, height int) string {
	s := m.identsUI
	inner := panelWidth(width, 76)
	cw := inner - 6
	list := m.idents.Identities

	var b strings.Builder
	b.WriteString(theme.Title.Render("Identities") +
		theme.Dim.Render("  reusable credentials for many hosts") + "\n\n")

	if len(list) == 0 {
		b.WriteString(theme.Hint.Render("No identities yet. Press ") + theme.Key("n") +
			theme.Hint.Render(" to create one — profiles can then pick it in the wizard.") + "\n")
	}
	maxRows := clamp(height-10, 1, 14)
	start := 0
	if s.cursor >= maxRows {
		start = s.cursor - maxRows + 1
	}
	for i := start; i < len(list) && i < start+maxRows; i++ {
		id := list[i]
		var chips []string
		if id.HasAuth(profile.AuthKey) {
			chips = append(chips, theme.IconKey)
		}
		if id.HasAuth(profile.AuthPassword) {
			chips = append(chips, theme.IconPwd)
		}
		line := theme.Value.Render(truncTo(id.Name, cw/3)) +
			theme.Sub.Render("  "+id.User) +
			theme.Chip.Render("  "+strings.Join(chips, " "))
		if n := m.usedBy(id.ID); n > 0 {
			line += theme.Dim.Render(fmt.Sprintf("  %d host(s)", n))
		}
		if i == s.cursor {
			b.WriteString(theme.Accent.Render("▎") + selFill(ansi.Truncate(" "+line, cw-1, "…"), cw-1) + "\n")
		} else {
			b.WriteString("  " + ansi.Truncate(line, cw-2, "…") + "\n")
		}
	}
	if len(list) > maxRows {
		b.WriteString(theme.Dim.Render(fmt.Sprintf("  %d–%d of %d", start+1, min(start+maxRows, len(list)), len(list))) + "\n")
	}

	if id := m.idents.ByID(s.deleteID); s.confirmDel && id != nil {
		b.WriteString("\n" + ansi.Truncate(theme.StatusErr.Render("delete “"+id.Name+"” and its vault secrets? ")+
			hintKeys([][2]string{{"y", "delete"}, {"any", "cancel"}}), cw, "…") + "\n")
	}

	b.WriteString("\n" + theme.Divider(cw) + "\n")
	b.WriteString(fitHints(cw,
		[][2]string{{"enter", "edit"}, {"n", "new"}, {"d", "delete"}, {"esc", "back"}},
		[][2]string{{"enter", "edit"}, {"n", "new"}, {"d", "del"}, {"esc", "back"}}))
	return panelView(b.String(), width, height, inner, m.panelScroll)
}
