package tui

import (
	"fmt"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

// mutate owns one short local transaction. TryAcquire never queues UI work
// behind network/cross-process ownership; callers retain drafts on contention.
// ponytail: synchronous credential-sized local I/O; move to detached commands
// if large local stores make fsync/encryption visibly slow (Task 5).
func (m *Model) mutate(build func(*diskState, *fstxn.Lock) ([]fstxn.Change, error)) error {
	if m.syncing || m.recovering {
		return fmt.Errorf("storage work in progress — draft retained")
	}
	if m.persistenceErr != nil {
		return fmt.Errorf("press ctrl+r to recover storage, then retry: %w", m.persistenceErr)
	}
	release, err := m.mutationLock()
	if err != nil {
		return err
	}
	defer release()
	l := m.uiLock
	for _, err := range []error{m.cfg.CheckCurrentLocked(l), m.store.CheckCurrentLocked(l), m.idents.CheckCurrentLocked(l), m.scripts.CheckCurrentLocked(l), m.vault.CheckCurrentLocked(l)} {
		if err != nil {
			return err
		}
	}
	s, err := loadDiskLocked(l)
	if err != nil {
		return err
	}
	changes, err := build(s, l)
	if err != nil {
		return err
	}
	if err := m.noteWrite(l.Apply(changes)); err != nil {
		return err
	}
	// Change doesn't advance a store's private revision. Never publish s.
	s, err = loadDiskLocked(l)
	if err != nil {
		return m.noteWrite(err)
	}
	m.applyDisk(s)
	return nil
}

func (m *Model) afterMutation(what string) tea.Cmd {
	m.syncState.Dirty = true
	if m.cfg.Sync.AutoSync && m.cfg.Sync.Remote != "" {
		return m.syncCmd("clavis: " + what)
	}
	return nil
}

func secretDeletes(names []string) ([]fstxn.Change, error) {
	var changes []fstxn.Change
	for _, name := range names {
		c, err := vault.DeleteChange(name, false)
		if err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}
	return changes, nil
}

func (w *wizardModel) credentialChanges(s *diskState, l *fstxn.Lock, pass, key, phrase string, bound bool) ([]fstxn.Change, error) {
	if !bound && w.useKey && len(w.keyPEM) > 0 {
		if _, err := sshx.AuthMethods(sshx.Credentials{PrivateKey: w.keyPEM, Passphrase: w.passphrase}); err != nil {
			if w.keyNeedsPassphrase {
				w.setStep(stepPassphrase)
			} else {
				w.setStep(stepKeySource)
			}
			return nil, err
		}
	}
	var changes []fstxn.Change
	for _, item := range []struct {
		name    string
		enabled bool
		value   []byte
	}{
		{pass, !bound && w.usePassword, []byte(w.password)},
		{key, !bound && w.useKey, w.keyPEM},
		{phrase, !bound && w.useKey && (len(w.keyPEM) == 0 || w.keyNeedsPassphrase), []byte(w.passphrase)},
	} {
		var c fstxn.Change
		var err error
		switch {
		case !item.enabled:
			c, err = vault.DeleteChange(item.name, false)
		case len(item.value) > 0:
			c, err = s.vault.SecretChangeLocked(l, item.name, item.value, false)
		default:
			// Empty edit means keep, but cannot create missing required secrets.
			if item.name != phrase {
				err = s.vault.HasLocked(l, item.name, false)
			}
			if err != nil {
				return nil, fmt.Errorf("credential required (%s): %w", item.name, err)
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}
	return changes, nil
}

func (m *Model) changeConfig(edit func(*config.Config)) error {
	return m.mutate(func(s *diskState, l *fstxn.Lock) ([]fstxn.Change, error) {
		edit(s.cfg)
		c, err := s.cfg.Change()
		return []fstxn.Change{c}, err
	})
}

type recoveredMsg struct {
	state *diskState
	err   error
}

// Recovery is explicit and runs under a NEW acquisition after failed Apply's
// owner has closed. It never replays an action key or guesses commit outcome.
func (m *Model) recoverCmd() tea.Cmd {
	if m.recovering || m.syncing {
		return nil
	}
	m.recovering = true
	dir, ctx := m.cfgDir, m.networkContext()
	return m.background(func() tea.Msg {
		l, err := fstxn.AcquireContext(ctx, dir)
		if err != nil {
			return recoveredMsg{err: err}
		}
		defer l.Close()
		s, err := loadDiskLocked(l)
		return recoveredMsg{s, err}
	}, recoveredMsg{err: fmt.Errorf("recovery canceled")})
}
