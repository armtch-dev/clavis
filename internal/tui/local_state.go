package tui

import (
	"context"
	"fmt"
	"time"

	"github.com/armtch-dev/clavis/internal/fido2"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

type credentialSnapshotMsg struct {
	generation int
	states     map[string]string
}

func (m *Model) credentialSnapshotCmd() tea.Cmd {
	dir, generation, ctx := m.cfgDir, m.credentialGeneration, m.networkContext()
	return m.background(func() tea.Msg {
		result := credentialSnapshotMsg{generation: generation, states: map[string]string{}}
		l, err := fstxn.AcquireContext(ctx, dir)
		if err != nil {
			return result
		}
		defer l.Close()
		s, err := loadDiskLocked(l)
		if err != nil {
			return result
		}
		for _, p := range s.store.Profiles {
			pass, key := p.PassSecret(), p.KeySecret()
			if p.IdentityID != "" {
				id := s.idents.ByID(p.IdentityID)
				if id == nil {
					result.states[p.ID] = "missing identity"
					continue
				}
				p.Auth, pass, key = id.Auth, id.PassSecret(), id.KeySecret()
			}
			state := "stored · auth untested"
			if len(p.Auth) == 0 {
				state = "no auth configured"
			}
			if p.HasAuth(profile.AuthPassword) && s.vault.HasLocked(l, pass, false) != nil {
				state = "missing password"
			}
			if p.HasAuth(profile.AuthKey) && s.vault.HasLocked(l, key, false) != nil {
				state = "missing key"
			}
			result.states[p.ID] = state
		}
		return result
	}, credentialSnapshotMsg{generation: generation})
}

type localSnapshotMsg struct {
	destination                      string
	owner                            *settingsModel
	seq                              int
	keychain, fido, available, token bool
	err                              error
}

func (m *Model) localSnapshotCmd(s *settingsModel) tea.Cmd {
	if s == m.settings {
		m.settingsRefresh = false
	}
	s.snapshotSeq++
	s.snapshotReady = false
	dir, seq, ctx := m.cfgDir, s.snapshotSeq, m.networkContext()
	return m.background(func() tea.Msg {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		r := localSnapshotMsg{owner: s, seq: seq, keychain: vault.HasKeychainContext(ctx), fido: fido2.Enrolled(dir), available: fido2.Available()}
		l, err := fstxn.AcquireContext(ctx, dir)
		if err != nil {
			r.err = err
			return r
		}
		defer l.Close()
		git := gitsync.New(dir, "")
		git.Context = ctx
		r.destination = git.DestinationURL()
		v, err := vault.LoadLocked(l)
		r.err = err
		if err == nil {
			r.token = v.HasLocked(l, "github-token", true) == nil
		}
		return r
	}, localSnapshotMsg{owner: s, seq: seq, err: context.Canceled})
}

type hardwareRequest struct {
	settings *settingsModel
	welcome  *welcomeModel
	banner   string
	action   string
}
type hardwareDoneMsg struct {
	request *hardwareRequest
	err     error
}

// Commands capture values only. A detached vault under directory ownership
// rechecks the recipient before replacing/removing an existing unlock method.
func (m *Model) hardwareCmd(r *hardwareRequest, identity string) tea.Cmd {
	if m.hardware != nil {
		m.setStatus(statusWarn, "local unlock update already in progress")
		return nil
	}
	m.hardware = r
	dir, ctx := m.cfgDir, m.networkContext()
	snapshot := *m.vault
	return m.background(func() tea.Msg {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		finish := func(err error) tea.Msg {
			if err == nil {
				err = ctx.Err()
			}
			return hardwareDoneMsg{r, err}
		}
		if ctx.Err() != nil {
			return finish(ctx.Err())
		}
		if r.action == "enroll" {
			if err := fido2.EnrollContext(ctx, dir, identity); err != nil {
				return finish(err)
			}
		}
		l, err := fstxn.AcquireContext(ctx, dir)
		if err != nil {
			return finish(err)
		}
		defer l.Close()
		if err := snapshot.CheckCurrentLocked(l); err != nil {
			return finish(err)
		}
		v, err := vault.LoadLocked(l)
		if err != nil {
			return finish(err)
		}
		if identity != "" {
			if err := v.Unlock(identity); err != nil {
				return finish(fmt.Errorf("vault changed; unlock again: %w", err))
			}
		}
		switch r.action {
		case "cache", "refresh":
			if r.action == "refresh" && !vault.HasKeychainContext(ctx) {
				return finish(nil)
			}
			err = vault.SaveToKeychainContext(ctx, identity)
			if err == nil && r.action == "cache" && fido2.Enrolled(dir) {
				err = fido2.RemoveLocked(l)
			}
		case "uncache", "enroll":
			if vault.HasKeychainContext(ctx) {
				err = vault.DeleteFromKeychainContext(ctx)
			}
		case "remove-fido":
			err = fido2.RemoveLocked(l)
		}
		return finish(err)
	}, hardwareDoneMsg{r, context.Canceled})
}

func (m *Model) updateLocalState(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch r := msg.(type) {
	case localSnapshotMsg:
		if r.owner == nil || r.owner.snapshotSeq != r.seq {
			return m, nil
		}
		s := r.owner
		s.keychainSet, s.fidoSet, s.fidoAvailable, s.tokenSet = r.keychain, r.fido, r.available, r.token
		s.snapshotReady = r.err == nil
		if s == m.settings && !m.syncing {
			m.syncState.Destination = r.destination
		}
		if r.err != nil {
			s.errs = r.err.Error()
		}
	case hardwareDoneMsg:
		if m.hardware != r.request {
			return m, nil
		}
		m.hardware = nil
		if s := r.request.settings; s != nil {
			s.busy = ""
			s.errs = ""
			if r.err != nil {
				s.errs = r.err.Error()
			}
		}
		if w := r.request.welcome; w != nil && m.welcome == w {
			w.busy = false
			if r.err != nil {
				w.errs = r.err.Error()
			} else {
				m.finishRestore(" — local unlock configured")
			}
		}
		if r.err != nil {
			m.setStatus(statusErr, r.err.Error())
		} else {
			if r.request.banner != "" && m.firstRun.identity == r.request.banner {
				m.firstRun.saved = true
			}
			m.setStatus(statusOK, "local unlock updated")
		}
		if m.settings != nil {
			return m, m.localSnapshotCmd(m.settings)
		}
	}
	return m, nil
}
