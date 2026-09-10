package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/fido2"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

// SyncState is retained independently of the expiring footer, for settings/details.
// Dirty means local persisted changes have not yet been successfully pushed.
type SyncState struct {
	Destination              string
	LastSuccess              time.Time
	Pending, Dirty, InFlight bool
	Error                    string
}

func (m *Model) SyncStatus() SyncState {
	s := m.syncState
	s.InFlight = m.syncing
	s.Pending = m.syncPending
	return s
}

type diskState struct {
	cfg     *config.Config
	store   *profile.Store
	idents  *profile.IdentityStore
	scripts *script.Store
	vault   *vault.Vault
}

func loadDiskLocked(l *fstxn.Lock) (*diskState, error) {
	s := &diskState{}
	var err error
	if s.cfg, err = config.LoadLocked(l); err != nil {
		return nil, err
	}
	if s.store, err = profile.LoadStoreLocked(l); err != nil {
		return nil, err
	}
	if s.idents, err = profile.LoadIdentitiesLocked(l); err != nil {
		return nil, err
	}
	if s.scripts, err = script.LoadStoreLocked(l); err != nil {
		return nil, err
	}
	if s.vault, err = vault.LoadLocked(l); err != nil {
		return nil, err
	}
	return s, nil
}

// applyDisk preserves live editor objects and selection. It never resolves a key
// from the environment or Keychain. Only an already-valid identity can survive.
func (m *Model) applyDisk(s *diskState) {
	// Reload can change credentials alone or rotate the recipient without moving
	// an endpoint. Never hand over a pending connection's captured old credentials.
	m.cancelPending()
	// A confirmation authorizes an observed target and its prerequisites, not a
	// future cursor row. Any coherent reload requires a fresh destructive intent.
	if m.identsUI != nil {
		m.identsUI.confirmDel, m.identsUI.deleteID = false, ""
	}
	if m.scriptsUI != nil {
		m.scriptsUI.confirmDel, m.scriptsUI.deleteID = false, ""
	}
	m.confirm = confirmModel{}
	if m.screen == scrConfirmDelete {
		m.screen = scrList
	}
	if w := m.wizard; w != nil && w.editing {
		if w.ident != nil {
			if !reflect.DeepEqual(m.idents.ByID(w.ident.ID), s.idents.ByID(w.ident.ID)) {
				m.staleWizard = w
			}
		} else if !reflect.DeepEqual(m.store.ByID(w.draft.ID), s.store.ByID(w.draft.ID)) {
			m.staleWizard = w
		}
		if w.ident == nil && s.store.ByID(w.draft.ID) == nil && w.testJob != nil {
			w.testJob.cancel()
			w.awaitingTest = false
			w.errs = "profile was deleted — draft retained; reopen before saving"
		}
	}
	if ed := m.scriptsUI; ed != nil && ed.editID != "" && !reflect.DeepEqual(m.scripts.ByID(ed.editID), s.scripts.ByID(ed.editID)) {
		m.staleScript = ed
	}
	if m.selectedID == "" {
		m.rememberSelection(m.visible())
	}
	changed := m.vault != nil && m.vault.Recipient() != s.vault.Recipient()
	if m.vault != nil && !changed && m.vault.Unlocked() {
		if id, err := m.vault.Identity(); err == nil {
			_ = s.vault.Unlock(id)
		}
	}
	m.cfg, m.store, m.idents, m.scripts, m.vault = s.cfg, s.store, s.idents, s.scripts, s.vault
	m.settingsRefresh = m.settings != nil
	if w := m.wizard; w != nil && w.step == stepIdentity {
		w.reconcileIdentityPick()
	}
	if m.welcome != nil {
		m.welcome.hasVault = m.vault != nil
	}
	m.syncTargets()
	m.clampCursor()
	if changed {
		m.unlock = newUnlock(m.vault, m.cfgDir)
		// Keep any editor objects intact; after unlock the user can return to them.
		m.resumeScreen = m.screen
		m.screen = scrUnlock
		m.unlock.errs = "vault recipient changed — unlock with the current master key"
	}
}

// dispatch owns the filesystem only for short UI work. The network worker never
// holds a lock the UI waits for. All nested storage calls use uiLock via helpers.
// Compound CRUD uses detached local transactions; long-running work uses commands.
func (m *Model) dispatch(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Capture the origin before any deferral/reload, including direct fixtures.
	switch result := msg.(type) {
	case tokenCheckedMsg:
		if result.request == nil && m.settings != nil {
			result.request = m.settings.request
			msg = result
		}
	case repoCreatedMsg:
		if result.request == nil && m.settings != nil {
			result.request = m.settings.request
			msg = result
		}
	}
	if m.selectedID == "" {
		m.rememberSelection(m.visible())
	}
	if result, ok := msg.(recoveredMsg); ok {
		m.recovering = false
		if result.err != nil {
			m.setStatus(statusErr, "recovery failed; draft retained — ctrl+r to retry: "+result.err.Error())
			return m, nil
		}
		m.applyDisk(result.state)
		m.persistenceErr = nil
		m.setStatus(statusInfo, "storage recovered; drafts retained — review and retry the action")
		return m, nil
	}
	if m.persistenceErr != nil || m.recovering {
		switch msg.(type) {
		case tokenCheckedMsg, repoCreatedMsg:
			// Settle completed network work into its draft even while writes are
			// forbidden. mutate refuses persistence; Enter retries after recovery.
			return m.updateSettings(msg)
		}
	}
	if key, ok := msg.(tea.KeyMsg); ok {
		// Read-only overlays remain usable during sync and the recovery barrier.
		if m.help || m.errorOpen || m.detailID != "" || key.String() == "ctrl+e" {
			return m.dispatchUnlocked(msg)
		}
		if key.String() == "ctrl+c" {
			m.cancelWork()
			return m.dispatchUnlocked(msg)
		}
		if key.String() == "ctrl+z" {
			return m.dispatchUnlocked(msg)
		}
		if m.persistenceErr != nil {
			if key.Type == tea.KeyCtrlR {
				return m, m.recoverCmd()
			}
			if key.String() == "q" && m.screen == scrList {
				m.cancelWork()
				return m.dispatchUnlocked(msg)
			}
			m.setStatus(statusErr, "local write failed; drafts retained — ctrl+r recovers storage, then retry: "+m.persistenceErr.Error())
			return m, nil
		}
		if m.recovering {
			return m, nil
		}
		if m.syncing {
			if key.String() == "s" && (m.screen == scrList || m.screen == scrSettings && m.settings.step == sMenu) {
				return m, m.syncCmd("manual sync")
			}
			if key.String() == "q" && m.screen == scrList {
				m.cancelWork()
				return m.dispatchUnlocked(msg)
			}
			m.setStatus(statusWarn, "sync in progress — actions paused; draft retained")
			return m, nil
		}
	}
	needsLock := false
	switch msg.(type) {
	case tea.KeyMsg, testDoneMsg, scopedPreflightMsg, preflightMsg, sessionDoneMsg, scriptDoneMsg, tokenCheckedMsg, repoCreatedMsg, fidoUnlockMsg:
		needsLock = m.vault != nil
	}
	if !needsLock {
		return m.dispatchUnlocked(msg)
	}
	if m.persistenceErr != nil {
		return m, nil
	}
	if m.syncing || m.recovering {
		return m, tea.Tick(50*time.Millisecond, func(time.Time) tea.Msg { return msg })
	}
	l, err := fstxn.TryAcquire(m.cfgDir)
	if err != nil {
		m.setStatus(statusWarn, err.Error()+" — draft retained; retry action")
		if _, key := msg.(tea.KeyMsg); !key && errors.Is(err, fstxn.ErrBusy) {
			return m, tea.Tick(50*time.Millisecond, func(time.Time) tea.Msg { return msg })
		}
		return m, nil
	}
	defer l.Close()
	checks := []error{m.cfg.CheckCurrentLocked(l), m.store.CheckCurrentLocked(l), m.idents.CheckCurrentLocked(l), m.scripts.CheckCurrentLocked(l), m.vault.CheckCurrentLocked(l)}
	for _, err := range checks {
		if err == nil {
			continue
		}
		if errors.Is(err, fstxn.ErrStale) || errors.Is(err, vault.ErrStale) {
			s, loadErr := loadDiskLocked(l)
			if loadErr != nil {
				m.setStatus(statusErr, loadErr.Error())
				return m, nil
			}
			if m.wizard != nil && m.wizard.editing {
				m.staleWizard = m.wizard
			}
			if m.scriptsUI != nil && m.scriptsUI.editID != "" {
				m.staleScript = m.scriptsUI
			}
			m.applyDisk(s)
			m.syncState.Dirty = true
			m.setStatus(statusWarn, "files changed in another process — reloaded; draft retained, reopen existing edits before saving")
			switch result := msg.(type) {
			case scopedPreflightMsg:
				// A reload invalidates captured credentials as well as endpoints.
				// Require a fresh connect; don't strand or replay the old pending job.
				if m.pending == result.pending {
					m.cancelPending()
				}
			case preflightMsg:
				if m.pending != nil && m.pending.p.ID == result.profileID {
					m.cancelPending()
				}
			case testDoneMsg:
				if result.wizard == nil && (result.job == nil || m.sshTests[result.profileID] == result.job) {
					delete(m.testing, result.profileID)
					delete(m.sshTests, result.profileID)
					if result.job != nil {
						result.job.cancel()
					}
				}
				if result.job != nil && result.wizard != nil && m.wizard == result.wizard && m.wizard.testJob == result.job {
					result.job.cancel()
					m.wizard.awaitingTest = false
					m.wizard.errs = "files changed during the test — test again"
				}
			case sessionDoneMsg:
				m.monitor.Suspend(result.profileID, false)
			case scriptDoneMsg:
				m.monitor.Suspend(result.profileID, false)
			case tokenCheckedMsg, repoCreatedMsg, fidoUnlockMsg:
				return m, tea.Tick(time.Millisecond, func(time.Time) tea.Msg { return msg })
			}
			return m, nil
		}
		m.setStatus(statusErr, err.Error())
		return m, nil
	}
	m.uiLock = l
	defer func() { m.uiLock = nil }()
	return m.dispatchUnlocked(msg)
}

func (m *Model) cancelWork() {
	m.cancelPending()
	if m.workCancel != nil {
		m.workCancel()
	}
}

// Shutdown waits for started Git workers to abort/release ownership. Commands
// which Bubble Tea hasn't started yet are canceled without waiting for a start.
type workGroup struct {
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func (w *workGroup) start() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	w.wg.Add(1)
	return true
}
func (w *workGroup) closeAndWait() { w.mu.Lock(); w.closed = true; w.mu.Unlock(); w.wg.Wait() }
func (m *Model) background(run tea.Cmd, canceled tea.Msg) tea.Cmd {
	if m.workers == nil {
		m.workers = &workGroup{}
	}
	w := m.workers
	return func() tea.Msg {
		if !w.start() {
			return canceled
		}
		defer w.wg.Done()
		return run()
	}
}

func (m *Model) finishSync(msg syncDoneMsg) (tea.Model, tea.Cmd) {
	m.syncing = false
	if msg.state != nil {
		m.applyDisk(msg.state)
	}
	m.syncState.Destination = msg.destination
	if msg.err != nil {
		m.syncState.Error = msg.err.Error()
		m.syncState.Dirty = true
		m.setStatus(statusErr, "sync failed: "+truncErr(msg.err))
	} else {
		m.syncState.Error = ""
		m.syncState.Dirty = false
		m.syncState.LastSuccess = time.Now()
		m.setStatus(statusOK, "synced to "+msg.destination)
	}
	if m.syncPending {
		m.syncPending = false
		return m, m.syncCmd("clavis: deferred sync")
	}
	return m, nil
}

func (m *Model) syncCmd(message string) tea.Cmd {
	if m.recovering {
		m.setStatus(statusWarn, "storage recovery in progress — retry sync afterward")
		return nil
	}
	if m.syncing {
		m.syncPending = true
		return nil
	}
	if m.persistenceErr != nil {
		m.setStatus(statusErr, "sync paused after failed local persistence; retain your edits and recover/reload first: "+m.persistenceErr.Error())
		return nil
	}
	if m.cfg.Sync.Remote == "" {
		m.setStatus(statusWarn, "sync not configured — press g for settings")
		return nil
	}
	m.syncing = true
	dir, remote := m.cfgDir, m.cfg.Sync.Remote
	cfgSnapshot := *m.cfg
	identity := ""
	if m.vault != nil {
		identity, _ = m.vault.Identity()
	}
	ctx := m.workContext
	if ctx == nil {
		ctx = context.Background()
	}
	return m.background(func() tea.Msg {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		result := syncDoneMsg{} // report only a destination actually resolved by Git
		l, err := fstxn.AcquireContext(ctx, dir)
		if err != nil {
			result.err = err
			return result
		}
		defer l.Close()
		// Read credentials only after ownership, from a detached vault; never capture
		// a mutable model/store/vault in a background command.
		err = cfgSnapshot.CheckCurrentLocked(l)
		var v *vault.Vault
		if err == nil {
			v, err = vault.LoadLocked(l)
		}
		token := ""
		if err == nil && (len(remote) >= 8 && remote[:8] == "https://" || len(remote) >= 7 && remote[:7] == "http://") {
			err = v.Unlock(identity)
			if err == nil {
				var b []byte
				b, err = v.GetLocked(l, "github-token", true)
				token = string(b)
			}
		}
		c := gitsync.New(dir, token)
		c.Context = ctx
		if err == nil {
			err = c.SyncLocked(l, remote, message)
			if actual := c.DestinationURL(); actual != "" {
				result.destination = actual
			}
		}
		result.state, result.err = loadDiskLocked(l)
		result.err = errors.Join(err, result.err)
		return result
	}, syncDoneMsg{err: context.Canceled})
}

// Legacy whole-store save supports existing integration callers. Interactive
// CRUD uses mutate instead, so failures never publish a partially edited store.
func (m *Model) saveProfiles() error {
	if m.persistenceErr != nil {
		return m.persistenceErr
	}
	if m.uiLock != nil {
		return m.noteWrite(m.store.SaveLocked(m.uiLock))
	}
	return m.noteWrite(m.store.Save())
}
func (m *Model) noteWrite(err error) error {
	if err != nil {
		m.persistenceErr = err
		m.syncState.Error = err.Error()
		m.cancelPending()
		for id, job := range m.sshTests {
			job.cancel()
			delete(m.sshTests, id)
		}
		clear(m.testing)
		if w := m.wizard; w != nil && w.awaitingTest {
			if w.testJob != nil {
				w.testJob.cancel()
			}
			w.awaitingTest = false
			w.errs = "test canceled after a storage error — recover and retry"
		}
	}
	m.syncState.Dirty = true
	return err
}
func (m *Model) getSecret(name string, local bool) ([]byte, error) {
	if m.uiLock != nil {
		return m.vault.GetLocked(m.uiLock, name, local)
	}
	if local {
		return m.vault.GetLocal(name)
	}
	return m.vault.Get(name)
}
func (m *Model) hasSecret(name string, local bool) bool {
	if m.uiLock != nil {
		return m.vault.HasLocked(m.uiLock, name, local) == nil
	}
	if local {
		return m.vault.HasLocal(name)
	}
	return m.vault.Has(name)
}
func (m *Model) putSecret(name string, b []byte, local bool) error {
	return m.mutate(func(s *diskState, l *fstxn.Lock) ([]fstxn.Change, error) {
		c, err := s.vault.SecretChangeLocked(l, name, b, local)
		return []fstxn.Change{c}, err
	})
}
func (m *Model) verifyVault() error {
	if m.uiLock != nil {
		return m.vault.VerifyAllLocked(m.uiLock)
	}
	return m.vault.VerifyAll()
}
func (m *Model) removeFIDO() error {
	if m.uiLock != nil {
		return fido2.RemoveLocked(m.uiLock)
	}
	return fido2.Remove(m.cfgDir)
}

func (m *Model) githubToken() (string, error) {
	if !m.vault.Unlocked() {
		return "", fmt.Errorf("vault is locked; token unavailable")
	}
	b, err := m.getSecret("github-token", true)
	if err != nil {
		return "", fmt.Errorf("GitHub token unavailable — press g for settings: %w", err)
	}
	return string(b), nil
}

// A callback deferred behind sync must not attach trust to a replacement target.
// Job identities add cancellation/origin checks on test and preflight callbacks.
func (m *Model) currentEndpoint(id string, observed profile.Profile) bool {
	p := m.store.ByID(id)
	return p != nil && observed.Host != "" && p.Host == observed.Host && p.Port == observed.Port && p.ProxyJump == observed.ProxyJump
}

// Draft credential versions cover secret-only changes (metadata and recipient
// can stay identical). A stale editor retains its buffers and must be reopened.
func (m *Model) secretSnapshot(names ...string) (map[string]fstxn.Revision, error) {
	l := m.uiLock
	if l == nil {
		var err error
		l, err = fstxn.Acquire(m.cfgDir)
		if err != nil {
			return nil, err
		}
		defer l.Close()
	}
	versions := map[string]fstxn.Revision{}
	for _, name := range names {
		change, err := vault.DeleteChange(name, false)
		if err != nil {
			return nil, err
		}
		raw, err := l.ReadFile(change.Path)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		versions[change.Path] = fstxn.RevisionOf(raw)
	}
	return versions, nil
}

// Mutation entry points also support direct calls: acquire once, without waiting,
// and retain ownership through both precondition checks and every nested write.
func (m *Model) mutationLock() (func(), error) {
	if m.uiLock != nil {
		return func() {}, nil
	}
	l, err := fstxn.TryAcquire(m.cfgDir)
	if err != nil {
		return nil, err
	}
	m.uiLock = l
	return func() { m.uiLock = nil; l.Close() }, nil
}

func (w *wizardModel) canSave(m *Model) bool {
	if m.staleWizard == w {
		w.errs = "draft predates disk changes — retain your input and reopen the edit before saving"
		return false
	}
	if m.syncing {
		w.errs = "sync in progress — draft retained"
		return false
	}
	if m.persistenceErr != nil {
		w.errs = m.persistenceErr.Error()
		return false
	}
	if w.secretSnapshotErr != nil {
		w.errs = w.secretSnapshotErr.Error()
		return false
	}
	l := m.uiLock
	if l == nil {
		var err error
		l, err = fstxn.TryAcquire(m.cfgDir)
		if err != nil {
			w.errs = err.Error()
			return false
		}
		defer l.Close()
	}
	checks := []error{m.store.CheckCurrentLocked(l), m.idents.CheckCurrentLocked(l), m.vault.CheckCurrentLocked(l)}
	if w.metadataCheck != nil {
		checks = append(checks, w.metadataCheck(l))
	}
	for _, err := range checks {
		if err != nil {
			w.errs = "draft predates disk changes — retain your input and reopen the edit: " + err.Error()
			return false
		}
	}
	for path, version := range w.secretRevisions {
		if err := version.Check(l, path); err != nil {
			w.errs = "credentials changed on disk — retain your input and reopen the edit: " + err.Error()
			return false
		}
	}
	return true
}
