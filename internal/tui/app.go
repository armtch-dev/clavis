// Package tui is the clavis terminal UI: profile list with live reachability,
// step-by-step profile wizard, vault unlock, and sync settings — all in the
// Night Owl palette shared with scriptorium.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/fido2"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/probe"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/theme"
	"github.com/armtch-dev/clavis/internal/vault"
)

type screen int

const (
	scrList    screen = iota
	scrWelcome        // first run: choose new vault vs restore from git
	scrUnlock
	scrFirstRun // key banner after vault init (also after rekey/reset from UI)
	scrWizard
	scrConfirmDelete
	scrSettings
	scrScripts    // pick/edit a script to run on the selected host
	scrIdentities // manage reusable identities
)

const (
	// 15s keeps the dashboard fresh while staying well under the per-source
	// connection-rate limits some gateways enforce on SSH (see probe.backoff).
	probeInterval    = 15 * time.Second
	probeTimeout     = 3 * time.Second
	testTimeout      = 8 * time.Second
	preflightTimeout = 5 * time.Second

	statusTTL    = 5 * time.Second  // info/ok/warn messages fade after this
	statusErrTTL = 10 * time.Second // errors linger a little longer
)

type statusKind int

const (
	statusInfo statusKind = iota
	statusOK
	statusWarn
	statusErr
)

// Model is the root bubbletea model.
type Model struct {
	cfgDir  string
	cfg     *config.Config
	store   *profile.Store
	idents  *profile.IdentityStore
	scripts *script.Store
	vault   *vault.Vault

	screen      screen
	help        bool
	panelScroll int
	detailID    string
	errorOpen   bool
	errorDetail string
	lastError   string
	width       int
	height      int
	quiting     bool

	// list state
	cursor      int
	selectedID  string // action identity; cursor is derived after ordering changes
	filter      string
	filtering   bool
	catTarget   string // profile ID being re-categorized with "c", "" when idle
	catInput    string
	sortMode    sortMode        // toggled with "o": in-group order (stored/latency)
	testing     map[string]bool // profile IDs with an in-flight test
	sshTests    map[string]*networkJob
	authResults map[string]testDoneMsg

	// connect preflight: the profile being reachability-checked before the
	// terminal is handed to ssh, so a dead host fails inside the TUI instead
	// of dumping the user onto a suspended screen.
	connecting string // profile ID, "" when idle
	pending    *pendingConnect

	// probe plumbing
	probeOverflow        atomic.Bool
	monitor              *probe.Monitor
	probeCh              chan probe.Status
	statuses             map[string]probe.Status
	listCache            visibleCache
	credentialState      map[string]string
	credentialGeneration int
	credentialRefresh    bool

	// sub-screens
	welcome     *welcomeModel
	unlock      unlockModel
	firstRun    keyBannerModel
	wizard      *wizardModel
	confirm     confirmModel
	settings    *settingsModel
	scriptsUI   *scriptsModel
	scriptDraft *scriptsModel // one recoverable in-memory draft, retaining its original target
	identsUI    *identsModel
	trust       *trustReview
	mismatches  map[string]testDoneMsg

	statusMsg       string
	statusType      statusKind
	statusSeq       int // generation counter, bumped by setStatus
	statusSched     int // generation an expiry tick has been scheduled for
	syncing         bool
	syncPending     bool
	syncState       SyncState
	uiLock          *fstxn.Lock
	workContext     context.Context
	workCancel      context.CancelFunc
	resumeScreen    screen
	staleWizard     *wizardModel
	staleScript     *scriptsModel
	persistenceErr  error // don't reload over edits after an uncertain/failed write
	workers         *workGroup
	recovering      bool
	settingsRefresh bool
	hardware        *hardwareRequest

	spin     spinner.Model
	spinning bool // a spinner tick is in flight
}

// New builds the root model. v is nil on first run (no vault.meta yet); the
// welcome screen then decides between minting a vault and restoring from git.
func New(cfgDir string, cfg *config.Config, store *profile.Store, idents *profile.IdentityStore, scripts *script.Store, v *vault.Vault) *Model {
	m := &Model{
		cfgDir:   cfgDir,
		cfg:      cfg,
		store:    store,
		idents:   idents,
		scripts:  scripts,
		vault:    v,
		testing:  map[string]bool{},
		statuses: map[string]probe.Status{},
		probeCh:  make(chan probe.Status, 64),
		spin:     spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(theme.Accent)),
	}
	m.monitor = probe.New(probeInterval, probeTimeout, func(s probe.Status) {
		select {
		case m.probeCh <- s:
		default: // A batch reconciles a monitor snapshot if callbacks overflow.
			m.probeOverflow.Store(true)
		}
	})
	// Also own shutdown while Bubble Tea has released the terminal for Exec.
	m.workContext, m.workCancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	m.workers = &workGroup{}
	m.syncTargets()

	switch {
	case v == nil:
		m.welcome = &welcomeModel{}
		m.screen = scrWelcome
	case !v.Unlocked():
		if id, src := vault.ResolveIdentity(); id != "" {
			if err := v.Unlock(id); err == nil {
				m.setStatus(statusOK, "vault unlocked via "+src)
				m.screen = scrList
				break
			}
		}
		m.unlock = newUnlock(v, cfgDir)
		// Launch parity with the Keychain path: security key enrolled and
		// plugged in → the assertion starts by itself (Init issues it), and
		// the unlock screen shows the touch prompt.
		m.unlock.fidoBusy = m.unlock.fido && fido2.Present()
		m.screen = scrUnlock
	default:
		m.screen = scrList
	}
	return m
}

func (m *Model) syncTargets() {
	m.listCache.valid = false
	m.credentialGeneration++
	m.credentialRefresh = true
	m.credentialState = nil
	m.authResults = nil
	targets := make([]probe.Target, 0, len(m.store.Profiles))
	for _, p := range m.store.Profiles {
		if p.ProxyJump != "" {
			continue // only reachable via the jump: a direct TCP probe would show a false "down"
		}
		targets = append(targets, probe.Target{ProfileID: p.ID, Addr: p.Addr()})
	}
	m.monitor.SetTargets(targets)
	for id, s := range m.statuses {
		if !m.monitor.Current(s) {
			delete(m.statuses, id)
		}
	}
	m.cancelObsoleteNetwork()
}

// setStatus records a status message and bumps its generation; the expiry
// tick is scheduled centrally in Update, so call sites stay command-free.
func (m *Model) setStatus(k statusKind, msg string) {
	m.statusType, m.statusMsg = k, msg
	if k == statusErr {
		m.lastError = msg
	}
	m.statusSeq++
}

// spinnerActive reports whether any in-flight work warrants animation.
func (m *Model) spinnerActive() bool {
	return m.syncing || m.recovering || m.hardware != nil || len(m.testing) > 0 || m.connecting != "" ||
		(m.wizard != nil && m.wizard.awaitingTest) ||
		(m.welcome != nil && m.welcome.busy) ||
		(m.settings != nil && m.settings.busy != "") ||
		m.unlock.fidoBusy
}

// --- messages ---

type probeMsg probe.Status
type probeBatchMsg []probe.Status

type testDoneMsg struct {
	profileID string
	result    sshx.TestResult
	endpoint  profile.Profile // target captured before any sync reload
	job       *networkJob
	wizard    *wizardModel
}

type syncDoneMsg struct {
	err         error
	state       *diskState
	destination string
}

// statusExpireMsg fades a status message; seq guards against clearing a
// message newer than the one the tick was scheduled for.
type statusExpireMsg struct{ seq int }

type sessionDoneMsg struct {
	profileID   string
	hostKeyFP   string
	hostKeyLine string
	err         error
	detail      string // last stderr line from ssh, if any — the human reason
	endpoint    profile.Profile
}

// pendingConnect stashes the profile and decrypted credentials between the
// preflight starting and the terminal handover, so they aren't re-derived.
// A non-nil script turns the handover into a script run instead of a shell.
type pendingConnect struct {
	p      profile.Profile
	creds  sshx.Credentials
	script *runScript
	job    *networkJob
}

type preflightMsg struct {
	profileID string
	err       error
}

func waitForProbe(ctx context.Context, ch chan probe.Status) tea.Cmd {
	return func() tea.Msg {
		select {
		case s := <-ch:
			batch := probeBatchMsg{s}
			timer := time.NewTimer(16 * time.Millisecond)
			defer timer.Stop()
			for {
				select {
				case s := <-ch:
					batch = append(batch, s)
				case <-timer.C:
					return batch
				case <-ctx.Done():
					return tea.Quit()
				}
			}
		case <-ctx.Done():
			return tea.Quit()
		}
	}
}

func (m *Model) Init() tea.Cmd {
	if m.screen == scrUnlock && m.unlock.fidoBusy {
		return tea.Batch(waitForProbe(m.networkContext(), m.probeCh), m.fidoUnlockCmd())
	}
	return waitForProbe(m.networkContext(), m.probeCh)
}

// --- update ---

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case statusExpireMsg:
		if msg.seq == m.statusSeq && !m.syncing && m.statusType != statusErr {
			m.statusMsg = ""
		}
		return m, nil
	case spinner.TickMsg:
		if !m.spinnerActive() {
			m.spinning = false // stop the loop; restarted centrally below
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	}
	model, cmd := m.dispatch(msg)
	return model, m.housekeeping(cmd)
}

// housekeeping appends the centrally driven commands — status expiry and
// spinner ticks — to whatever a dispatch produced, so the ~20 setStatus call
// sites and every syncing/testing toggle stay command-free.
func (m *Model) housekeeping(cmd tea.Cmd) tea.Cmd {
	m.resizeEditors()
	if detail := m.errorText(); detail != "" {
		m.lastError = detail
	}
	cmds := []tea.Cmd{cmd}
	if m.settingsRefresh && m.settings != nil {
		cmds = append(cmds, m.localSnapshotCmd(m.settings))
	}
	if m.credentialRefresh && m.vault != nil {
		m.credentialRefresh = false
		cmds = append(cmds, m.credentialSnapshotCmd())
	}
	if m.statusMsg != "" && m.statusType != statusErr && m.statusSched != m.statusSeq {
		m.statusSched = m.statusSeq // exactly one tick per message
		seq := m.statusSeq
		ttl := statusTTL
		if m.statusType == statusErr {
			ttl = statusErrTTL
		}
		cmds = append(cmds, tea.Tick(ttl, func(time.Time) tea.Msg { return statusExpireMsg{seq} }))
	}
	if m.spinnerActive() && !m.spinning {
		m.spinning = true
		cmds = append(cmds, m.spin.Tick)
	}
	if len(cmds) == 1 {
		return cmd
	}
	return tea.Batch(cmds...)
}

// dispatch is the pre-housekeeping message handling: global messages first,
// then whatever screen is active.
func (m *Model) dispatchUnlocked(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resizeEditors()
		return m, nil
	case credentialSnapshotMsg:
		if msg.generation == m.credentialGeneration {
			m.credentialState = msg.states
		}
		return m, nil
	case localSnapshotMsg, hardwareDoneMsg:
		return m.updateLocalState(msg)
	case restoreOfferMsg:
		return m.updateWelcome(msg)
	case copiedMsg:
		if msg.err != nil {
			m.setStatus(statusErr, "clipboard: "+msg.err.Error())
		} else {
			if msg.banner != "" && m.firstRun.identity == msg.banner {
				m.firstRun.copied = true
			}
			m.setStatus(statusOK, "copied")
		}
		return m, nil
	case probeBatchMsg:
		for _, s := range msg {
			if m.monitor.Current(s) {
				m.statuses[s.ProfileID] = s
			}
		}
		if m.probeOverflow.Swap(false) {
			for id, s := range m.monitor.Snapshot() {
				if m.monitor.Current(s) {
					m.statuses[id] = s
				}
			}
		}
		m.listCache.groups = nil
		if m.sortMode == sortLatency {
			m.listCache.valid = false
			m.clampCursor()
		}
		return m, waitForProbe(m.networkContext(), m.probeCh)

	case probeMsg:
		if m.monitor.Current(probe.Status(msg)) {
			m.statuses[msg.ProfileID] = probe.Status(msg)
			m.listCache.groups = nil
			if m.sortMode == sortLatency {
				m.listCache.valid = false
				m.clampCursor()
			}
		}
		return m, waitForProbe(m.networkContext(), m.probeCh)

	case testDoneMsg:
		if msg.job != nil {
			if msg.job.ctx.Err() != nil {
				return m, nil
			}
			defer msg.job.cancel()
			if msg.wizard != nil {
				if m.wizard != msg.wizard || m.wizard.testJob != msg.job {
					return m, nil
				}
				if !sameTestTarget(m.effective(m.wizard.draft), msg.endpoint) {
					m.wizard.awaitingTest = false
					m.wizard.errs = "draft changed during test — test again"
					return m, nil
				}
				endpoint := msg.endpoint
				m.wizard.testEndpoint = &endpoint
				m.wizard.testResult, m.wizard.awaitingTest = &msg.result, false
				return m, nil
			}
			if m.sshTests[msg.profileID] != msg.job {
				return m, nil
			}
			delete(m.sshTests, msg.profileID)
		}
		delete(m.testing, msg.profileID)
		if p := m.store.ByID(msg.profileID); p != nil && sameTestTarget(m.effective(*p), msg.endpoint) {
			if m.mismatches == nil {
				m.mismatches = map[string]testDoneMsg{}
			}
			delete(m.mismatches, msg.profileID)
			if msg.result.Stage == sshx.StageHostKey {
				m.mismatches[msg.profileID] = msg
			}
			m.applyTestResult(msg.profileID, msg.result)
			if m.authResults == nil {
				m.authResults = map[string]testDoneMsg{}
			}
			if current := m.store.ByID(msg.profileID); current != nil {
				msg.endpoint = m.effective(*current)
				m.authResults[msg.profileID] = msg
			}
		}
		return m, nil

	case syncDoneMsg:
		return m.finishSync(msg)
	case tokenCheckedMsg, repoCreatedMsg:
		return m.updateSettings(msg)

	case scopedPreflightMsg:
		if m.pending != msg.pending || msg.pending.job.ctx.Err() != nil {
			return m, nil
		}
		return m.applyPreflight(msg.preflightMsg)
	case preflightMsg:
		return m.applyPreflight(msg)

	case scriptDoneMsg:
		m.monitor.Suspend(msg.profileID, false)
		if msg.ok && m.networkContext().Err() == nil && m.currentEndpoint(msg.profileID, msg.endpoint) {
			if err := m.pinHostKey(msg.profileID, msg.hostKeyFP, msg.hostKeyLine); err != nil {
				m.setStatus(statusErr, "host key save failed: "+err.Error())
				return m, nil
			}
		}
		if msg.ok {
			m.setStatus(statusOK, msg.summary)
		} else {
			m.setStatus(statusErr, msg.summary)
		}
		return m, nil

	case sessionDoneMsg:
		m.monitor.Suspend(msg.profileID, false)
		if msg.err == nil && m.networkContext().Err() == nil && m.currentEndpoint(msg.profileID, msg.endpoint) {
			if err := m.pinHostKey(msg.profileID, msg.hostKeyFP, msg.hostKeyLine); err != nil {
				m.setStatus(statusErr, "host key save failed: "+err.Error())
				return m, nil
			}
		}
		if msg.err != nil {
			reason := truncErr(msg.err)
			if msg.detail != "" {
				reason = msg.detail
			}
			m.setStatus(statusErr, "session ended: "+reason)
		} else {
			m.setStatus(statusInfo, "session closed")
		}
		return m, nil

	case tea.KeyMsg:
		if msg.Type == tea.KeyEsc && m.pending != nil {
			m.cancelPending()
			m.setStatus(statusInfo, "connection canceled")
		}
		// Terminal citizenship, on every screen: ctrl+c always quits cleanly,
		// ctrl+z always suspends — no screen may shadow either.
		switch msg.String() {
		case "ctrl+c":
			m.quiting = true
			m.monitor.Stop()
			return m, tea.Quit
		case "ctrl+z":
			return m, tea.Suspend
		}
		if m.help || m.detailID != "" || m.errorOpen {
			switch msg.String() {
			case "pgdown", "down", "j":
				m.panelScroll += max(1, m.height/2)
			case "pgup", "up", "k":
				m.panelScroll = max(0, m.panelScroll-max(1, m.height/2))
			case "c":
				if m.errorOpen {
					return m, copyText(m.errorDetail)
				}
				if p := m.store.ByID(m.detailID); p != nil {
					p := m.effective(*p)
					return m, copyText(p.User + "@" + p.Addr())
				}
			case "f":
				if p := m.store.ByID(m.detailID); p != nil {
					fp, err := sshx.HostKeyFingerprint(*p)
					if err != nil {
						m.setStatus(statusErr, err.Error())
					} else {
						return m, copyText(fp)
					}
				}
			case "esc", "?", "v", "ctrl+e":
				m.help, m.errorOpen, m.detailID, m.panelScroll = false, false, "", 0
			case "d":
				if m.errorOpen {
					m.lastError, m.statusMsg, m.errorDetail, m.errorOpen = "", "", "", false
					switch m.screen {
					case scrWizard:
						m.wizard.errs = ""
					case scrScripts:
						m.scriptsUI.errs = ""
					case scrSettings:
						m.settings.errs = ""
					case scrUnlock:
						m.unlock.errs = ""
					case scrWelcome:
						m.welcome.errs = ""
					}
				}
			}
			return m, nil
		}
		if msg.String() == "ctrl+e" {
			m.errorDetail = m.errorText()
			m.errorOpen = true
			m.panelScroll = 0
			return m, nil
		}
		if m.trust != nil {
			return m.updateTrust(msg)
		}
		if m.screen != scrList {
			switch msg.String() {
			case "pgdown":
				m.panelScroll += max(1, m.height/2)
				return m, nil
			case "pgup":
				m.panelScroll = max(0, m.panelScroll-max(1, m.height/2))
				return m, nil
			default:
				m.panelScroll = 0
			}
		}
	}

	switch m.screen {
	case scrWelcome:
		return m.updateWelcome(msg)
	case scrUnlock:
		return m.updateUnlock(msg)
	case scrFirstRun:
		return m.updateFirstRun(msg)
	case scrWizard:
		return m.updateWizard(msg)
	case scrConfirmDelete:
		return m.updateConfirm(msg)
	case scrSettings:
		return m.updateSettings(msg)
	case scrScripts:
		return m.updateScripts(msg)
	case scrIdentities:
		return m.updateIdentities(msg)
	default:
		return m.updateList(msg)
	}
}

func (m *Model) applyTestResult(profileID string, r sshx.TestResult) {
	p := m.store.ByID(profileID)
	if p == nil {
		return
	}
	if r.OK {
		if err := m.pinHostKey(profileID, r.HostKeyFP, r.HostKeyLine); err != nil {
			m.setStatus(statusErr, "host key save failed: "+err.Error())
			return
		}
		m.setStatus(statusOK, fmt.Sprintf("%s: %s (%.0f ms)", p.Name, r.Reason, float64(r.Latency.Milliseconds())))
		return
	}
	kind := statusErr
	if r.Stage == sshx.StageHostKey {
		m.setStatus(statusErr, fmt.Sprintf("%s: %s — h reviews old/new fingerprints", p.Name, r.Reason))
		return
	}
	m.setStatus(kind, fmt.Sprintf("%s [%s]: %s", p.Name, r.Stage, r.Reason))
}

// pinHostKey records the fingerprint + full key on first successful contact
// (TOFU). The full key line lets ExternalCommand hand ssh a strict
// known_hosts file, so the pin protects real sessions too.
func (m *Model) pinHostKey(profileID, fp, line string) error {
	if fp == "" {
		return nil
	}
	p := m.store.ByID(profileID)
	if p == nil {
		return nil
	}
	old, err := sshx.HostKeyFingerprint(*p)
	if err != nil {
		return err
	}
	if old != "" && old != fp {
		return sshx.ErrHostKeyChanged
	}
	if p.HostKeyFP != "" && p.HostKey != "" {
		return nil
	}
	if err := observedKey(fp, line); err != nil {
		return err
	}
	return m.mutate(func(s *diskState, l *fstxn.Lock) ([]fstxn.Change, error) {
		p := s.store.ByID(profileID)
		if p == nil {
			return nil, fmt.Errorf("profile no longer exists")
		}
		p.HostKeyFP, p.HostKey = fp, line
		c, err := s.store.Change()
		return []fstxn.Change{c}, err
	})
}

// --- commands ---

func (m *Model) testCmd(p profile.Profile) tea.Cmd {
	p = m.effective(p)
	creds, err := m.credsFor(&p)
	if err != nil {
		return func() tea.Msg {
			return testDoneMsg{profileID: p.ID, endpoint: p, result: sshx.TestResult{Stage: sshx.StageAuth, Err: err, Reason: err.Error()}}
		}
	}
	return m.runTest(p, creds, nil)
}

// effective returns a copy of p with identity-backed fields resolved: a
// profile bound to an identity takes its username and auth kinds from the
// identity, live — editing the identity updates every bound profile.
func (m *Model) effective(p profile.Profile) profile.Profile {
	if p.IdentityID == "" {
		return p
	}
	if id := m.idents.ByID(p.IdentityID); id != nil {
		p.User = id.User
		p.Auth = id.Auth
	}
	return p
}

func (m *Model) credsFor(p *profile.Profile) (sshx.Credentials, error) {
	var creds sshx.Credentials
	if !m.vault.Unlocked() {
		return creds, fmt.Errorf("vault is locked — press u to unlock")
	}
	// An identity-backed profile reads the identity's secrets; otherwise its own.
	pass, key, phrase := p.PassSecret(), p.KeySecret(), p.PassphraseSecret()
	hasPw, hasKey := p.HasAuth(profile.AuthPassword), p.HasAuth(profile.AuthKey)
	if p.IdentityID != "" {
		id := m.idents.ByID(p.IdentityID)
		if id == nil {
			return creds, fmt.Errorf("the identity for %s no longer exists — edit the profile", p.Name)
		}
		pass, key, phrase = id.PassSecret(), id.KeySecret(), id.PassphraseSecret()
		hasPw, hasKey = id.HasAuth(profile.AuthPassword), id.HasAuth(profile.AuthKey)
	}
	if hasPw {
		b, err := m.getSecret(pass, false)
		if err != nil {
			return creds, fmt.Errorf("password missing from vault: %w", err)
		}
		creds.Password = string(b)
	}
	if hasKey {
		b, err := m.getSecret(key, false)
		if err != nil {
			return creds, fmt.Errorf("ssh key missing from vault: %w", err)
		}
		creds.PrivateKey = b
		pp, err := m.optionalSecret(phrase)
		if err != nil {
			return creds, fmt.Errorf("key passphrase unavailable: %w", err)
		}
		creds.Passphrase = string(pp)
	}
	return creds, nil
}

func (m *Model) optionalSecret(name string) ([]byte, error) {
	b, err := m.getSecret(name, false)
	if errors.Is(err, vault.ErrNotFound) {
		return nil, nil
	}
	return b, err
}

// Identity-backed profiles resolve their effective user before any real
// connection: startConnect, testCmd, and startRunScript all go through
// m.effective so ssh authenticates as the identity's user.

// startConnect kicks off a connect: credentials are resolved and the host is
// preflighted asynchronously while the TUI keeps running (spinner in the
// status bar). Only when the host actually answers does the terminal get
// handed to ssh — so a dead, slow, or rate-limited host is a status-bar
// message, not a long suspension of the UI. Probing is paused for the host
// for the duration so the probe and the session don't burst connections
// together (some gateways rate-limit new SSH connections per source).
func (m *Model) startConnect(p profile.Profile) tea.Cmd {
	p = m.effective(p)
	creds, err := m.credsFor(&p)
	if err != nil {
		m.setStatus(statusErr, err.Error())
		return nil
	}
	m.cancelPending()
	m.connecting = p.ID
	m.pending = &pendingConnect{p: p, creds: creds}
	m.monitor.Suspend(p.ID, true)
	m.setStatus(statusInfo, "connecting to "+p.Name+"…")
	// A jump-only host is unreachable directly — preflighting the target
	// would block the connect forever. ssh does the jump itself, and its
	// ConnectTimeout covers the stall case.
	return m.preflightCmd(m.pending)
}

// applyPreflight either surfaces the failure (staying in the TUI) or hands
// the terminal over to the real session.
func (m *Model) applyPreflight(msg preflightMsg) (tea.Model, tea.Cmd) {
	if m.pending == nil || m.connecting != msg.profileID {
		return m, nil // stale — profile deleted or connect superseded
	}
	pc := *m.pending
	if !m.currentEndpoint(pc.p.ID, pc.p) || m.networkContext().Err() != nil {
		m.cancelPending()
		return m, nil
	}
	if pc.job != nil {
		pc.job.cancel()
	}
	m.connecting, m.pending = "", nil
	if msg.err != nil {
		m.monitor.Suspend(pc.p.ID, false)
		m.setStatus(statusErr, pc.p.Name+": "+msg.err.Error())
		return m, nil
	}
	m.statusMsg = "" // clear "connecting…" before the handover
	return m, m.handoverCmd(pc)
}

// handoverCmd gives the terminal to a real SSH session; probing for the host
// stays suspended until sessionDoneMsg (or scriptDoneMsg for script runs).
func (m *Model) handoverCmd(pc pendingConnect) tea.Cmd {
	if pc.script != nil {
		return m.scriptSessionCmd(pc)
	}
	p := pc.p
	if p.ProxyJump != "" {
		cmd, tail, cleanup, err := sshx.ExternalKeyCommandContext(m.networkContext(), p, pc.creds)
		if err != nil {
			m.monitor.Suspend(p.ID, false)
			m.setStatus(statusErr, err.Error())
			return nil
		}
		return tea.ExecProcess(cmd, func(err error) tea.Msg {
			var fp, line string
			if err == nil {
				fp, line, err = sshx.ExternalHostKey(cmd)
			}
			cleanup()
			detail := ""
			if err != nil {
				detail = tail.LastLine()
			}
			return sessionDoneMsg{profileID: p.ID, hostKeyFP: fp, hostKeyLine: line, err: err, detail: detail, endpoint: p}
		})
	}
	// Direct sessions share full key/passphrase/password authentication.
	sess := &passwordSession{p: p, creds: pc.creds, ctx: m.networkContext()}
	return tea.Exec(sess, func(err error) tea.Msg {
		return sessionDoneMsg{profileID: p.ID, hostKeyFP: sess.fp, hostKeyLine: sess.keyLine, err: err, endpoint: p}
	})
}

// passwordSession adapts sshx.RunPasswordSession to tea.ExecCommand.
type passwordSession struct {
	p       profile.Profile
	creds   sshx.Credentials
	ctx     context.Context
	fp      string
	keyLine string
}

func (s *passwordSession) Run() error {
	fp, line, err := sshx.RunSessionContext(s.ctx, s.p, s.creds, preflightTimeout*2)
	s.fp, s.keyLine = fp, line
	s.creds = sshx.Credentials{} // shrink the plaintext window once the session ends
	return err
}

// The session talks to the real TTY directly; bubbletea's redirects are moot.
func (s *passwordSession) SetStdin(io.Reader)  {}
func (s *passwordSession) SetStdout(io.Writer) {}
func (s *passwordSession) SetStderr(io.Writer) {}

// saveAll persists profiles and, when autosync is on, fires a background sync.
func (m *Model) saveAll(what string) tea.Cmd {
	if m.syncing {
		m.setStatus(statusWarn, "sync in progress — save deferred; draft retained")
		return nil
	}
	if err := m.saveProfiles(); err != nil {
		m.setStatus(statusErr, "save failed: "+err.Error())
		return nil
	}
	m.syncState.Dirty = true
	m.syncTargets()
	if m.cfg.Sync.AutoSync && m.cfg.Sync.Remote != "" {
		return m.syncCmd("clavis: " + what)
	}
	return nil
}

func truncErr(err error) string {
	return err.Error() // retain the full reason; views budget cells, the error viewer wraps
}

// Close stops background work; called by main after the program exits.
func (m *Model) Close() {
	m.cancelWork()
	if m.workers != nil {
		m.workers.closeAndWait()
	}
	m.cancelPending()
	m.monitor.Stop()
}

// --- view ---

func (m *Model) View() string {
	if m.quiting {
		return ""
	}
	// Below the floor every row wraps and the frame tears — say so instead.
	if m.width > 0 && (m.width < 40 || m.height < 8) {
		return center(theme.Dim.Render("terminal too small — need 40×8"), m.width, m.height)
	}
	bodyH := max(m.height-m.footerHeight(), 1)
	var body string
	switch m.screen {
	case scrWelcome:
		body = m.welcome.view(m.spin.View(), m.width, bodyH, m.panelScroll)
	case scrUnlock:
		body = m.unlock.view(m.spin.View(), m.width, bodyH, m.panelScroll)
	case scrFirstRun:
		body = m.firstRun.view(m.width, bodyH, m.panelScroll)
	case scrWizard:
		body = m.wizard.view(m.width, bodyH)
	case scrConfirmDelete:
		body = m.confirm.view(m.width, bodyH, m.panelScroll)
	case scrSettings:
		body = m.settings.view(m.width, bodyH)
	case scrScripts:
		body = m.scriptsUI.view(m.width, bodyH)
	case scrIdentities:
		body = m.viewIdentities(m.width, bodyH)
	default:
		body = m.viewList()
	}
	if m.help {
		body = center(m.viewHelp(), m.width, bodyH)
	}
	if p := m.store.ByID(m.detailID); p != nil {
		body = panelView("Details · c target · f fingerprint · esc back\n"+m.detailText(*p), m.width, bodyH, 80, m.panelScroll)
	}
	if m.errorOpen {
		body = panelView("Error · c copy · d dismiss · esc back\n"+m.errorDetail, m.width, bodyH, 80, m.panelScroll)
	}
	if m.trust != nil {
		body = m.trust.view(m.width, bodyH)
	}
	// Pin the footer to the bottom of the terminal — and never let an
	// over-tall body push it past the last row: a frame taller than the
	// terminal scrolls the whole layout. Clip the body's tail instead.
	body = strings.TrimRight(body, "\n")
	if m.height > 0 {
		if h := lipgloss.Height(body); h < bodyH {
			body += strings.Repeat("\n", bodyH-h)
		} else if h > bodyH {
			lines := strings.Split(body, "\n")
			body = strings.Join(lines[:bodyH], "\n")
		}
	}
	return lipgloss.JoinVertical(lipgloss.Left, body, m.viewStatusBar())
}

// footerHeight mirrors viewStatusBar's line count so views can size themselves.
func (m *Model) footerHeight() int {
	if m.statusMsg != "" || m.syncing || (m.screen == scrList && !m.help) {
		return 2 // divider + the shared status/legend line
	}
	return 1
}

// viewStatusBar renders the footer: a hairline, then one shared line — the
// ephemeral status message while one is showing (it fades on its TTL), the
// key legend otherwise. One line of chrome, never a stack.
func (m *Model) viewStatusBar() string {
	width := max(m.width, 40)
	pad := strings.Repeat(" ", m.layoutList().pad)
	lines := []string{theme.Divider(width)}

	switch {
	case m.statusMsg != "" || m.syncing:
		style := theme.Dim
		switch m.statusType {
		case statusOK:
			style = theme.StatusOK
		case statusWarn:
			style = theme.StatusWarn
		case statusErr:
			style = theme.StatusErr
		}
		msg := m.statusMsg
		if m.statusType == statusErr {
			msg = "ctrl+e details · " + msg
		}
		if m.syncing {
			msg = m.spin.View() + " syncing… " + msg
			style = theme.Accent
		}
		lines = append(lines, pad+style.MaxWidth(width-len(pad)-1).Render(msg))
	case m.screen == scrList && !m.help:
		lines = append(lines, pad+m.legend(width-2*len(pad)))
	}
	return strings.Join(lines, "\n")
}

// legend renders the persistent key legend, dropping entries until it fits.
func (m *Model) legend(avail int) string {
	if m.filtering {
		return hintKeys([][2]string{{"enter", "apply"}, {"esc", "clear"}})
	}
	if m.catTarget != "" {
		return hintKeys([][2]string{{"enter", "set category"}, {"esc", "cancel"}})
	}
	tiers := [][][2]string{
		{{"enter", "connect"}, {"r", "run script"}, {"m", "scripts"}, {"a", "add"}, {"e", "edit"}, {"c", "category"}, {"d", "delete"}, {"t", "test"},
			{"y", "identities"}, {"s", "sync"}, {"g", "settings"}, {"i", "import"}, {"o", "sort"}, {"/", "filter"}, {"?", "help"}, {"q", "quit"}},
		{{"enter", "connect"}, {"r", "run"}, {"a", "add"}, {"e", "edit"}, {"d", "delete"}, {"/", "filter"}, {"?", "help"}, {"q", "quit"}},
		{{"v", "details"}, {"?", "help"}, {"q", "quit"}},
		{{"?", "help"}, {"q", "quit"}},
	}
	for _, t := range tiers {
		if s := hintKeys(t); lipgloss.Width(s) <= avail {
			return s
		}
	}
	return hintKeys(tiers[len(tiers)-1])
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
