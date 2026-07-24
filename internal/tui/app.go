// Package tui is the clavis terminal UI: profile list with live reachability,
// step-by-step profile wizard, vault unlock, and sync settings — all in the
// Night Owl palette shared with scriptorium.
package tui

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/probe"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/theme"
	"github.com/armtch-dev/clavis/internal/vault"
)

type screen int

const (
	scrList screen = iota
	scrUnlock
	scrFirstRun // key banner after vault init (also after rekey/reset from UI)
	scrWizard
	scrConfirmDelete
	scrSettings
	scrScripts // pick/edit a script to run on the selected host
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
	scripts *script.Store
	vault   *vault.Vault

	screen  screen
	help    bool
	width   int
	height  int
	quiting bool

	// list state
	cursor    int
	filter    string
	filtering bool
	sortMode  sortMode        // cycled with "o"
	testing   map[string]bool // profile IDs with an in-flight test

	// connect preflight: the profile being reachability-checked before the
	// terminal is handed to ssh, so a dead host fails inside the TUI instead
	// of dumping the user onto a suspended screen.
	connecting string // profile ID, "" when idle
	pending    *pendingConnect

	// probe plumbing
	monitor  *probe.Monitor
	probeCh  chan probe.Status
	statuses map[string]probe.Status

	// sub-screens
	unlock    unlockModel
	firstRun  keyBannerModel
	wizard    *wizardModel
	confirm   confirmModel
	settings  *settingsModel
	scriptsUI *scriptsModel

	statusMsg   string
	statusType  statusKind
	statusSeq   int // generation counter, bumped by setStatus
	statusSched int // generation an expiry tick has been scheduled for
	syncing     bool

	spin     spinner.Model
	spinning bool // a spinner tick is in flight
}

// New builds the root model. identity is non-empty only right after a
// first-run vault init (so the key banner can be shown once).
func New(cfgDir string, cfg *config.Config, store *profile.Store, scripts *script.Store, v *vault.Vault, freshIdentity string) *Model {
	m := &Model{
		cfgDir:   cfgDir,
		cfg:      cfg,
		store:    store,
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
		default: // UI briefly busy; drop rather than block a probe goroutine
		}
	})
	m.syncTargets()

	switch {
	case freshIdentity != "":
		m.firstRun = newKeyBanner(freshIdentity, cfg, cfgDir)
		m.screen = scrFirstRun
	case !v.Unlocked():
		if id, src := vault.ResolveIdentity(); id != "" {
			if err := v.Unlock(id); err == nil {
				m.setStatus(statusOK, "vault unlocked via "+src)
				m.screen = scrList
				break
			}
		}
		m.unlock = newUnlock(v)
		m.screen = scrUnlock
	default:
		m.screen = scrList
	}
	return m
}

func (m *Model) syncTargets() {
	targets := make([]probe.Target, 0, len(m.store.Profiles))
	for _, p := range m.store.Profiles {
		targets = append(targets, probe.Target{ProfileID: p.ID, Addr: p.Addr()})
	}
	m.monitor.SetTargets(targets)
}

// setStatus records a status message and bumps its generation; the expiry
// tick is scheduled centrally in Update, so call sites stay command-free.
func (m *Model) setStatus(k statusKind, msg string) {
	m.statusType, m.statusMsg = k, msg
	m.statusSeq++
}

// spinnerActive reports whether any in-flight work warrants animation.
func (m *Model) spinnerActive() bool {
	return m.syncing || len(m.testing) > 0 || m.connecting != "" || (m.wizard != nil && m.wizard.awaitingTest)
}

// --- messages ---

type probeMsg probe.Status

type testDoneMsg struct {
	profileID string
	result    sshx.TestResult
}

type syncDoneMsg struct{ err error }

// statusExpireMsg fades a status message; seq guards against clearing a
// message newer than the one the tick was scheduled for.
type statusExpireMsg struct{ seq int }

type sessionDoneMsg struct {
	profileID   string
	hostKeyFP   string
	hostKeyLine string
	err         error
	detail      string // last stderr line from ssh, if any — the human reason
}

// pendingConnect stashes the profile and decrypted credentials between the
// preflight starting and the terminal handover, so they aren't re-derived.
// A non-nil script turns the handover into a script run instead of a shell.
type pendingConnect struct {
	p      profile.Profile
	creds  sshx.Credentials
	script *runScript
}

type preflightMsg struct {
	profileID string
	err       error
}

func waitForProbe(ch chan probe.Status) tea.Cmd {
	return func() tea.Msg { return probeMsg(<-ch) }
}

func (m *Model) Init() tea.Cmd {
	return waitForProbe(m.probeCh)
}

// --- update ---

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case statusExpireMsg:
		if msg.seq == m.statusSeq && !m.syncing {
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
	cmds := []tea.Cmd{cmd}
	if m.statusMsg != "" && m.statusSched != m.statusSeq {
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
func (m *Model) dispatch(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case probeMsg:
		m.statuses[msg.ProfileID] = probe.Status(msg)
		return m, waitForProbe(m.probeCh)

	case testDoneMsg:
		delete(m.testing, msg.profileID)
		m.applyTestResult(msg.profileID, msg.result)
		if m.wizard != nil && m.wizard.awaitingTest && m.wizard.draft.ID == msg.profileID {
			m.wizard.testResult = &msg.result
			m.wizard.awaitingTest = false
		}
		return m, nil

	case syncDoneMsg:
		m.syncing = false
		if msg.err != nil {
			m.setStatus(statusErr, "sync failed: "+truncErr(msg.err))
		} else {
			m.setStatus(statusOK, "synced to "+m.cfg.Sync.Remote)
		}
		return m, nil

	case preflightMsg:
		return m.applyPreflight(msg)

	case scriptDoneMsg:
		m.monitor.Suspend(msg.profileID, false)
		m.pinHostKey(msg.profileID, msg.hostKeyFP, msg.hostKeyLine)
		if msg.ok {
			m.setStatus(statusOK, msg.summary)
		} else {
			m.setStatus(statusErr, msg.summary)
		}
		return m, nil

	case sessionDoneMsg:
		m.monitor.Suspend(msg.profileID, false)
		m.pinHostKey(msg.profileID, msg.hostKeyFP, msg.hostKeyLine)
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
		if m.help {
			m.help = false
			return m, nil
		}
	}

	switch m.screen {
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
		m.setStatus(statusOK, fmt.Sprintf("%s: %s (%.0f ms)", p.Name, r.Reason, float64(r.Latency.Milliseconds())))
		m.pinHostKey(profileID, r.HostKeyFP, r.HostKeyLine)
		return
	}
	kind := statusErr
	if r.Stage == sshx.StageHostKey {
		m.setStatus(statusErr, fmt.Sprintf("%s: %s", p.Name, r.Reason))
		return
	}
	m.setStatus(kind, fmt.Sprintf("%s [%s]: %s", p.Name, r.Stage, r.Reason))
}

// pinHostKey records the fingerprint + full key on first successful contact
// (TOFU). The full key line lets ExternalCommand hand ssh a strict
// known_hosts file, so the pin protects real sessions too.
func (m *Model) pinHostKey(profileID, fp, line string) {
	if fp == "" {
		return
	}
	p := m.store.ByID(profileID)
	if p == nil {
		return
	}
	if p.HostKeyFP == "" {
		p.HostKeyFP, p.HostKey = fp, line
		m.store.Save()
		return
	}
	if p.HostKeyFP == fp && p.HostKey == "" && line != "" {
		p.HostKey = line // backfill full key for profiles pinned before this field existed
		m.store.Save()
	}
	// A differing pin never overwrites silently — sshx already refused the
	// connection; the stale pin stays until the user re-trusts via edit.
}

// --- commands ---

func (m *Model) testCmd(p profile.Profile) tea.Cmd {
	creds, err := m.credsFor(&p)
	if err != nil {
		return func() tea.Msg {
			return testDoneMsg{p.ID, sshx.TestResult{Stage: sshx.StageAuth, Err: err, Reason: err.Error()}}
		}
	}
	return func() tea.Msg {
		return testDoneMsg{p.ID, sshx.Test(p, creds, testTimeout)}
	}
}

func (m *Model) credsFor(p *profile.Profile) (sshx.Credentials, error) {
	var creds sshx.Credentials
	if !m.vault.Unlocked() {
		return creds, fmt.Errorf("vault is locked — restart clavis and unlock to use credentials")
	}
	if p.HasAuth(profile.AuthPassword) {
		b, err := m.vault.Get(p.PassSecret())
		if err != nil {
			return creds, fmt.Errorf("password missing from vault: %w", err)
		}
		creds.Password = string(b)
	}
	if p.HasAuth(profile.AuthKey) {
		b, err := m.vault.Get(p.KeySecret())
		if err != nil {
			return creds, fmt.Errorf("ssh key missing from vault: %w", err)
		}
		creds.PrivateKey = b
		if m.vault.Has(p.PassphraseSecret()) {
			pp, err := m.vault.Get(p.PassphraseSecret())
			if err == nil {
				creds.Passphrase = string(pp)
			}
		}
	}
	return creds, nil
}

// startConnect kicks off a connect: credentials are resolved and the host is
// preflighted asynchronously while the TUI keeps running (spinner in the
// status bar). Only when the host actually answers does the terminal get
// handed to ssh — so a dead, slow, or rate-limited host is a status-bar
// message, not a long suspension of the UI. Probing is paused for the host
// for the duration so the probe and the session don't burst connections
// together (some gateways rate-limit new SSH connections per source).
func (m *Model) startConnect(p profile.Profile) tea.Cmd {
	creds, err := m.credsFor(&p)
	if err != nil {
		m.setStatus(statusErr, err.Error())
		return nil
	}
	m.connecting = p.ID
	m.pending = &pendingConnect{p: p, creds: creds}
	m.monitor.Suspend(p.ID, true)
	m.setStatus(statusInfo, "connecting to "+p.Name+"…")
	addr := p.Addr()
	return func() tea.Msg {
		return preflightMsg{p.ID, sshx.Preflight(addr, preflightTimeout)}
	}
}

// applyPreflight either surfaces the failure (staying in the TUI) or hands
// the terminal over to the real session.
func (m *Model) applyPreflight(msg preflightMsg) (tea.Model, tea.Cmd) {
	if m.pending == nil || m.connecting != msg.profileID {
		return m, nil // stale — profile deleted or connect superseded
	}
	pc := *m.pending
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
	if p.HasAuth(profile.AuthKey) {
		cmd, tail, cleanup, err := sshx.ExternalCommand(p, pc.creds.PrivateKey)
		if err != nil {
			m.monitor.Suspend(p.ID, false)
			m.setStatus(statusErr, err.Error())
			return nil
		}
		return tea.ExecProcess(cmd, func(err error) tea.Msg {
			cleanup()
			detail := ""
			if err != nil {
				detail = tail.LastLine()
			}
			return sessionDoneMsg{p.ID, "", "", err, detail}
		})
	}
	// password-only: in-process PTY session
	sess := &passwordSession{p: p, password: pc.creds.Password}
	return tea.Exec(sess, func(err error) tea.Msg {
		return sessionDoneMsg{p.ID, sess.fp, sess.keyLine, err, ""}
	})
}

// passwordSession adapts sshx.RunPasswordSession to tea.ExecCommand.
type passwordSession struct {
	p        profile.Profile
	password string
	fp       string
	keyLine  string
}

func (s *passwordSession) Run() error {
	fp, line, err := sshx.RunPasswordSession(s.p, s.password)
	s.fp, s.keyLine = fp, line
	s.password = "" // shrink the plaintext window once the session ends
	return err
}

// The session talks to the real TTY directly; bubbletea's redirects are moot.
func (s *passwordSession) SetStdin(io.Reader)  {}
func (s *passwordSession) SetStdout(io.Writer) {}
func (s *passwordSession) SetStderr(io.Writer) {}

func (m *Model) syncCmd(msg string) tea.Cmd {
	if m.cfg.Sync.Remote == "" {
		m.setStatus(statusWarn, "sync not configured — press g for settings")
		return nil
	}
	token, err := m.githubToken()
	if err != nil {
		m.setStatus(statusErr, err.Error())
		return nil
	}
	m.syncing = true
	dir, remote := m.cfgDir, m.cfg.Sync.Remote
	return func() tea.Msg {
		c := gitsync.New(dir, token)
		if err := c.EnsureRepo(); err != nil {
			return syncDoneMsg{err}
		}
		if c.RemoteURL() == "" {
			if err := c.SetRemote(remote); err != nil {
				return syncDoneMsg{err}
			}
		}
		return syncDoneMsg{c.Sync(msg)}
	}
}

func (m *Model) githubToken() (string, error) {
	if !m.vault.HasLocal("github-token") {
		return "", fmt.Errorf("no GitHub token on this machine — press g for settings")
	}
	if !m.vault.Unlocked() {
		return "", fmt.Errorf("vault is locked; token unavailable")
	}
	b, err := m.vault.GetLocal("github-token")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// saveAll persists profiles and, when autosync is on, fires a background sync.
func (m *Model) saveAll(what string) tea.Cmd {
	if err := m.store.Save(); err != nil {
		m.setStatus(statusErr, "save failed: "+err.Error())
		return nil
	}
	m.syncTargets()
	if m.cfg.Sync.AutoSync && m.cfg.Sync.Remote != "" {
		return m.syncCmd("clavis: " + what)
	}
	return nil
}

func truncErr(err error) string {
	s := err.Error()
	if i := len(s); i > 160 {
		return s[:160] + "…"
	}
	return s
}

// Close stops background work; called by main after the program exits.
func (m *Model) Close() { m.monitor.Stop() }

// --- view ---

func (m *Model) View() string {
	if m.quiting {
		return ""
	}
	bodyH := max(m.height-m.footerHeight(), 1)
	var body string
	switch m.screen {
	case scrUnlock:
		body = m.unlock.view(m.width, bodyH)
	case scrFirstRun:
		body = m.firstRun.view(m.width, bodyH)
	case scrWizard:
		body = m.wizard.view(m.width, bodyH)
	case scrConfirmDelete:
		body = m.confirm.view(m.width, bodyH)
	case scrSettings:
		body = m.settings.view(m.width, bodyH)
	case scrScripts:
		body = m.scriptsUI.view(m.width, bodyH)
	default:
		body = m.viewList()
	}
	if m.help {
		body = center(m.viewHelp(), m.width, bodyH)
	}
	// Pin the footer to the bottom of the terminal.
	body = strings.TrimRight(body, "\n")
	if h := lipgloss.Height(body); m.height > 0 && h < bodyH {
		body += strings.Repeat("\n", bodyH-h)
	}
	return lipgloss.JoinVertical(lipgloss.Left, body, m.viewStatusBar())
}

// footerHeight mirrors viewStatusBar's line count so views can size themselves.
func (m *Model) footerHeight() int {
	h := 1 // divider
	if m.statusMsg != "" || m.syncing {
		h++
	}
	if m.screen == scrList && !m.help {
		h++ // key legend
	}
	return h
}

func (m *Model) viewStatusBar() string {
	width := max(m.width, 40)
	pad := strings.Repeat(" ", m.layoutList().pad)
	lines := []string{theme.Divider(width)}

	if m.statusMsg != "" || m.syncing {
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
		if m.syncing {
			msg = m.spin.View() + " syncing… " + msg
			style = theme.Accent
		}
		lines = append(lines, pad+style.MaxWidth(width-len(pad)-1).Render(msg))
	}

	if m.screen == scrList && !m.help {
		lines = append(lines, pad+m.legend(width-2*len(pad)))
	}
	return strings.Join(lines, "\n")
}

// legend renders the persistent key legend, dropping entries until it fits.
func (m *Model) legend(avail int) string {
	if m.filtering {
		return hintKeys([][2]string{{"enter", "apply"}, {"esc", "clear"}})
	}
	tiers := [][][2]string{
		{{"enter", "connect"}, {"r", "run script"}, {"a", "add"}, {"e", "edit"}, {"d", "delete"}, {"t", "test"},
			{"s", "sync"}, {"g", "settings"}, {"i", "import"}, {"o", "sort"}, {"/", "filter"}, {"?", "help"}, {"q", "quit"}},
		{{"enter", "connect"}, {"r", "run"}, {"a", "add"}, {"e", "edit"}, {"d", "delete"}, {"/", "filter"}, {"?", "help"}, {"q", "quit"}},
		{{"enter", "connect"}, {"/", "filter"}, {"?", "help"}, {"q", "quit"}},
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
