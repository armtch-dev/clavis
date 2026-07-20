// Package tui is the clavis terminal UI: profile list with live reachability,
// step-by-step profile wizard, vault unlock, and sync settings — all in the
// Night Owl palette shared with scriptorium.
package tui

import (
	"fmt"
	"io"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/probe"
	"github.com/armtch-dev/clavis/internal/profile"
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
)

const (
	probeInterval = 10 * time.Second
	probeTimeout  = 3 * time.Second
	testTimeout   = 8 * time.Second
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
	cfgDir string
	cfg    *config.Config
	store  *profile.Store
	vault  *vault.Vault

	screen  screen
	help    bool
	width   int
	height  int
	quiting bool

	// list state
	cursor    int
	filter    string
	filtering bool
	testing   map[string]bool // profile IDs with an in-flight test

	// probe plumbing
	monitor  *probe.Monitor
	probeCh  chan probe.Status
	statuses map[string]probe.Status

	// sub-screens
	unlock   unlockModel
	firstRun keyBannerModel
	wizard   *wizardModel
	confirm  confirmModel
	settings *settingsModel

	statusMsg  string
	statusType statusKind
	syncing    bool
}

// New builds the root model. identity is non-empty only right after a
// first-run vault init (so the key banner can be shown once).
func New(cfgDir string, cfg *config.Config, store *profile.Store, v *vault.Vault, freshIdentity string) *Model {
	m := &Model{
		cfgDir:   cfgDir,
		cfg:      cfg,
		store:    store,
		vault:    v,
		testing:  map[string]bool{},
		statuses: map[string]probe.Status{},
		probeCh:  make(chan probe.Status, 64),
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

func (m *Model) setStatus(k statusKind, msg string) {
	m.statusType, m.statusMsg = k, msg
}

// --- messages ---

type probeMsg probe.Status

type testDoneMsg struct {
	profileID string
	result    sshx.TestResult
}

type syncDoneMsg struct{ err error }

type sessionDoneMsg struct {
	profileID   string
	hostKeyFP   string
	hostKeyLine string
	err         error
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

	case sessionDoneMsg:
		m.pinHostKey(msg.profileID, msg.hostKeyFP, msg.hostKeyLine)
		if msg.err != nil {
			m.setStatus(statusErr, "session ended: "+truncErr(msg.err))
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

// connectCmd hands the terminal over to a real SSH session.
func (m *Model) connectCmd(p profile.Profile) tea.Cmd {
	creds, err := m.credsFor(&p)
	if err != nil {
		m.setStatus(statusErr, err.Error())
		return nil
	}
	if p.HasAuth(profile.AuthKey) {
		cmd, cleanup, err := sshx.ExternalCommand(p, creds.PrivateKey)
		if err != nil {
			m.setStatus(statusErr, err.Error())
			return nil
		}
		return tea.ExecProcess(cmd, func(err error) tea.Msg {
			cleanup()
			return sessionDoneMsg{p.ID, "", "", err}
		})
	}
	// password-only: in-process PTY session
	sess := &passwordSession{p: p, password: creds.Password}
	return tea.Exec(sess, func(err error) tea.Msg {
		return sessionDoneMsg{p.ID, sess.fp, sess.keyLine, err}
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
	var body string
	switch m.screen {
	case scrUnlock:
		body = m.unlock.view(m.width, m.height)
	case scrFirstRun:
		body = m.firstRun.view(m.width, m.height)
	case scrWizard:
		body = m.wizard.view(m.width, m.height)
	case scrConfirmDelete:
		body = m.confirm.view(m.width, m.height)
	case scrSettings:
		body = m.settings.view(m.width, m.height)
	default:
		body = m.viewList()
	}
	if m.help {
		body = m.viewHelp()
	}
	return lipgloss.JoinVertical(lipgloss.Left, body, m.viewStatusBar())
}

func (m *Model) viewStatusBar() string {
	style := theme.MutedText
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
		msg = "⟳ syncing… " + msg
		style = theme.Accent
	}
	if msg == "" {
		msg = "enter connect · a add · t test · e edit · d delete · s sync · g settings · i import · / filter · ? help · q quit"
		style = theme.MutedText
	}
	return style.MaxWidth(max(m.width, 20)).Render(" " + msg)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
