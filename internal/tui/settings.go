package tui

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/fido2"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/theme"
	"github.com/armtch-dev/clavis/internal/vault"
)

// --- unlock screen ---

type unlockModel struct {
	v        *vault.Vault
	input    textinput.Model
	errs     string
	fidoBusy bool // assertion in flight — waiting for a key touch
	fido     bool // a security key is enrolled and the tools are present
}

// fidoUnlockMsg carries the identity recovered from a security-key assertion.
type fidoUnlockMsg struct {
	identity string
	err      error
}

// fidoEnrollMsg reports settings-screen enroll/remove completion.
type fidoEnrollMsg struct{ err error }

func newUnlock(v *vault.Vault, cfgDir string) unlockModel {
	return unlockModel{
		v:     v,
		input: newTextInput("AGE-SECRET-KEY-…", true),
		fido:  fido2.Available() && fido2.Enrolled(cfgDir),
	}
}

// fidoUnlockCmd asserts against the enrolled credential (blocks on a key
// touch, so always off the UI thread as a command).
func (m *Model) fidoUnlockCmd() tea.Cmd {
	dir := m.cfgDir
	ctx := m.networkContext()
	return m.background(func() tea.Msg {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		id, err := fido2.UnlockContext(ctx, dir)
		return fidoUnlockMsg{id, err}
	}, fidoUnlockMsg{err: context.Canceled})
}

func (m *Model) updateUnlock(msg tea.Msg) (tea.Model, tea.Cmd) {
	if fm, ok := msg.(fidoUnlockMsg); ok {
		m.unlock.fidoBusy = false
		if fm.err == nil {
			fm.err = m.vault.Unlock(fm.identity)
		}
		if fm.err != nil {
			m.unlock.errs = fm.err.Error()
			return m, nil
		}
		m.finishUnlock()
		m.setStatus(statusOK, "vault unlocked via security key")
		return m, nil
	}
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if m.unlock.fidoBusy {
		return m, nil
	}
	if key.Type == tea.KeyTab && m.unlock.fido {
		m.unlock.fidoBusy = true
		m.unlock.errs = ""
		return m, m.fidoUnlockCmd()
	}
	switch key.Type {
	case tea.KeyEsc:
		m.screen = scrList
		m.setStatus(statusWarn, "vault stays locked — connecting and testing are disabled")
		return m, nil
	case tea.KeyEnter:
		if err := m.vault.Unlock(m.unlock.input.Value()); err != nil {
			m.unlock.errs = err.Error()
			m.unlock.input.SetValue("")
			return m, nil
		}
		identity := strings.TrimSpace(m.unlock.input.Value())
		m.finishUnlock()
		m.setStatus(statusOK, "vault unlocked")
		return m, m.hardwareCmd(&hardwareRequest{action: "refresh"}, identity)
	}
	var cmd tea.Cmd
	m.unlock.input, cmd = m.unlock.input.Update(msg)
	return m, cmd
}

func (m *Model) finishUnlock() {
	m.screen = m.resumeScreen
	m.resumeScreen = scrList
	if m.screen == scrUnlock || m.screen == scrWelcome || m.screen == scrFirstRun {
		m.screen = scrList
	}
}

func (u unlockModel) view(spin string, w, h int, scroll ...int) string {
	pw := min(56, w-2) // panel width; dividers must track it or they wrap inside
	var b strings.Builder
	b.WriteString(theme.Title.Render("Unlock vault") + "\n\n")
	b.WriteString(theme.Dim.Render("Paste your master key to decrypt stored credentials.") + "\n\n")
	b.WriteString(u.input.View() + "\n")
	if u.fidoBusy {
		b.WriteString("\n" + spin + theme.Accent.Render(" touch your security key…") + "\n")
	}
	if u.errs != "" {
		b.WriteString("\n" + theme.StatusErr.Render("✗ "+u.errs) + "\n")
	}
	b.WriteString("\n" + theme.Divider(pw-6) + "\n")
	hints := [][2]string{{"enter", "unlock"}, {"esc", "browse locked"}}
	if u.fido {
		hints = append(hints, [2]string{"tab", "security key"})
	}
	b.WriteString(hintKeys(hints) + "\n")
	b.WriteString(theme.Hint.Render("lost the key?  clavis vault reset"))
	if h < 10 {
		return panelView("Unlock vault\n"+u.input.View()+"\nenter unlock · tab security key\nesc browse · ctrl+e error", w, h, pw, scrollOffset(scroll))
	}
	return panelView(b.String(), w, h, pw, scrollOffset(scroll))
}

// --- first-run key banner ---

type keyBannerModel struct {
	identity string
	saved    bool // user pressed k (keychain)
	copied   bool // user pressed c (clipboard)
}

func newKeyBanner(identity string) keyBannerModel {
	return keyBannerModel{identity: identity}
}

func (m *Model) updateFirstRun(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "c", "C":
		identity := m.firstRun.identity
		return m, func() tea.Msg { return copiedMsg{err: clipboard.WriteAll(identity), banner: identity} }
	case "k", "K":
		if m.hardware != nil {
			return m, nil
		}
		return m, m.hardwareCmd(&hardwareRequest{action: "cache", banner: m.firstRun.identity}, m.firstRun.identity)
	case "enter":
		m.firstRun.identity = "" // drop it from memory
		m.screen = scrList
		return m, nil
	}
	return m, nil
}

func (k keyBannerModel) view(w, h int, scroll ...int) string {
	pw := min(70, w-2)
	var b strings.Builder
	b.WriteString(theme.Title.Render("Master key") + theme.Dim.Render("   shown only once") + "\n\n")
	b.WriteString(theme.Value.Render("Everything in the vault is encrypted to this key. clavis does not") + "\n")
	b.WriteString(theme.Value.Render("store it. Copy it somewhere off this machine — a password") + "\n")
	b.WriteString(theme.Value.Render("manager, printed, a USB stick. Lose it and stored credentials") + "\n")
	b.WriteString(theme.Value.Render("cannot be recovered, only reset.") + "\n\n")
	b.WriteString(theme.Accent.Render(k.identity) + "\n\n")
	b.WriteString(theme.Divider(pw-6) + "\n")
	if k.copied {
		b.WriteString(theme.StatusOK.Render("✓ copied — paste it into your password manager, then clear the clipboard") + "\n")
	}
	if k.saved {
		b.WriteString(theme.StatusOK.Render("✓ cached in macOS Keychain (Touch ID unlocks on this Mac)") + "\n")
	}
	var hints [][2]string
	if !k.copied {
		hints = append(hints, [2]string{"c", "copy to clipboard"})
	}
	if !k.saved && runtime.GOOS == "darwin" {
		hints = append(hints, [2]string{"k", "cache in macOS Keychain"})
	}
	if len(hints) > 0 {
		b.WriteString(hintKeys(hints) + "\n")
	}
	b.WriteString(hintKeys([][2]string{{"enter", "I stored it safely — continue"}}))
	return panelView(b.String(), w, h, pw, scrollOffset(scroll))
}

// --- settings screen ---

type sstep int

const (
	sMenu sstep = iota
	sToken
	sRemoteURL
	sRepoName
	sConfirmCreate
)

type settingsModel struct {
	app                                       *Model
	step                                      sstep
	input                                     textinput.Model
	errs                                      string
	login                                     string // validated GitHub login
	busy                                      string // in-flight work notice; "" when idle
	pending                                   string // repo name awaiting creation confirm
	remoteDraft                               string // returned/unsaved URL, retained across menu navigation
	token                                     string // pending token, stored only after GitHub validates it
	tokenValidated                            bool   // retain a completed validation across local write failure
	tokenLogin                                string
	request                                   *settingsRequest
	tokenSet, fidoSet                         bool
	keychainSet, fidoAvailable, snapshotReady bool
	snapshotSeq                               int
}

// Immutable command identity. Only the UI consumes owner.request; background
// closures return this pointer without reading mutable settings/model state.
type settingsRequest struct {
	owner *settingsModel
	token string
}

type tokenCheckedMsg struct {
	login   string
	err     error
	request *settingsRequest
}

type repoCreatedMsg struct {
	url     string
	err     error
	request *settingsRequest
}

func newSettings(app *Model) *settingsModel {
	return &settingsModel{app: app, step: sMenu, tokenSet: app.hasSecret("github-token", true)}
}

func (s *settingsModel) textStep(step sstep, placeholder string, masked bool) {
	s.input = newTextInput(placeholder, masked)
	switch step {
	case sToken:
		s.input.SetValue(s.token)
	case sRemoteURL:
		s.input.SetValue(s.remoteDraft)
	}
	s.step = step
	s.errs = ""
}

func (m *Model) updateSettings(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := m.settings

	switch msg := msg.(type) {
	case fidoEnrollMsg:
		if s == nil {
			return m, nil
		}
		s.busy = ""
		if msg.err != nil {
			s.errs = truncErr(msg.err)
			return m, nil
		}
		s.fidoSet = true
		// Keychain and security key are either/or: the enrollment that just
		// succeeded replaces the cache. Removed only now — a failed enroll
		// must not cost the user their working Keychain unlock.
		return m, m.hardwareCmd(&hardwareRequest{settings: s, action: "uncache"}, "")

	case tokenCheckedMsg:
		s = m.settingsResultOwner(msg.request)
		if s == nil {
			return m, nil
		}
		s.busy = ""
		if msg.request != nil {
			s.token = msg.request.token
			s.input.SetValue(s.token)
		}
		if msg.err != nil {
			s.tokenValidated = false
			s.step = sToken
			s.errs = msg.err.Error()
			return m, nil
		}
		s.tokenValidated, s.tokenLogin = true, msg.login
		return s.saveToken(m)

	case repoCreatedMsg:
		s = m.settingsResultOwner(msg.request)
		if s == nil {
			return m, nil
		}
		s.busy = ""
		if msg.err != nil {
			s.errs = msg.err.Error()
			s.step = sMenu
			return m, nil
		}
		s.remoteDraft = msg.url
		if s != m.settings {
			s.textStep(sRemoteURL, "repo URL", false)
			s.errs = "repository created — URL retained for local save"
			return m, nil
		}
		if err := m.changeConfig(func(c *config.Config) { c.Sync.Remote = msg.url }); err != nil {
			s.textStep(sRemoteURL, "repo URL", false)
			s.errs = err.Error()
			return m, nil
		}
		s.remoteDraft = ""
		s.step = sMenu
		m.setStatus(statusOK, "private repo created: "+shortRemote(msg.url))
		return m, m.syncCmd("initial sync")

	case tea.KeyMsg:
		if s == nil {
			return m, nil
		}
		return m.settingsKey(msg)
	}
	return m, nil
}

func (m *Model) settingsResultOwner(request *settingsRequest) *settingsModel {
	if request == nil {
		return m.settings
	} // compatibility for direct result fixtures
	s := request.owner
	if s == nil || s.request != request {
		return nil
	} // superseded or already consumed
	s.request = nil
	return s
}

func (m *Model) settingsKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := m.settings
	if s.busy != "" {
		return m, nil
	}

	if s.step == sMenu {
		switch key.String() {
		case "esc", "q":
			m.screen = scrList
		case "t":
			s.textStep(sToken, "ghp_… / github_pat_…", true)
		case "u":
			s.textStep(sRemoteURL, "https://github.com/you/clavis-vault.git", false)
		case "c":
			s.textStep(sRepoName, "clavis-vault", false)
		case "a":
			if err := m.changeConfig(func(c *config.Config) { c.Sync.AutoSync = !c.Sync.AutoSync }); err != nil {
				s.errs = err.Error()
			}
		case "r":
			return m, m.localSnapshotCmd(s)
		case "v":
			m.errorDetail, m.errorOpen, m.panelScroll = m.syncDetails(), true, 0
		case "k":
			if runtime.GOOS != "darwin" {
				return m, nil
			}
			if !s.snapshotReady || m.hardware != nil {
				s.errs = "local status loading — r refreshes"
				return m, nil
			}
			if s.keychainSet {
				s.busy = "removing Keychain cache…"
				return m, m.hardwareCmd(&hardwareRequest{settings: s, action: "uncache"}, "")
			}
			id, err := m.vault.Identity()
			if err != nil {
				s.errs = "unlock the vault first, then enable the keychain cache"
				return m, nil
			}
			s.busy = "updating Keychain…"
			return m, m.hardwareCmd(&hardwareRequest{settings: s, action: "cache"}, id)
		case "f":
			if !s.snapshotReady || m.hardware != nil {
				s.errs = "local status loading — r refreshes"
				return m, nil
			}
			if !s.fidoAvailable {
				s.errs = "fido2 tools not found — brew install libfido2 (or apt install fido2-tools)"
				return m, nil
			}
			if s.fidoSet {
				s.busy = "removing security-key unlock…"
				return m, m.hardwareCmd(&hardwareRequest{settings: s, action: "remove-fido"}, "")
			}
			id, err := m.vault.Identity()
			if err != nil {
				s.errs = "vault is locked — unlock first to enroll a security key"
				return m, nil
			}
			s.busy = "touch your security key…"
			return m, m.hardwareCmd(&hardwareRequest{settings: s, action: "enroll"}, id)
		case "s":
			return m, m.syncCmd("manual sync")
		}
		return m, nil
	}

	if s.step == sConfirmCreate {
		switch key.String() {
		case "y", "Y":
			token, err := m.githubToken()
			if err != nil {
				s.errs, s.step = err.Error(), sMenu
				return m, nil
			}
			s.busy = "talking to GitHub…"
			name := s.pending
			request := &settingsRequest{owner: s}
			s.request = request
			return m, func() tea.Msg {
				url, err := gitsync.CreateGitHubRepo(token, name, "clavis encrypted SSH vault")
				return repoCreatedMsg{url: url, err: err, request: request}
			}
		default:
			s.step = sMenu
		}
		return m, nil
	}

	switch key.Type {
	case tea.KeyEsc:
		s.step = sMenu
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(s.input.Value())
		switch s.step {
		case sToken:
			if val == "" {
				s.step = sMenu
				return m, nil
			}
			if s.tokenValidated && val == s.token {
				return s.saveToken(m)
			}
			s.token = val
			s.tokenValidated = false
			s.busy = "talking to GitHub…"
			request := &settingsRequest{owner: s, token: val}
			s.request = request
			return m, func() tea.Msg {
				login, err := gitsync.ValidateToken(val)
				return tokenCheckedMsg{login: login, err: err, request: request}
			}
		case sRemoteURL:
			if val != "" {
				s.remoteDraft = val
				if err := m.changeConfig(func(c *config.Config) { c.Sync.Remote = val }); err != nil {
					s.errs = err.Error()
					return m, nil
				}
				s.remoteDraft = ""
			}
			s.step = sMenu
		case sRepoName:
			if val == "" {
				s.step = sMenu
				return m, nil
			}
			s.pending = val
			s.step = sConfirmCreate
		}
		return m, nil
	}

	var cmd tea.Cmd
	s.input, cmd = s.input.Update(key)
	return m, cmd
}

// A successful remote validation is reusable for exactly these token bytes.
// Local persistence failure retains it; retry must not call GitHub again.
func (s *settingsModel) saveToken(m *Model) (tea.Model, tea.Cmd) {
	s.step = sToken
	if s != m.settings {
		s.errs = "token validated — input retained for local save"
		return m, nil
	}
	if err := m.putSecret("github-token", []byte(s.token), true); err != nil {
		s.errs = err.Error()
		return m, nil
	}
	s.login = s.tokenLogin
	s.token, s.tokenLogin = "", ""
	s.tokenValidated = false
	s.input.SetValue("")
	s.tokenSet = true
	s.snapshotSeq++ // an older entry snapshot cannot undo this persisted token state
	s.step, s.errs = sMenu, ""
	m.setStatus(statusOK, "token valid for @"+s.login+" (stored encrypted, this machine only)")
	return m, nil
}

func (s *settingsModel) view(w, h int) string {
	inner := panelWidth(w, 70)
	dw := inner - 6
	var b strings.Builder
	b.WriteString(theme.Title.Render(theme.IconGear+" Settings") + theme.Dim.Render("   sync & unlock") + "\n\n")

	switch s.step {
	case sToken, sRemoteURL, sRepoName:
		prompts := map[sstep]string{
			sToken:     "GitHub personal access token (needs repo scope)",
			sRemoteURL: "Existing repo URL",
			sRepoName:  "Name for the new private repo",
		}
		b.WriteString(theme.Label.Render(prompts[s.step]) + "\n\n" + s.input.View() + "\n")
	case sConfirmCreate:
		b.WriteString(theme.StatusWarn.Render("Create private GitHub repo “"+s.pending+"”?") + "\n\n")
		b.WriteString(theme.Value.Render("It receives profiles.json, config.json, vault.meta and") + "\n")
		b.WriteString(theme.Value.Render("vault/*.age (encrypted secrets). Never your master key,") + "\n")
		b.WriteString(theme.Value.Render("never your GitHub token, nothing in plaintext.") + "\n\n")
		b.WriteString(hintKeys([][2]string{{"y", "create + push"}, {"esc", "cancel"}}) + "\n")
	default:
		row := func(k, label, val string) {
			line := theme.Accent.Render(k) + " " + theme.Label.Render(label)
			if val != "" {
				line += "\n  " + theme.Value.Render(val)
			}
			b.WriteString(line + "\n")
		}
		cfg := s.app.cfg
		tok := theme.Dim.Render("not set")
		if s.tokenSet {
			tok = "set"
		}
		if s.login != "" {
			tok = "@" + s.login
		}
		remote := theme.Dim.Render("not set")
		if cfg.Sync.Remote != "" {
			remote = shortRemote(cfg.Sync.Remote)
		}
		row("t", "GitHub token (this machine)", tok)
		row("u", "use existing repo URL", remote)
		row("c", "create new private repo", "")
		row("a", "autosync on every change", onOff(cfg.Sync.AutoSync))
		if runtime.GOOS == "darwin" {
			row("k", "Keychain unlock (Touch ID)", onOff(s.keychainSet))
		}
		row("f", "security-key unlock (FIDO2)", onOff(s.fidoSet))
		row("s", "sync now", "")
		row("r", "refresh local unlock status", "")
		row("v", "full sync details", "")
		if !s.snapshotReady {
			b.WriteString(theme.Hint.Render("loading local status…") + "\n")
		}
		b.WriteString(s.app.syncDetails() + "\n")
	}
	if s.errs != "" {
		b.WriteString("\n" + theme.StatusErr.Render("✗ "+s.errs) + "\n")
	}
	if s.busy != "" {
		b.WriteString("\n" + s.app.spin.View() + theme.Accent.Render(" "+s.busy) + "\n")
	}
	b.WriteString("\n" + theme.Divider(dw) + "\n" + theme.Hint.Render("esc back"))
	return panelView(b.String(), w, h, inner, s.app.panelScroll)
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
