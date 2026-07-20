package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/theme"
	"github.com/armtch-dev/clavis/internal/vault"
)

// --- unlock screen ---

type unlockModel struct {
	v     *vault.Vault
	input textinput.Model
	errs  string
}

func newUnlock(v *vault.Vault) unlockModel {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.PromptStyle = theme.Accent
	ti.Cursor.Style = theme.Accent
	ti.EchoMode = textinput.EchoPassword
	ti.Placeholder = "AGE-SECRET-KEY-…"
	ti.Focus()
	return unlockModel{v: v, input: ti}
}

func (m *Model) updateUnlock(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
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
		if m.cfg.KeychainOptIn {
			vault.SaveToKeychain(strings.TrimSpace(m.unlock.input.Value()))
		}
		m.screen = scrList
		m.setStatus(statusOK, "vault unlocked")
		return m, nil
	}
	var cmd tea.Cmd
	m.unlock.input, cmd = m.unlock.input.Update(msg)
	return m, cmd
}

func (u unlockModel) view(w, h int) string {
	var b strings.Builder
	b.WriteString(theme.Title.Render("Unlock vault") + "\n\n")
	b.WriteString(theme.Dim.Render("Paste your master key to decrypt stored credentials.") + "\n\n")
	b.WriteString(u.input.View() + "\n")
	if u.errs != "" {
		b.WriteString("\n" + theme.StatusErr.Render("✗ "+u.errs) + "\n")
	}
	b.WriteString("\n" + theme.Divider(50) + "\n")
	b.WriteString(hintKeys([][2]string{{"enter", "unlock"}, {"esc", "browse locked"}}) + "\n")
	b.WriteString(theme.Hint.Render("lost the key?  clavis vault reset"))
	return center(theme.Panel.Width(56).Render(b.String()), w, h)
}

// --- first-run key banner ---

type keyBannerModel struct {
	identity string
	cfg      *config.Config
	cfgDir   string
	saved    bool // user pressed k (keychain)
}

func newKeyBanner(identity string, cfg *config.Config, cfgDir string) keyBannerModel {
	return keyBannerModel{identity: identity, cfg: cfg, cfgDir: cfgDir}
}

func (m *Model) updateFirstRun(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "k", "K":
		if err := vault.SaveToKeychain(m.firstRun.identity); err != nil {
			m.setStatus(statusErr, err.Error())
		} else {
			m.firstRun.saved = true
			m.cfg.KeychainOptIn = true
			m.cfg.Save(m.cfgDir)
		}
		return m, nil
	case "enter":
		m.firstRun.identity = "" // drop it from memory
		m.screen = scrList
		return m, nil
	}
	return m, nil
}

func (k keyBannerModel) view(w, h int) string {
	var b strings.Builder
	b.WriteString(theme.Title.Render("Master key") + theme.Dim.Render("   shown only once") + "\n\n")
	b.WriteString(theme.Value.Render("Everything in the vault is encrypted to this key. clavis does not") + "\n")
	b.WriteString(theme.Value.Render("store it. Copy it somewhere off this machine — a password") + "\n")
	b.WriteString(theme.Value.Render("manager, printed, a USB stick. Lose it and stored credentials") + "\n")
	b.WriteString(theme.Value.Render("cannot be recovered, only reset.") + "\n\n")
	b.WriteString(theme.Accent.Render(k.identity) + "\n\n")
	b.WriteString(theme.Divider(64) + "\n")
	if k.saved {
		b.WriteString(theme.StatusOK.Render("✓ cached in macOS Keychain (auto-unlock on this Mac)") + "\n")
	} else {
		b.WriteString(hintKeys([][2]string{{"k", "also cache in macOS Keychain"}}) + "\n")
	}
	b.WriteString(hintKeys([][2]string{{"enter", "I stored it safely — continue"}}))
	return center(theme.Panel.Width(70).Render(b.String()), w, h)
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
	app     *Model
	step    sstep
	input   textinput.Model
	errs    string
	login   string // validated GitHub login
	busy    bool
	pending string // repo name awaiting creation confirm
	token   string // pending token, stored only after GitHub validates it
}

type tokenCheckedMsg struct {
	login string
	err   error
}

type repoCreatedMsg struct {
	url string
	err error
}

func newSettings(app *Model) *settingsModel {
	return &settingsModel{app: app, step: sMenu}
}

func (s *settingsModel) textStep(step sstep, placeholder string, masked bool) {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.PromptStyle = theme.Accent
	ti.Cursor.Style = theme.Accent
	ti.Placeholder = placeholder
	if masked {
		ti.EchoMode = textinput.EchoPassword
	}
	ti.Focus()
	s.input = ti
	s.step = step
	s.errs = ""
}

func (m *Model) updateSettings(msg tea.Msg) (tea.Model, tea.Cmd) {
	s := m.settings

	switch msg := msg.(type) {
	case tokenCheckedMsg:
		s.busy = false
		if msg.err != nil {
			s.token = ""
			s.errs = msg.err.Error()
			s.textStep(sToken, "ghp_… / github_pat_…", true)
			return m, nil
		}
		if err := m.vault.PutLocal("github-token", []byte(s.token)); err != nil {
			s.token = ""
			s.errs = err.Error()
			return m, nil
		}
		s.token = ""
		s.login = msg.login
		s.step = sMenu
		m.setStatus(statusOK, "token valid for @"+msg.login+" (stored encrypted, this machine only)")
		return m, nil

	case repoCreatedMsg:
		s.busy = false
		if msg.err != nil {
			s.errs = msg.err.Error()
			s.step = sMenu
			return m, nil
		}
		m.cfg.Sync.Remote = msg.url
		m.cfg.Save(m.cfgDir)
		s.step = sMenu
		m.setStatus(statusOK, "private repo created: "+shortRemote(msg.url))
		return m, m.syncCmd("initial sync")

	case tea.KeyMsg:
		return m.settingsKey(msg)
	}
	return m, nil
}

func (m *Model) settingsKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := m.settings
	if s.busy {
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
			m.cfg.Sync.AutoSync = !m.cfg.Sync.AutoSync
			m.cfg.Save(m.cfgDir)
		case "k":
			m.cfg.KeychainOptIn = !m.cfg.KeychainOptIn
			if !m.cfg.KeychainOptIn {
				vault.DeleteFromKeychain()
			}
			m.cfg.Save(m.cfgDir)
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
			s.busy = true
			name := s.pending
			return m, func() tea.Msg {
				url, err := gitsync.CreateGitHubRepo(token, name, "clavis encrypted SSH vault")
				return repoCreatedMsg{url, err}
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
			s.token = val
			s.busy = true
			return m, func() tea.Msg {
				login, err := gitsync.ValidateToken(val)
				return tokenCheckedMsg{login, err}
			}
		case sRemoteURL:
			if val != "" {
				m.cfg.Sync.Remote = val
				m.cfg.Save(m.cfgDir)
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

func (s *settingsModel) view(w, h int) string {
	inner := min(w-6, 70)
	if inner < 34 {
		inner = 34
	}
	dw := inner - 6
	var b strings.Builder
	b.WriteString(theme.Title.Render("Settings") + theme.Dim.Render("   git sync") + "\n\n")

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
			b.WriteString("  " + theme.Accent.Render(k) + "  " +
				theme.Label.Width(30).Render(label) + theme.Value.Render(val) + "\n")
		}
		cfg := s.app.cfg
		tok := theme.Dim.Render("not set")
		if s.app.vault.HasLocal("github-token") {
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
		row("k", "cache master key in Keychain", onOff(cfg.KeychainOptIn))
		row("s", "sync now", "")
	}
	if s.errs != "" {
		b.WriteString("\n" + theme.StatusErr.Render("✗ "+s.errs) + "\n")
	}
	if s.busy {
		b.WriteString("\n" + theme.Accent.Render("talking to GitHub…") + "\n")
	}
	b.WriteString("\n" + theme.Divider(dw) + "\n" + theme.Hint.Render("esc back"))
	return theme.Panel.Width(inner).Render(b.String())
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
