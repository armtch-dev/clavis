package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/theme"
	"github.com/armtch-dev/clavis/internal/vault"
)

// --- welcome screen (first run: no vault on this machine yet) ---
//
// Two paths out: mint a new vault (existing key banner takes over), or
// restore — fetch an existing clavis repo, then unlock it with the master
// key from the original setup.

type welStep int

const (
	wChoice welStep = iota
	wURL            // repo URL prompt
	wToken          // GitHub PAT prompt (masked)
	wKey            // master key prompt (masked), after a successful fetch
)

type welcomeModel struct {
	step  welStep
	input textinput.Model
	url   string
	token string // held only until it lands encrypted in local/
	busy  bool
	errs  string
}

type restoreFetchedMsg struct{ err error }

// newTextInput is the shared prompt style for settings and welcome inputs.
func newTextInput(placeholder string, masked bool) textinput.Model {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.PromptStyle = theme.Accent
	ti.Cursor.Style = theme.Accent
	ti.Placeholder = placeholder
	if masked {
		ti.EchoMode = textinput.EchoPassword
	}
	ti.Focus()
	return ti
}

func (w *welcomeModel) textStep(step welStep, placeholder string, masked bool) {
	w.input = newTextInput(placeholder, masked)
	w.step = step
	w.errs = ""
}

func (m *Model) updateWelcome(msg tea.Msg) (tea.Model, tea.Cmd) {
	w := m.welcome
	switch msg := msg.(type) {
	case restoreFetchedMsg:
		w.busy = false
		if msg.err != nil {
			w.errs = truncErr(msg.err)
			w.step = wChoice
			return m, nil
		}
		if err := m.reloadFetched(); err != nil {
			w.errs = truncErr(err)
			w.step = wChoice
			return m, nil
		}
		w.textStep(wKey, "AGE-SECRET-KEY-…", true)
		return m, nil
	case tea.KeyMsg:
		return m.welcomeKey(msg)
	}
	return m, nil
}

// reloadFetched re-reads everything the fetch may have replaced on disk.
func (m *Model) reloadFetched() error {
	v, err := vault.Load(m.cfgDir)
	if err != nil {
		return fmt.Errorf("fetched repo is not a clavis config: %w", err)
	}
	cfg, err := config.Load(m.cfgDir)
	if err != nil {
		return err
	}
	store, err := profile.LoadStore(m.cfgDir)
	if err != nil {
		return err
	}
	scripts, err := script.LoadStore(m.cfgDir)
	if err != nil {
		return err
	}
	m.vault, m.cfg, m.store, m.scripts = v, cfg, store, scripts
	m.syncTargets()
	return nil
}

func (m *Model) welcomeKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	w := m.welcome
	if key.String() == "ctrl+c" {
		m.quiting = true
		return m, tea.Quit
	}
	if w.busy {
		return m, nil
	}

	if w.step == wChoice {
		switch key.String() {
		case "n", "N", "enter":
			v, id, err := vault.Init(m.cfgDir)
			if err != nil {
				w.errs = err.Error()
				return m, nil
			}
			m.vault = v
			m.firstRun = newKeyBanner(id, m.cfg, m.cfgDir)
			m.screen = scrFirstRun
		case "r", "R":
			w.textStep(wURL, "https://github.com/you/clavis-vault.git", false)
		case "q":
			m.quiting = true
			return m, tea.Quit
		}
		return m, nil
	}

	switch key.Type {
	case tea.KeyEsc:
		w.step, w.errs = wChoice, ""
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(w.input.Value())
		if val == "" {
			return m, nil
		}
		switch w.step {
		case wURL:
			w.url = val
			w.textStep(wToken, "ghp_… / github_pat_…", true)
		case wToken:
			w.token = val
			w.busy = true
			dir, url := m.cfgDir, w.url
			return m, func() tea.Msg {
				return restoreFetchedMsg{gitsync.New(dir, val).Bootstrap(url)}
			}
		case wKey:
			if err := m.vault.Unlock(val); err != nil {
				w.errs = err.Error()
				w.input.SetValue("")
				return m, nil
			}
			if err := m.vault.VerifyAll(); err != nil {
				m.vault.Lock()
				w.errs = "vault verification failed: " + truncErr(err)
				w.input.SetValue("")
				return m, nil
			}
			if err := m.vault.PutLocal("github-token", []byte(w.token)); err != nil {
				m.setStatus(statusWarn, "token not stored: "+err.Error())
			}
			w.token = ""
			// The fetched config.json usually carries the remote already;
			// fill it from the paste only if it doesn't.
			if m.cfg.Sync.Remote == "" {
				m.cfg.Sync.Remote = w.url
				m.cfg.Save(m.cfgDir)
			}
			m.screen = scrList
			m.setStatus(statusOK, "restored from "+shortRemote(w.url))
		}
		return m, nil
	}

	var cmd tea.Cmd
	w.input, cmd = w.input.Update(key)
	return m, cmd
}

func (w *welcomeModel) view(width, h int) string {
	var b strings.Builder
	b.WriteString(theme.Title.Render("Welcome to clavis") + "\n\n")
	switch w.step {
	case wChoice:
		b.WriteString(theme.Value.Render("No vault on this machine yet.") + "\n\n")
		b.WriteString("  " + theme.Accent.Render("n") + "  " + theme.Label.Render("new vault — generate a master key here") + "\n")
		b.WriteString("  " + theme.Accent.Render("r") + "  " + theme.Label.Render("restore — fetch your existing clavis git repo") + "\n")
	case wURL:
		b.WriteString(theme.Label.Render("Git repo URL holding your clavis config") + "\n\n" + w.input.View() + "\n")
	case wToken:
		b.WriteString(theme.Label.Render("GitHub token for this repo (repo scope)") + "\n")
		b.WriteString(theme.Dim.Render("stored encrypted on this machine only, never synced") + "\n\n")
		b.WriteString(w.input.View() + "\n")
	case wKey:
		b.WriteString(theme.StatusOK.Render("✓ config fetched") + "\n\n")
		b.WriteString(theme.Label.Render("Paste the master key from your original setup") + "\n\n")
		b.WriteString(w.input.View() + "\n")
	}
	if w.errs != "" {
		b.WriteString("\n" + theme.StatusErr.Render("✗ "+w.errs) + "\n")
	}
	if w.busy {
		b.WriteString("\n" + theme.Accent.Render("fetching…") + "\n")
	}
	b.WriteString("\n" + theme.Divider(56) + "\n")
	if w.step == wChoice {
		b.WriteString(hintKeys([][2]string{{"n", "new vault"}, {"r", "restore"}, {"q", "quit"}}))
	} else {
		b.WriteString(hintKeys([][2]string{{"enter", "continue"}, {"esc", "back"}}))
	}
	return center(theme.Panel.Width(62).Render(b.String()), width, h)
}
