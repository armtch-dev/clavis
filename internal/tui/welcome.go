package tui

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/fido2"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/gitsync"
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
	wCache          // one-time offer: cache the key in the macOS Keychain
	wEnroll         // one-time offer: enroll a connected security key
)

type welcomeModel struct {
	hasVault bool
	step     welStep
	input    textinput.Model
	url      string
	token    string // held only until it lands encrypted in local/
	key      string // held only from unlock until the local-auth offer is answered
	busy     bool
	errs     string
}

// restoreOffer picks the one-time local-auth offer shown after a successful
// restore unlock: security-key enrollment when a token is plugged in (it and
// the Keychain are either/or, and a plugged-in key signals intent), else the
// Keychain on macOS, else none. This is the only moment the pasted master
// key is in hand, so the offer happens here or never.
func restoreOffer(goos string, fidoReady bool) (welStep, bool) {
	if fidoReady {
		return wEnroll, true
	}
	if goos == "darwin" {
		return wCache, true
	}
	return wChoice, false
}

type restoreFetchedMsg struct{ err error }
type restoreSnapshotMsg struct {
	state *diskState
	err   error
}

// newTextInput is the shared prompt style for settings and welcome inputs.
// PlaceholderStyle must be set explicitly: bubbles defaults it to a fixed
// dark grey (ANSI 240) that ignores the theme and vanishes on non-dark
// backgrounds — theme.Dim follows the palette fallback instead.
func newTextInput(placeholder string, masked bool) textinput.Model {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.PromptStyle = theme.Accent
	ti.TextStyle = theme.Value
	ti.PlaceholderStyle = theme.Dim
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
	case restoreOfferMsg:
		if msg.owner != w {
			return m, nil
		}
		w.busy = false
		if step, ok := restoreOffer(runtime.GOOS, msg.ready); ok {
			w.step = step
		} else {
			m.finishRestore("")
		}
		return m, nil
	case restoreSnapshotMsg:
		w.busy = false
		if msg.err != nil {
			w.errs = msg.err.Error()
			w.step = wChoice
			return m, nil
		}
		m.applyDisk(msg.state)
		w.textStep(wKey, "AGE-SECRET-KEY-…", true)
		return m, nil
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
	case fidoEnrollMsg:
		w.busy = false
		if msg.err != nil {
			w.errs = truncErr(msg.err) // stay on the offer: retry with y, skip with n
			return m, nil
		}
		m.finishRestore(" — security key enrolled")
		return m, nil
	case tea.KeyMsg:
		return m.welcomeKey(msg)
	}
	return m, nil
}

// finishRestore drops the master key from memory and lands on the list.
func (m *Model) finishRestore(note string) {
	m.welcome.key = ""
	m.screen = scrList
	m.setStatus(statusOK, "restored from "+shortRemote(m.welcome.url)+note)
}

// reloadFetched re-reads everything the fetch may have replaced on disk.
func (m *Model) reloadFetched() error {
	l, err := fstxn.Acquire(m.cfgDir)
	if err != nil {
		return err
	}
	defer l.Close()
	s, err := loadDiskLocked(l)
	if err != nil {
		return fmt.Errorf("fetched repo is not a clavis config: %w", err)
	}
	m.applyDisk(s)
	return nil
}

func (m *Model) welcomeKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	w := m.welcome
	w.hasVault = m.vault != nil
	if w.busy {
		return m, nil
	}

	if w.step == wChoice {
		switch key.String() {
		case "u":
			if w.hasVault {
				w.step = wKey
				w.errs = ""
			}
		case "n", "N", "enter":
			if w.hasVault {
				if key.Type == tea.KeyEnter {
					w.step = wKey
					w.errs = ""
				} else {
					w.errs = "a vault is already present — press u to resume unlocking it"
				}
				return m, nil
			}
			release, err := m.mutationLock()
			if err != nil {
				w.errs = err.Error()
				return m, nil
			}
			defer release()
			v, id, err := vault.InitLocked(m.uiLock)
			if err != nil {
				w.errs = err.Error()
				return m, nil
			}
			m.vault = v
			m.firstRun = newKeyBanner(id)
			m.screen = scrFirstRun
		case "r", "R":
			w.textStep(wURL, "https://github.com/you/clavis-vault.git", false)
		case "q":
			m.quiting = true
			return m, tea.Quit
		}
		return m, nil
	}

	switch w.step {
	case wCache: // default yes: enter accepts
		switch key.String() {
		case "y", "Y", "enter":
			w.busy = true
			return m, m.hardwareCmd(&hardwareRequest{welcome: w, action: "cache"}, w.key)
		case "n", "N", "esc":
			m.finishRestore("")
		}
		return m, nil
	case wEnroll: // default no: accepting starts a hardware ceremony
		switch key.String() {
		case "y", "Y":
			w.busy, w.errs = true, ""
			return m, m.hardwareCmd(&hardwareRequest{welcome: w, action: "enroll"}, w.key)
		case "n", "N", "enter", "esc":
			m.finishRestore("")
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
			cfgBefore, profilesBefore, identsBefore, scriptsBefore := *m.cfg, *m.store, *m.idents, *m.scripts
			recipientBefore := ""
			if m.vault != nil {
				recipientBefore = m.vault.Recipient()
			}
			ctx := m.workContext
			if ctx == nil {
				ctx = context.Background()
			}
			return m, m.background(func() tea.Msg {
				ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
				defer cancel()
				l, err := fstxn.AcquireContext(ctx, dir)
				if err != nil {
					return restoreSnapshotMsg{err: err}
				}
				defer l.Close()
				for _, err := range []error{cfgBefore.CheckCurrentLocked(l), profilesBefore.CheckCurrentLocked(l), identsBefore.CheckCurrentLocked(l), scriptsBefore.CheckCurrentLocked(l)} {
					if err != nil {
						return restoreSnapshotMsg{err: err}
					}
				}
				v, loadErr := vault.LoadLocked(l)
				if recipientBefore == "" {
					if !errors.Is(loadErr, vault.ErrNotInited) {
						if loadErr != nil {
							return restoreSnapshotMsg{err: loadErr}
						}
						return restoreSnapshotMsg{err: fstxn.ErrStale}
					}
				} else if loadErr != nil {
					return restoreSnapshotMsg{err: loadErr}
				} else if v.Recipient() != recipientBefore {
					return restoreSnapshotMsg{err: fstxn.ErrStale}
				}
				c := gitsync.New(dir, val)
				c.Context = ctx
				err = c.BootstrapLocked(l, url)
				s, loadErr := loadDiskLocked(l)
				return restoreSnapshotMsg{state: s, err: errors.Join(err, loadErr)}
			}, restoreSnapshotMsg{err: context.Canceled})
		case wKey:
			if err := m.vault.Unlock(val); err != nil {
				w.errs = err.Error()
				w.input.SetValue("")
				return m, nil
			}
			if err := m.verifyVault(); err != nil {
				m.vault.Lock()
				w.errs = "vault verification failed: " + truncErr(err)
				w.input.SetValue("")
				return m, nil
			}
			if err := m.mutate(func(s *diskState, l *fstxn.Lock) ([]fstxn.Change, error) {
				token, err := s.vault.SecretChangeLocked(l, "github-token", []byte(w.token), true)
				if err != nil {
					return nil, err
				}
				if s.cfg.Sync.Remote == "" {
					s.cfg.Sync.Remote = w.url
				}
				c, err := s.cfg.Change()
				return []fstxn.Change{token, c}, err
			}); err != nil {
				w.errs = "restore finalization failed: " + err.Error()
				return m, nil
			}
			w.token = ""
			w.key = val
			w.busy = true
			ctx := m.networkContext()
			return m, func() tea.Msg {
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				return restoreOfferMsg{owner: w, ready: fido2.Available() && fido2.PresentContext(ctx)}
			}
		}
		return m, nil
	}

	var cmd tea.Cmd
	w.input, cmd = w.input.Update(key)
	return m, cmd
}

func (w *welcomeModel) view(spin string, width, h int, scroll ...int) string {
	pw := min(62, width-2)
	var b strings.Builder
	b.WriteString(theme.Title.Render("Welcome to clavis") + "\n\n")
	switch w.step {
	case wChoice:
		if w.hasVault {
			b.WriteString(theme.Value.Render("A vault is already present on this machine.") + "\n\n")
			b.WriteString("  " + theme.Accent.Render("u") + "  " + theme.Label.Render("resume unlocking the existing vault") + "\n")
		} else {
			b.WriteString(theme.Value.Render("No vault on this machine yet.") + "\n\n")
			b.WriteString("  " + theme.Accent.Render("n") + "  " + theme.Label.Render("new vault — generate a master key here") + "\n")
		}
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
	case wCache:
		b.WriteString(theme.StatusOK.Render("✓ vault unlocked") + "\n\n")
		b.WriteString(theme.Label.Render("Cache the master key in the macOS Keychain?") + "\n")
		b.WriteString(theme.Dim.Render("Touch ID then unlocks on this Mac — no more pasting the key.") + "\n")
		b.WriteString(theme.Dim.Render("Change your mind later in settings (k).") + "\n")
	case wEnroll:
		b.WriteString(theme.StatusOK.Render("✓ vault unlocked") + "\n\n")
		b.WriteString(theme.Label.Render("Enroll your security key for future unlocks?") + "\n")
		b.WriteString(theme.Dim.Render("Touch it when it blinks (twice). Change your mind later in settings (f).") + "\n")
	}
	if w.errs != "" {
		b.WriteString("\n" + theme.StatusErr.Render("✗ "+w.errs) + "\n")
	}
	if w.busy {
		working := " fetching…"
		if w.step == wEnroll {
			working = " touch your security key…"
		}
		b.WriteString("\n" + spin + theme.Accent.Render(working) + "\n")
	}
	b.WriteString("\n" + theme.Divider(pw-6) + "\n")
	switch w.step {
	case wChoice:
		if w.hasVault {
			b.WriteString(hintKeys([][2]string{{"u", "unlock"}, {"r", "restore"}, {"q", "quit"}}))
		} else {
			b.WriteString(hintKeys([][2]string{{"n", "new vault"}, {"r", "restore"}, {"q", "quit"}}))
		}
	case wCache:
		b.WriteString(hintKeys([][2]string{{"enter", "yes, cache it"}, {"n", "skip"}}))
	case wEnroll:
		b.WriteString(hintKeys([][2]string{{"y", "enroll"}, {"enter", "skip"}}))
	default:
		b.WriteString(hintKeys([][2]string{{"enter", "continue"}, {"esc", "back"}}))
	}
	return panelView(b.String(), width, h, pw, scrollOffset(scroll))
}

type restoreOfferMsg struct {
	owner *welcomeModel
	ready bool
}
