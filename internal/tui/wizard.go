package tui

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshx"
	"github.com/armtch-dev/clavis/internal/theme"
)

// wizard steps, in order; some are skipped depending on earlier answers.
type wstep int

const (
	stepName wstep = iota
	stepHost
	stepPort
	stepUser
	stepUsePassword // y/n
	stepPassword
	stepUseKey // y/n
	stepKeyPath
	stepPassphrase
	stepProxyJump
	stepTags
	stepTest
)

var stepTitles = map[wstep]string{
	stepName:        "Profile name",
	stepHost:        "Server DNS address or IP",
	stepPort:        "SSH port",
	stepUser:        "User",
	stepUsePassword: "Use a password?",
	stepPassword:    "Password",
	stepUseKey:      "Use an SSH key?",
	stepKeyPath:     "Path to the private key file",
	stepPassphrase:  "Key passphrase",
	stepProxyJump:   "ProxyJump (optional)",
	stepTags:        "Tags (optional, space-separated)",
	stepTest:        "Connection test",
}

type wizardModel struct {
	app     *Model
	editing bool
	draft   profile.Profile

	step  wstep
	input textinput.Model
	errs  string

	usePassword, useKey bool
	password            string
	keyPEM              []byte
	passphrase          string
	keyNeedsPassphrase  bool

	awaitingTest bool
	testResult   *sshx.TestResult
	tested       bool
}

func newWizard(app *Model, edit *profile.Profile) *wizardModel {
	w := &wizardModel{app: app}
	if edit != nil {
		w.editing = true
		w.draft = *edit
		w.usePassword = edit.HasAuth(profile.AuthPassword)
		w.useKey = edit.HasAuth(profile.AuthKey)
	} else {
		w.draft = profile.Profile{ID: profile.NewID(), Port: 22}
	}
	w.setStep(stepName)
	return w
}

func (w *wizardModel) setStep(s wstep) {
	w.step = s
	w.errs = ""
	ti := textinput.New()
	ti.Prompt = "▸ "
	ti.PromptStyle = theme.Accent
	ti.TextStyle = theme.Value
	ti.Focus()
	switch s {
	case stepName:
		ti.SetValue(w.draft.Name)
	case stepHost:
		ti.SetValue(w.draft.Host)
	case stepPort:
		ti.SetValue(strconv.Itoa(w.draft.Port))
	case stepUser:
		ti.SetValue(w.draft.User)
	case stepPassword:
		ti.EchoMode = textinput.EchoPassword
		if w.editing && w.app.vault.Has(w.draft.PassSecret()) {
			ti.Placeholder = "leave empty to keep the stored password"
		}
	case stepKeyPath:
		if w.editing && w.app.vault.Has(w.draft.KeySecret()) {
			ti.Placeholder = "leave empty to keep the stored key"
		} else {
			ti.Placeholder = "~/.ssh/id_ed25519"
		}
	case stepPassphrase:
		ti.EchoMode = textinput.EchoPassword
	case stepProxyJump:
		ti.SetValue(w.draft.ProxyJump)
		ti.Placeholder = "user@bastion.example.com:22 — enter to skip"
	case stepTags:
		ti.SetValue(strings.Join(w.draft.Tags, " "))
	}
	w.input = ti
}

// next returns the step after s, honoring skip rules.
func (w *wizardModel) next(s wstep) wstep {
	n := s + 1
	switch n {
	case stepPassword:
		if !w.usePassword {
			return w.next(n)
		}
	case stepPassphrase:
		if !w.keyNeedsPassphrase {
			return w.next(n)
		}
	case stepKeyPath:
		if !w.useKey {
			return w.next(n)
		}
	}
	return n
}

func (w *wizardModel) prev(s wstep) wstep {
	if s == stepName {
		return stepName
	}
	p := s - 1
	switch p {
	case stepPassword:
		if !w.usePassword {
			return w.prev(p)
		}
	case stepPassphrase:
		if !w.keyNeedsPassphrase {
			return w.prev(p)
		}
	case stepKeyPath:
		if !w.useKey {
			return w.prev(p)
		}
	}
	return p
}

func (m *Model) updateWizard(msg tea.Msg) (tea.Model, tea.Cmd) {
	w := m.wizard
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	if key.Type == tea.KeyEsc {
		if w.step == stepName || w.awaitingTest {
			// Abandoning the wizard: drop any typed secrets with it.
			w.password, w.passphrase = "", ""
			for i := range w.keyPEM {
				w.keyPEM[i] = 0
			}
			m.wizard = nil
			m.screen = scrList
			return m, nil
		}
		w.setStep(w.prev(w.step))
		return m, nil
	}

	// y/n steps and the final test screen take single keys, not text input.
	switch w.step {
	case stepUsePassword, stepUseKey:
		switch key.String() {
		case "y", "Y":
			w.setBool(true)
		case "n", "N":
			w.setBool(false)
		}
		return m, nil
	case stepTest:
		return w.updateTest(m, key)
	}

	if key.Type == tea.KeyEnter {
		if err := w.commitStep(); err != nil {
			w.errs = err.Error()
			return m, nil
		}
		nx := w.next(w.step)
		if nx == stepTest {
			w.step = stepTest
			w.tested, w.testResult = false, nil
			return m, w.startTest(m)
		}
		w.setStep(nx)
		return m, nil
	}

	var cmd tea.Cmd
	w.input, cmd = w.input.Update(msg)
	return m, cmd
}

func (w *wizardModel) setBool(v bool) {
	if w.step == stepUsePassword {
		w.usePassword = v
	} else {
		w.useKey = v
	}
	if !w.usePassword && !w.useKey && w.step == stepUseKey {
		w.errs = "pick at least one: password or key"
		w.useKey = false
		return
	}
	w.setStep(w.next(w.step))
}

// commitStep validates and stores the current text input into the draft.
func (w *wizardModel) commitStep() error {
	val := strings.TrimSpace(w.input.Value())
	switch w.step {
	case stepName:
		if val == "" {
			return fmt.Errorf("name is required")
		}
		w.draft.Name = val
	case stepHost:
		if err := profile.ValidateHost(val); err != nil {
			return err
		}
		w.draft.Host = val
	case stepPort:
		if val == "" {
			w.draft.Port = 22
			return nil
		}
		p, err := strconv.Atoi(val)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("port must be 1-65535")
		}
		w.draft.Port = p
	case stepUser:
		if val == "" {
			return fmt.Errorf("user is required")
		}
		w.draft.User = val
	case stepPassword:
		if val == "" && !(w.editing && w.app.vault.Has(w.draft.PassSecret())) {
			return fmt.Errorf("password is required (or go back and answer n)")
		}
		w.password = val
	case stepKeyPath:
		return w.loadKey(val)
	case stepPassphrase:
		if _, err := ssh.ParsePrivateKeyWithPassphrase(w.keyPEM, []byte(val)); err != nil {
			return fmt.Errorf("passphrase does not unlock this key")
		}
		w.passphrase = val
	case stepProxyJump:
		if val != "" {
			if err := profile.ValidateProxyJump(val); err != nil {
				return err
			}
		}
		w.draft.ProxyJump = val
	case stepTags:
		w.draft.Tags = nil
		for _, t := range strings.Fields(val) {
			w.draft.Tags = append(w.draft.Tags, strings.TrimPrefix(t, "#"))
		}
	}
	return nil
}

func (w *wizardModel) loadKey(path string) error {
	if path == "" {
		if w.editing && w.app.vault.Has(w.draft.KeySecret()) {
			return nil // keep stored key
		}
		return fmt.Errorf("key path is required (or go back and answer n)")
	}
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		path = home + path[1:]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read key: %v", err)
	}
	if _, err := ssh.ParsePrivateKey(raw); err != nil {
		if strings.Contains(err.Error(), "passphrase") {
			w.keyPEM = raw
			w.keyNeedsPassphrase = true
			return nil
		}
		return fmt.Errorf("not a valid private key: %v", err)
	}
	w.keyPEM = raw
	w.keyNeedsPassphrase = false
	return nil
}

// startTest saves nothing yet — it builds creds from the draft and probes.
func (w *wizardModel) startTest(m *Model) tea.Cmd {
	w.draft.Auth = nil
	if w.usePassword {
		w.draft.Auth = append(w.draft.Auth, profile.AuthPassword)
	}
	if w.useKey {
		w.draft.Auth = append(w.draft.Auth, profile.AuthKey)
	}
	creds := sshx.Credentials{Password: w.password, PrivateKey: w.keyPEM, Passphrase: w.passphrase}
	// Edit mode with kept secrets: pull them from the vault if unlocked.
	if w.editing && m.vault.Unlocked() {
		if creds.Password == "" && w.usePassword {
			if b, err := m.vault.Get(w.draft.PassSecret()); err == nil {
				creds.Password = string(b)
			}
		}
		if len(creds.PrivateKey) == 0 && w.useKey {
			if b, err := m.vault.Get(w.draft.KeySecret()); err == nil {
				creds.PrivateKey = b
			}
			if b, err := m.vault.Get(w.draft.PassphraseSecret()); err == nil {
				creds.Passphrase = string(b)
			}
		}
	}
	if creds.Password == "" && len(creds.PrivateKey) == 0 {
		w.testResult = &sshx.TestResult{
			Stage:  sshx.StageAuth,
			Reason: "no credentials available to test (vault locked?) — you can still save",
		}
		return nil
	}
	w.awaitingTest = true
	p := w.draft
	return func() tea.Msg {
		return testDoneMsg{p.ID, sshx.Test(p, creds, testTimeout)}
	}
}

func (w *wizardModel) updateTest(m *Model, key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if w.awaitingTest {
		return m, nil // wait for the result
	}
	switch key.String() {
	case "r", "R":
		w.tested = false
		return m, w.startTest(m)
	case "enter", "s", "S":
		return w.save(m)
	case "b", "B":
		w.setStep(stepTags)
		return m, nil
	}
	return m, nil
}

func (w *wizardModel) save(m *Model) (tea.Model, tea.Cmd) {
	var saved *profile.Profile
	var err error
	if w.editing {
		err = m.store.Update(w.draft)
		saved = m.store.ByID(w.draft.ID)
	} else {
		saved, err = m.store.Add(w.draft)
	}
	if err != nil {
		w.errs = err.Error()
		w.setStep(stepName)
		return m, nil
	}
	// Secrets: recipient-only encryption, so this works even locked.
	if w.usePassword && w.password != "" {
		if err := m.vault.Put(saved.PassSecret(), []byte(w.password)); err != nil {
			m.setStatus(statusErr, "vault write failed: "+err.Error())
		}
	}
	if !w.usePassword {
		m.vault.Delete(saved.PassSecret())
	}
	if w.useKey && len(w.keyPEM) > 0 {
		m.vault.Put(saved.KeySecret(), w.keyPEM)
		if w.passphrase != "" {
			m.vault.Put(saved.PassphraseSecret(), []byte(w.passphrase))
		}
	}
	if !w.useKey {
		m.vault.Delete(saved.KeySecret())
		m.vault.Delete(saved.PassphraseSecret())
	}
	// TOFU pin from the wizard's successful test.
	if w.testResult != nil && w.testResult.OK && saved.HostKeyFP == "" {
		saved.HostKeyFP = w.testResult.HostKeyFP
		saved.HostKey = w.testResult.HostKeyLine
	}
	// Plaintext copies are no longer needed once they're in the vault.
	w.password, w.passphrase = "", ""
	for i := range w.keyPEM {
		w.keyPEM[i] = 0
	}
	w.keyPEM = nil
	m.wizard = nil
	m.screen = scrList
	m.setStatus(statusOK, "saved "+saved.Name)
	return m, m.saveAll("save profile " + saved.Name)
}

// --- view ---

func (w *wizardModel) view(width, height int) string {
	title := "Add profile"
	if w.editing {
		title = "Edit " + w.draft.Name
	}
	var b strings.Builder
	b.WriteString(theme.TitleFocused.Render(" "+title+" ") +
		theme.MutedText.Render(fmt.Sprintf("  step %d/12", int(w.step)+1)) + "\n\n")

	b.WriteString(theme.Label.Render("  "+stepTitles[w.step]) + "\n\n")

	switch w.step {
	case stepUsePassword, stepUseKey:
		b.WriteString("  " + theme.Accent.Render("y") + theme.Value.Render(" yes    ") +
			theme.Accent.Render("n") + theme.Value.Render(" no") + "\n")
	case stepTest:
		b.WriteString(w.viewTest())
	default:
		b.WriteString("  " + w.input.View() + "\n")
	}

	if w.errs != "" {
		b.WriteString("\n" + theme.StatusErr.Render("  ✗ "+w.errs) + "\n")
	}
	b.WriteString("\n" + theme.MutedText.Render("  enter next · esc back"))
	return theme.PanelBorder.Padding(1, 2).Width(min(width-2, 76)).Render(b.String())
}

func (w *wizardModel) viewTest() string {
	if w.awaitingTest {
		return "  " + theme.Accent.Render("⟳ connecting to "+w.draft.Addr()+"…") + "\n"
	}
	if w.testResult == nil {
		return ""
	}
	r := w.testResult
	var b strings.Builder
	if r.OK {
		b.WriteString("  " + theme.StatusOK.Render("✓ "+r.Reason) + "\n")
		if r.HostKeyFP != "" {
			b.WriteString("  " + theme.MutedText.Render("host key pinned: "+r.HostKeyFP) + "\n")
		}
	} else {
		b.WriteString("  " + theme.StatusErr.Render("✗ ["+string(r.Stage)+"] "+r.Reason) + "\n")
	}
	if w.draft.ProxyJump != "" {
		b.WriteString("  " + theme.StatusWarn.Render("note: test dialed directly; ProxyJump applies only to real sessions") + "\n")
	}
	b.WriteString("\n  " + theme.Accent.Render("enter") + theme.Value.Render(" save") +
		theme.Accent.Render("   r") + theme.Value.Render(" retest") +
		theme.Accent.Render("   b") + theme.Value.Render(" back") + "\n")
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
