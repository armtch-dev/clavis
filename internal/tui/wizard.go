package tui

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
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
	stepUseKey    // y/n
	stepKeySource // paste | file
	stepKeyPaste  // textarea
	stepKeyPath   // textinput
	stepPassphrase
	stepProxyJump
	stepTags
	stepTest
)

// allSteps drives skip logic and the progress dots.
var allSteps = []wstep{
	stepName, stepHost, stepPort, stepUser,
	stepUsePassword, stepPassword,
	stepUseKey, stepKeySource, stepKeyPaste, stepKeyPath,
	stepPassphrase, stepProxyJump, stepTags, stepTest,
}

var stepTitles = map[wstep]string{
	stepName:        "Profile name",
	stepHost:        "Server DNS address or IP",
	stepPort:        "SSH port",
	stepUser:        "User",
	stepUsePassword: "Use a password?",
	stepPassword:    "Password",
	stepUseKey:      "Use an SSH key?",
	stepKeySource:   "How should the key be added?",
	stepKeyPaste:    "Paste the private key",
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
	area  textarea.Model
	errs  string

	usePassword, useKey bool
	keySource           string // "paste" | "file"
	password            string
	keyPEM              []byte
	passphrase          string
	keyNeedsPassphrase  bool

	awaitingTest bool
	testResult   *sshx.TestResult
	tested       bool
}

func newWizard(app *Model, edit *profile.Profile) *wizardModel {
	w := &wizardModel{app: app, keySource: "paste"}
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

	if s == stepKeyPaste {
		ta := textarea.New()
		ta.Placeholder = "-----BEGIN OPENSSH PRIVATE KEY-----\n…paste the whole key here…\n-----END OPENSSH PRIVATE KEY-----"
		ta.ShowLineNumbers = false
		ta.SetWidth(clamp(w.app.width-16, 28, 64))
		ta.SetHeight(clamp(w.app.height-14, 5, 9))
		ta.CharLimit = 0
		if len(w.keyPEM) > 0 {
			ta.SetValue(string(w.keyPEM))
		}
		ta.Focus()
		w.area = ta
		return
	}

	ti := textinput.New()
	ti.Prompt = "› "
	ti.PromptStyle = theme.Accent
	ti.TextStyle = theme.Value
	ti.Cursor.Style = theme.Accent
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

// skip reports whether a step doesn't apply given the answers so far.
func (w *wizardModel) skip(s wstep) bool {
	switch s {
	case stepPassword:
		return !w.usePassword
	case stepKeySource:
		return !w.useKey
	case stepKeyPaste:
		return !w.useKey || w.keySource != "paste"
	case stepKeyPath:
		return !w.useKey || w.keySource != "file"
	case stepPassphrase:
		return !w.keyNeedsPassphrase
	}
	return false
}

func (w *wizardModel) next(s wstep) wstep {
	for n := s + 1; int(n) < len(allSteps)+int(stepName); n++ {
		if !w.skip(n) {
			return n
		}
	}
	return stepTest
}

func (w *wizardModel) prev(s wstep) wstep {
	for p := s - 1; p >= stepName; p-- {
		if !w.skip(p) {
			return p
		}
	}
	return stepName
}

// sequence is the ordered list of applicable steps, for the progress dots.
func (w *wizardModel) sequence() []wstep {
	var seq []wstep
	for _, s := range allSteps {
		if !w.skip(s) {
			seq = append(seq, s)
		}
	}
	return seq
}

func (m *Model) updateWizard(msg tea.Msg) (tea.Model, tea.Cmd) {
	w := m.wizard
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		if w.step == stepKeyPaste {
			var cmd tea.Cmd
			w.area, cmd = w.area.Update(msg)
			return m, cmd
		}
		return m, nil
	}

	if key.Type == tea.KeyEsc {
		if w.step == stepName || w.awaitingTest {
			w.wipeSecrets()
			m.wizard = nil
			m.screen = scrList
			return m, nil
		}
		w.setStep(w.prev(w.step))
		return m, nil
	}

	// Choice steps take single keys.
	switch w.step {
	case stepUsePassword, stepUseKey:
		switch key.String() {
		case "y", "Y":
			w.setBool(true)
		case "n", "N":
			w.setBool(false)
		}
		return m, nil
	case stepKeySource:
		switch key.String() {
		case "p", "P":
			w.keySource = "paste"
			w.setStep(w.next(w.step))
		case "f", "F":
			w.keySource = "file"
			w.setStep(w.next(w.step))
		}
		return m, nil
	case stepTest:
		return w.updateTest(m, key)
	}

	// Paste step: textarea owns input; ctrl+d confirms.
	if w.step == stepKeyPaste {
		if key.Type == tea.KeyCtrlD {
			if err := w.commitStep(); err != nil {
				w.errs = err.Error()
				return m, nil
			}
			w.setStep(w.next(w.step))
			return m, nil
		}
		var cmd tea.Cmd
		w.area, cmd = w.area.Update(msg)
		return m, cmd
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

// commitStep validates and stores the current input into the draft.
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
	case stepKeyPaste:
		raw := []byte(w.area.Value())
		if len(strings.TrimSpace(string(raw))) == 0 {
			if w.editing && w.app.vault.Has(w.draft.KeySecret()) {
				return nil // keep stored key
			}
			return fmt.Errorf("paste a private key, or press esc and choose 'from file'")
		}
		return w.acceptKey(raw)
	case stepKeyPath:
		return w.loadKeyFile(val)
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

// acceptKey validates a private key blob (pasted or read from a file) and
// records whether it needs a passphrase.
func (w *wizardModel) acceptKey(raw []byte) error {
	if _, err := ssh.ParsePrivateKey(raw); err != nil {
		if strings.Contains(err.Error(), "passphrase") {
			w.keyPEM = raw
			w.keyNeedsPassphrase = true
			return nil
		}
		return fmt.Errorf("not a valid private key (need PEM/OpenSSH format)")
	}
	w.keyPEM = raw
	w.keyNeedsPassphrase = false
	return nil
}

func (w *wizardModel) loadKeyFile(path string) error {
	if path == "" {
		if w.editing && w.app.vault.Has(w.draft.KeySecret()) {
			return nil
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
	return w.acceptKey(raw)
}

func (w *wizardModel) wipeSecrets() {
	w.password, w.passphrase = "", ""
	for i := range w.keyPEM {
		w.keyPEM[i] = 0
	}
	w.keyPEM = nil
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
		return m, nil
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
	if w.testResult != nil && w.testResult.OK && saved.HostKeyFP == "" {
		saved.HostKeyFP = w.testResult.HostKeyFP
		saved.HostKey = w.testResult.HostKeyLine
	}
	w.wipeSecrets()
	m.wizard = nil
	m.screen = scrList
	m.setStatus(statusOK, "saved "+saved.Name)
	return m, m.saveAll("save profile " + saved.Name)
}

// --- view ---

func (w *wizardModel) view(width, height int) string {
	inner := min(width-6, 72)
	if inner < 30 {
		inner = 30
	}
	dw := inner - 6 // content width inside the panel's horizontal padding

	title := "New profile"
	if w.editing {
		title = "Edit " + w.draft.Name
	}

	var b strings.Builder
	b.WriteString(theme.Title.Render(title) + "\n")
	b.WriteString(w.progress(inner) + "\n\n")
	b.WriteString(theme.Label.Render(stepIcon(w.step)+stepTitles[w.step]) + "\n\n")

	switch w.step {
	case stepUsePassword, stepUseKey:
		b.WriteString(choiceRow([][2]string{{"y", "yes"}, {"n", "no"}}))
	case stepKeySource:
		b.WriteString(choiceRow([][2]string{{"p", "paste key"}, {"f", "from file"}}))
		b.WriteString("\n\n" + theme.Hint.Render("Pasted keys are encrypted straight into the vault — the\noriginal file is never referenced again."))
	case stepKeyPaste:
		b.WriteString(w.area.View())
	case stepTest:
		b.WriteString(w.viewTest())
	default:
		b.WriteString(w.input.View())
	}

	if w.errs != "" {
		b.WriteString("\n\n" + theme.StatusErr.Render("✗ "+w.errs))
	}
	b.WriteString("\n\n" + theme.Divider(dw))
	b.WriteString("\n" + w.footer())

	return center(theme.Panel.Width(inner).Render(b.String()), width, height)
}

// progress renders the applicable steps as matte dots.
func (w *wizardModel) progress(width int) string {
	seq := w.sequence()
	var parts []string
	for _, s := range seq {
		switch {
		case s == w.step:
			parts = append(parts, theme.Accent.Render("●"))
		case s < w.step:
			parts = append(parts, theme.Dim.Render("●"))
		default:
			parts = append(parts, theme.Hint.Render("·"))
		}
	}
	cur := 1
	for i, s := range seq {
		if s == w.step {
			cur = i + 1
			break
		}
	}
	counter := theme.Hint.Render(fmt.Sprintf("step %d of %d", cur, len(seq)))
	return strings.Join(parts, " ") + "  " + counter
}

func (w *wizardModel) footer() string {
	switch w.step {
	case stepUsePassword, stepUseKey, stepKeySource:
		return theme.Hint.Render("choose a key · esc back")
	case stepKeyPaste:
		return theme.Hint.Render("ctrl+d save key · esc back")
	case stepTest:
		return "" // test screen prints its own actions
	default:
		return theme.Hint.Render("enter next · esc back")
	}
}

func (w *wizardModel) viewTest() string {
	if w.awaitingTest {
		return w.app.spin.View() + " " + theme.Accent.Render("connecting to "+w.draft.Addr()+" …")
	}
	if w.testResult == nil {
		return ""
	}
	r := w.testResult
	var b strings.Builder
	if r.OK {
		b.WriteString(theme.StatusOK.Render("✓ " + r.Reason))
		if r.HostKeyFP != "" {
			b.WriteString("\n" + theme.Dim.Render("host key pinned  ") + theme.Value.Render(r.HostKeyFP))
		}
	} else {
		b.WriteString(theme.StatusErr.Render("✗ ["+string(r.Stage)+"]  ") + theme.Value.Render(r.Reason))
	}
	if w.draft.ProxyJump != "" {
		b.WriteString("\n" + theme.StatusWarn.Render("note: test dials directly; ProxyJump applies to real sessions only"))
	}
	b.WriteString("\n\n" + hintKeys([][2]string{{"enter", "save"}, {"r", "retest"}, {"b", "back"}}))
	return b.String()
}

// stepIcon prefixes auth steps with the matching uniform glyph.
func stepIcon(s wstep) string {
	switch s {
	case stepUsePassword, stepPassword:
		return theme.IconPwd + " " // "pw" is two cells wide — one space keeps alignment
	case stepUseKey, stepKeySource, stepKeyPaste, stepKeyPath, stepPassphrase:
		return theme.IconKey + "  "
	}
	return ""
}

// choiceRow renders selectable single-key options, e.g.  [y] yes   [n] no
func choiceRow(opts [][2]string) string {
	var parts []string
	for _, o := range opts {
		parts = append(parts, theme.Accent.Render(o[0])+"  "+theme.Value.Render(o[1]))
	}
	return strings.Join(parts, theme.Dim.Render("     "))
}

// hintKeys renders "key label" pairs for a footer.
func hintKeys(pairs [][2]string) string {
	var parts []string
	for _, p := range pairs {
		parts = append(parts, theme.Accent.Render(p[0])+" "+theme.Dim.Render(p[1]))
	}
	return strings.Join(parts, theme.Dim.Render("   "))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
