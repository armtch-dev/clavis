// clavis — an sshs-style SSH connection manager with an encrypted vault,
// live reachability probes, and guarded git sync. Night Owl palette,
// same as scriptorium.
package main

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/armtch-dev/clavis/internal/cli"
	"github.com/armtch-dev/clavis/internal/config"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/theme"
	"github.com/armtch-dev/clavis/internal/tui"
	"github.com/armtch-dev/clavis/internal/vault"
)

const version = "0.1.0"

const usage = `clavis %s — SSH connection manager with an encrypted vault

usage:
  clavis                 launch the TUI
  clavis doctor          health check: key, vault, git, ssh
  clavis import [path]   import hosts from ssh_config (default ~/.ssh/config)
  clavis vault rekey     rotate the master key (re-encrypts everything)
  clavis vault reset     wipe all credentials, mint a new key (lost-key path)
  clavis version

environment:
  CLAVIS_KEY         master key (identity string)
  CLAVIS_KEY_FILE    path to a file containing the master key
  CLAVIS_CONFIG_DIR  config dir override (default ~/.config/clavis)
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "clavis:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgDir, err := config.Dir()
	if err != nil {
		return err
	}

	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "doctor":
			return cli.Doctor(os.Stdout, cfgDir)
		case "import":
			path := ""
			if len(args) > 1 {
				path = args[1]
			}
			return cli.ImportSSHConfig(os.Stdout, cfgDir, path)
		case "vault":
			if len(args) > 1 && args[1] == "rekey" {
				return cli.VaultRekey(os.Stdout, cfgDir)
			}
			if len(args) > 1 && args[1] == "reset" {
				return cli.VaultReset(os.Stdout, os.Stdin, cfgDir)
			}
			return fmt.Errorf("usage: clavis vault rekey|reset")
		case "version", "--version", "-v":
			fmt.Println("clavis", version)
			return nil
		case "--dump-frame":
			return dumpFrame(cfgDir)
		case "help", "--help", "-h":
			fmt.Printf(usage, version)
			return nil
		default:
			fmt.Printf(usage, version)
			return fmt.Errorf("unknown command %q", args[0])
		}
	}

	m, err := buildModel(cfgDir)
	if err != nil {
		return err
	}
	defer m.Close()
	// Rebase the palette's bg-relative tints onto the terminal's real
	// background before bubbletea takes over the tty (OSC 11 query).
	theme.Init()
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

// buildModel loads (or first-run initializes) everything the TUI needs.
func buildModel(cfgDir string) (*tui.Model, error) {
	cfg, err := config.Load(cfgDir)
	if err != nil {
		return nil, err
	}
	store, err := profile.LoadStore(cfgDir)
	if err != nil {
		return nil, err
	}
	scripts, err := script.LoadStore(cfgDir)
	if err != nil {
		return nil, err
	}
	freshIdentity := ""
	v, err := vault.Load(cfgDir)
	if err == vault.ErrNotInited {
		v, freshIdentity, err = vault.Init(cfgDir)
	}
	if err != nil {
		return nil, err
	}
	return tui.New(cfgDir, cfg, store, scripts, v, freshIdentity), nil
}

// dumpFrame renders a single 100x30 frame to stdout and exits — a debug hook
// so agents/tests can eyeball layout without a live TTY. It refuses to run
// on an uninitialized config dir: it must never mint a master key and print
// it into a log.
func dumpFrame(cfgDir string) error {
	if _, err := vault.Load(cfgDir); err != nil {
		return fmt.Errorf("--dump-frame needs an initialized vault (run clavis interactively first): %w", err)
	}
	m, err := buildModel(cfgDir)
	if err != nil {
		return err
	}
	defer m.Close()
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	// Optional: replay a comma-separated key sequence to preview deeper
	// screens (e.g. CLAVIS_DUMP_KEYS="a,n,y,p").
	if seq := os.Getenv("CLAVIS_DUMP_KEYS"); seq != "" {
		for _, tok := range strings.Split(seq, ",") {
			m.Update(keyMsgFor(tok))
		}
	}
	fmt.Println(m.View())
	return nil
}

func keyMsgFor(tok string) tea.KeyMsg {
	switch tok {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "ctrl+d":
		return tea.KeyMsg{Type: tea.KeyCtrlD}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tok)}
	}
}
