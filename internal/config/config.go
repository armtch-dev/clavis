// Package config handles config.json (non-secret app settings) and locates
// the clavis config dir.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/armtch-dev/clavis/internal/gitsync"
)

type Config struct {
	Sync gitsync.Settings `json:"sync"`
	// KeychainOptIn records that the user chose to cache the master key in
	// the macOS Keychain (weakens the offline-key guarantee; their call).
	KeychainOptIn bool `json:"keychain_opt_in"`
}

// Dir returns the config directory: $CLAVIS_CONFIG_DIR, else ~/.config/clavis.
func Dir() (string, error) {
	if d := os.Getenv("CLAVIS_CONFIG_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "clavis"), nil
}

func Load(dir string) (*Config, error) {
	c := &Config{Sync: gitsync.Settings{Branch: gitsync.DefaultBranch}}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	if c.Sync.Branch == "" {
		c.Sync.Branch = gitsync.DefaultBranch
	}
	return c, nil
}

func (c *Config) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "config.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
