// Package config handles config.json (non-secret app settings) and locates
// the clavis config dir.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/armtch-dev/clavis/internal/gitsync"
)

// Config holds synced, non-secret app settings. Machine-local state (the
// keychain cache, the GitHub token, security-key enrollment) deliberately
// lives elsewhere — config.json travels through git to other machines.
type Config struct {
	Sync gitsync.Settings `json:"sync"`
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
	c := &Config{}
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
