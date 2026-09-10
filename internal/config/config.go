// Package config handles config.json (non-secret app settings) and locates
// the clavis config dir.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/gitsync"
)

// Config holds synced, non-secret app settings. Machine-local state (the
// keychain cache, the GitHub token, security-key enrollment) deliberately
// lives elsewhere — config.json travels through git to other machines.
type Config struct {
	Sync     gitsync.Settings `json:"sync"`
	revision fstxn.Revision
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
	l, err := fstxn.Acquire(dir)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return LoadLocked(l)
}

func LoadLocked(l *fstxn.Lock) (*Config, error) {
	c := &Config{}
	raw, err := l.ReadFile("config.json")
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	c.revision = fstxn.RevisionOf(raw)
	return c, nil
}

func (c *Config) Save(dir string) error {
	l, err := fstxn.Acquire(dir)
	if err != nil {
		return err
	}
	defer l.Close()
	return c.SaveLocked(l)
}

func (c *Config) CheckCurrentLocked(l *fstxn.Lock) error { return c.revision.Check(l, "config.json") }

func (c *Config) SaveLocked(l *fstxn.Lock) error {
	if err := c.CheckCurrentLocked(l); err != nil {
		return err
	}
	change, err := c.Change()
	if err != nil {
		return err
	}
	if err := l.Apply([]fstxn.Change{change}); err != nil {
		return err
	}
	c.revision = fstxn.RevisionOf(change.Data)
	return nil
}

func (c *Config) Change() (fstxn.Change, error) {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fstxn.Change{}, err
	}
	return fstxn.Change{Path: "config.json", Data: raw}, nil
}
