// Package script stores reusable remote scripts in scripts.json.
// Scripts are plain automation text, not secrets — anything secret belongs
// in the vault and should be read by the script on the remote side.
package script

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/armtch-dev/clavis/internal/profile"
)

const storeVersion = 1

type Script struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Content   string   `json:"content"`
	Tags      []string `json:"tags,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

// MatchesTags reports whether the script applies to a host carrying the given
// tags. An untagged script is universal; a tagged one needs at least one tag
// in common with the host (case-insensitive).
func (sc *Script) MatchesTags(hostTags []string) bool {
	if len(sc.Tags) == 0 {
		return true
	}
	for _, t := range sc.Tags {
		for _, h := range hostTags {
			if strings.EqualFold(t, h) {
				return true
			}
		}
	}
	return false
}

// ParseTags splits space-separated tag input the same way the profile wizard
// does: "#" prefixes stripped, blanks dropped, duplicates folded.
func ParseTags(input string) []string {
	return normTags(strings.Fields(input))
}

func normTags(tags []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range tags {
		t = strings.TrimPrefix(strings.TrimSpace(t), "#")
		key := strings.ToLower(t)
		if t == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

type Store struct {
	Path    string
	Version int      `json:"version"`
	Scripts []Script `json:"scripts"`
}

func LoadStore(configDir string) (*Store, error) {
	s := &Store{Path: filepath.Join(configDir, "scripts.json"), Version: storeVersion}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("scripts.json is corrupt: %w", err)
	}
	return s, nil
}

func (s *Store) Save() error {
	sort.Slice(s.Scripts, func(i, j int) bool {
		return strings.ToLower(s.Scripts[i].Name) < strings.ToLower(s.Scripts[j].Name)
	})
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

func (s *Store) ByID(id string) *Script {
	for i := range s.Scripts {
		if s.Scripts[i].ID == id {
			return &s.Scripts[i]
		}
	}
	return nil
}

func (s *Store) ByName(name string) *Script {
	for i := range s.Scripts {
		if strings.EqualFold(s.Scripts[i].Name, name) {
			return &s.Scripts[i]
		}
	}
	return nil
}

func (s *Store) Add(sc Script) (*Script, error) {
	if sc.ID == "" {
		sc.ID = "s" + profile.NewID()[1:] // same random hex shape, s-prefixed
	}
	if err := Validate(&sc); err != nil {
		return nil, err
	}
	if s.ByName(sc.Name) != nil {
		return nil, fmt.Errorf("a script named %q already exists", sc.Name)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	sc.CreatedAt, sc.UpdatedAt = now, now
	s.Scripts = append(s.Scripts, sc)
	return &s.Scripts[len(s.Scripts)-1], nil
}

func (s *Store) Update(sc Script) error {
	cur := s.ByID(sc.ID)
	if cur == nil {
		return fmt.Errorf("no script with id %s", sc.ID)
	}
	if err := Validate(&sc); err != nil {
		return err
	}
	if other := s.ByName(sc.Name); other != nil && other.ID != sc.ID {
		return fmt.Errorf("a script named %q already exists", sc.Name)
	}
	sc.CreatedAt = cur.CreatedAt
	sc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	*cur = sc
	return nil
}

func (s *Store) Remove(id string) error {
	for i := range s.Scripts {
		if s.Scripts[i].ID == id {
			s.Scripts = append(s.Scripts[:i], s.Scripts[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no script with id %s", id)
}

func Validate(sc *Script) error {
	sc.Name = strings.TrimSpace(sc.Name)
	sc.Tags = normTags(sc.Tags)
	if sc.Name == "" {
		return errors.New("script needs a name")
	}
	if strings.TrimSpace(sc.Content) == "" {
		return errors.New("script is empty")
	}
	return nil
}
