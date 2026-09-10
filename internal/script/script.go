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

	"github.com/armtch-dev/clavis/internal/fstxn"
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
	revision fstxn.Revision
	Path     string   `json:"-"`
	Version  int      `json:"version"`
	Scripts  []Script `json:"scripts"`
}

func LoadStore(configDir string) (*Store, error) {
	l, err := fstxn.Acquire(configDir)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return LoadStoreLocked(l)
}

func LoadStoreLocked(l *fstxn.Lock) (*Store, error) {
	s := &Store{Path: filepath.Join(l.Dir(), "scripts.json")}
	raw, err := l.ReadFile("scripts.json")
	if err != nil {
		if os.IsNotExist(err) {
			s.Version = storeVersion
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("scripts.json is corrupt: %w", err)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	s.revision = fstxn.RevisionOf(raw)
	return s, nil
}

func (s *Store) validate() error {
	if s.Version != storeVersion {
		return fmt.Errorf("unsupported scripts.json version %d", s.Version)
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for i := range s.Scripts {
		sc := &s.Scripts[i]
		if err := profile.ValidateID(sc.ID); err != nil {
			return err
		}
		if err := Validate(sc); err != nil {
			return fmt.Errorf("script %s: %w", sc.ID, err)
		}
		name := strings.ToLower(sc.Name)
		id := strings.ToLower(sc.ID)
		if ids[id] || names[name] {
			return fmt.Errorf("duplicate script ID/name %q", sc.ID)
		}
		ids[id], names[name] = true, true
	}
	return nil
}

func (s *Store) Save() error {
	l, err := fstxn.Acquire(filepath.Dir(s.Path))
	if err != nil {
		return err
	}
	defer l.Close()
	return s.SaveLocked(l)
}

func (s *Store) CheckCurrentLocked(l *fstxn.Lock) error { return s.revision.Check(l, "scripts.json") }

func (s *Store) SaveLocked(l *fstxn.Lock) error {
	if err := s.CheckCurrentLocked(l); err != nil {
		return err
	}
	c, err := s.Change()
	if err != nil {
		return err
	}
	if err := l.Apply([]fstxn.Change{c}); err != nil {
		return err
	}
	s.revision = fstxn.RevisionOf(c.Data)
	return nil
}

// Change returns metadata for a caller-owned transaction, without locking/writing.
func (s *Store) Change() (fstxn.Change, error) {
	if err := s.validate(); err != nil {
		return fstxn.Change{}, err
	}
	sort.Slice(s.Scripts, func(i, j int) bool {
		return strings.ToLower(s.Scripts[i].Name) < strings.ToLower(s.Scripts[j].Name)
	})
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fstxn.Change{}, err
	}
	return fstxn.Change{Path: "scripts.json", Data: raw}, nil
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
	for _, other := range s.Scripts {
		if strings.EqualFold(other.ID, sc.ID) {
			return nil, fmt.Errorf("duplicate script ID %q", sc.ID)
		}
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
	for i := range s.Scripts {
		if &s.Scripts[i] != cur && strings.EqualFold(s.Scripts[i].ID, sc.ID) {
			return fmt.Errorf("duplicate script ID %q", sc.ID)
		}
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
	if sc.ID != "" {
		if err := profile.ValidateID(sc.ID); err != nil {
			return err
		}
	}
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
