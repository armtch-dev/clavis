package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Identity is a reusable credential set — a username plus a password and/or
// SSH key — that any number of profiles can authenticate with. Metadata only:
// the secrets live in the vault under the identity's ID.
type Identity struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	User      string     `json:"user"`
	Auth      []AuthKind `json:"auth"`
	CreatedAt string     `json:"created_at"`
	UpdatedAt string     `json:"updated_at"`
}

// Vault secret names for this identity (same scheme as Profile's).
func (i *Identity) PassSecret() string       { return i.ID + ".pass" }
func (i *Identity) KeySecret() string        { return i.ID + ".sshkey" }
func (i *Identity) PassphraseSecret() string { return i.ID + ".passphrase" }

func (i *Identity) HasAuth(k AuthKind) bool {
	for _, a := range i.Auth {
		if a == k {
			return true
		}
	}
	return false
}

// IdentityStore persists identities.json in the config dir (synced like
// profiles.json; contains no secrets).
type IdentityStore struct {
	Path       string
	Version    int        `json:"version"`
	Identities []Identity `json:"identities"`
}

func LoadIdentities(configDir string) (*IdentityStore, error) {
	s := &IdentityStore{Path: filepath.Join(configDir, "identities.json"), Version: storeVersion}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("identities.json is corrupt: %w", err)
	}
	return s, nil
}

func (s *IdentityStore) Save() error {
	sort.Slice(s.Identities, func(i, j int) bool {
		return strings.ToLower(s.Identities[i].Name) < strings.ToLower(s.Identities[j].Name)
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

func (s *IdentityStore) ByID(id string) *Identity {
	for i := range s.Identities {
		if s.Identities[i].ID == id {
			return &s.Identities[i]
		}
	}
	return nil
}

func (s *IdentityStore) ByName(name string) *Identity {
	for i := range s.Identities {
		if strings.EqualFold(s.Identities[i].Name, name) {
			return &s.Identities[i]
		}
	}
	return nil
}

// Add validates and appends. The caller stores credentials in the vault
// under i.PassSecret()/i.KeySecret() afterwards.
func (s *IdentityStore) Add(i Identity) (*Identity, error) {
	if i.ID == "" {
		i.ID = "i" + NewID()[1:] // same random hex shape, i-prefixed
	}
	if err := ValidateIdentity(&i); err != nil {
		return nil, err
	}
	if s.ByName(i.Name) != nil {
		return nil, fmt.Errorf("an identity named %q already exists", i.Name)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	i.CreatedAt, i.UpdatedAt = now, now
	s.Identities = append(s.Identities, i)
	return &s.Identities[len(s.Identities)-1], nil
}

func (s *IdentityStore) Update(i Identity) error {
	cur := s.ByID(i.ID)
	if cur == nil {
		return fmt.Errorf("no identity with id %s", i.ID)
	}
	if err := ValidateIdentity(&i); err != nil {
		return err
	}
	if other := s.ByName(i.Name); other != nil && other.ID != i.ID {
		return fmt.Errorf("an identity named %q already exists", i.Name)
	}
	i.CreatedAt = cur.CreatedAt
	i.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	*cur = i
	return nil
}

// Remove deletes the identity and returns its vault secret names so the
// caller can purge them.
func (s *IdentityStore) Remove(id string) ([]string, error) {
	for j := range s.Identities {
		if s.Identities[j].ID == id {
			i := s.Identities[j]
			s.Identities = append(s.Identities[:j], s.Identities[j+1:]...)
			return []string{i.PassSecret(), i.KeySecret(), i.PassphraseSecret()}, nil
		}
	}
	return nil, fmt.Errorf("no identity with id %s", id)
}

func ValidateIdentity(i *Identity) error {
	i.Name = strings.TrimSpace(i.Name)
	i.User = strings.TrimSpace(i.User)
	if i.Name == "" || !nameRe.MatchString(i.Name) {
		return errors.New("name must start with a letter/number (letters, numbers, spaces, . _ -)")
	}
	if i.User == "" || !userRe.MatchString(i.User) {
		return errors.New("user looks invalid")
	}
	if len(i.Auth) == 0 {
		return errors.New("identity needs at least one auth method (password or key)")
	}
	return nil
}
