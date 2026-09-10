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

	"github.com/armtch-dev/clavis/internal/fstxn"
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
	revision   fstxn.Revision
	Path       string     `json:"-"`
	Version    int        `json:"version"`
	Identities []Identity `json:"identities"`
}

func LoadIdentities(configDir string) (*IdentityStore, error) {
	l, err := fstxn.Acquire(configDir)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return LoadIdentitiesLocked(l)
}

func LoadIdentitiesLocked(l *fstxn.Lock) (*IdentityStore, error) {
	s := &IdentityStore{Path: filepath.Join(l.Dir(), "identities.json")}
	raw, err := l.ReadFile("identities.json")
	if err != nil {
		if os.IsNotExist(err) {
			s.Version = storeVersion
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("identities.json is corrupt: %w", err)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	s.revision = fstxn.RevisionOf(raw)
	return s, nil
}

func (s *IdentityStore) validate() error {
	if s.Version != storeVersion {
		return fmt.Errorf("unsupported identities.json version %d", s.Version)
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for j := range s.Identities {
		i := &s.Identities[j]
		if err := ValidateID(i.ID); err != nil {
			return err
		}
		if err := ValidateIdentity(i); err != nil {
			return fmt.Errorf("identity %s: %w", i.ID, err)
		}
		name := strings.ToLower(i.Name)
		id := strings.ToLower(i.ID)
		if ids[id] || names[name] {
			return fmt.Errorf("duplicate identity ID/name %q", i.ID)
		}
		ids[id], names[name] = true, true
	}
	return nil
}

func (s *IdentityStore) Save() error {
	l, err := fstxn.Acquire(filepath.Dir(s.Path))
	if err != nil {
		return err
	}
	defer l.Close()
	return s.SaveLocked(l)
}

func (s *IdentityStore) CheckCurrentLocked(l *fstxn.Lock) error {
	return s.revision.Check(l, "identities.json")
}

func (s *IdentityStore) SaveLocked(l *fstxn.Lock) error {
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
func (s *IdentityStore) Change() (fstxn.Change, error) {
	if err := s.validate(); err != nil {
		return fstxn.Change{}, err
	}
	sort.Slice(s.Identities, func(i, j int) bool {
		return strings.ToLower(s.Identities[i].Name) < strings.ToLower(s.Identities[j].Name)
	})
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fstxn.Change{}, err
	}
	return fstxn.Change{Path: "identities.json", Data: raw}, nil
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
	for _, other := range s.Identities {
		if strings.EqualFold(other.ID, i.ID) {
			return nil, fmt.Errorf("duplicate identity ID %q", i.ID)
		}
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
	for j := range s.Identities {
		if &s.Identities[j] != cur && strings.EqualFold(s.Identities[j].ID, i.ID) {
			return fmt.Errorf("duplicate identity ID %q", i.ID)
		}
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
	if i.ID != "" {
		if err := ValidateID(i.ID); err != nil {
			return err
		}
	}
	if err := validateAuth(i.Auth); err != nil {
		return err
	}
	i.Name = strings.TrimSpace(i.Name)
	i.User = strings.TrimSpace(i.User)
	if err := ValidateName(i.Name); err != nil {
		return err
	}
	if err := ValidateUser(i.User); err != nil {
		return err
	}
	if len(i.Auth) == 0 {
		return errors.New("identity needs at least one auth method (password or key)")
	}
	return nil
}
