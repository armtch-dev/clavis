// Package profile stores SSH connection metadata in profiles.json.
// No secrets live here — passwords/keys are referenced by vault secret names
// derived from the profile ID.
package profile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/armtch-dev/clavis/internal/fstxn"
)

const storeVersion = 1

type AuthKind string

const (
	AuthPassword AuthKind = "password"
	AuthKey      AuthKind = "key"
)

type Profile struct {
	ID   string     `json:"id"`
	Name string     `json:"name"`
	Host string     `json:"host"` // DNS name or IP
	Port int        `json:"port"`
	User string     `json:"user"`
	Auth []AuthKind `json:"auth"` // which credentials exist in the vault
	// IdentityID binds this profile to a reusable identity; when set, the
	// identity supplies the username, auth kinds, and vault secrets, and the
	// profile's own User/Auth may be empty.
	IdentityID string `json:"identity_id,omitempty"`
	ProxyJump  string `json:"proxy_jump,omitempty"`
	// Category is the list's grouping bucket ("cloud", "local", "work") — a
	// single label, deliberately separate from Tags: tags are free-form
	// labels used for filtering and script matching, the category is where
	// the host lives in the list.
	Category string   `json:"category,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`
	// HostKeyFP is the pinned SHA256 fingerprint recorded on first successful
	// connection (TOFU). A later mismatch triggers a loud MITM warning.
	HostKeyFP string `json:"host_key_fp,omitempty"`
	// HostKey is the full pinned public key (authorized_keys format) so
	// external ssh sessions can be given a strict known_hosts file.
	HostKey   string `json:"host_key,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// Vault secret names for this profile.
func (p *Profile) PassSecret() string       { return p.ID + ".pass" }
func (p *Profile) KeySecret() string        { return p.ID + ".sshkey" }
func (p *Profile) PassphraseSecret() string { return p.ID + ".passphrase" }

func (p *Profile) HasAuth(k AuthKind) bool {
	for _, a := range p.Auth {
		if a == k {
			return true
		}
	}
	return false
}

func (p *Profile) Addr() string { return net.JoinHostPort(p.Host, fmt.Sprintf("%d", p.Port)) }

type Store struct {
	revision fstxn.Revision
	Path     string    `json:"-"`
	Version  int       `json:"version"`
	Profiles []Profile `json:"profiles"`
}

func LoadStore(configDir string) (*Store, error) {
	l, err := fstxn.Acquire(configDir)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return LoadStoreLocked(l)
}

// LoadStoreLocked reads under caller-owned config-directory coordination.
func LoadStoreLocked(l *fstxn.Lock) (*Store, error) {
	s := &Store{Path: filepath.Join(l.Dir(), "profiles.json")}
	raw, err := l.ReadFile("profiles.json")
	if err != nil {
		if os.IsNotExist(err) {
			s.Version = storeVersion
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("profiles.json is corrupt: %w", err)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	s.revision = fstxn.RevisionOf(raw)
	return s, nil
}

// Shared by loading and serialization so a saved store is always loadable.
func (s *Store) validate() error {
	if s.Version != storeVersion {
		return fmt.Errorf("unsupported profiles.json version %d", s.Version)
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for i := range s.Profiles {
		p := &s.Profiles[i]
		if err := ValidateID(p.ID); err != nil {
			return err
		}
		if err := Validate(p); err != nil {
			return fmt.Errorf("profile %s: %w", p.ID, err)
		}
		name := strings.ToLower(p.Name)
		id := strings.ToLower(p.ID)
		if ids[id] || names[name] {
			return fmt.Errorf("duplicate profile ID/name %q", p.ID)
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

func (s *Store) CheckCurrentLocked(l *fstxn.Lock) error { return s.revision.Check(l, "profiles.json") }

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

// Change serializes metadata for a caller-owned metadata+secret transaction.
// It does not acquire a lock or write to disk. Publish drafts only after Apply.
func (s *Store) Change() (fstxn.Change, error) {
	if err := s.validate(); err != nil {
		return fstxn.Change{}, err
	}
	sort.Slice(s.Profiles, func(i, j int) bool {
		return strings.ToLower(s.Profiles[i].Name) < strings.ToLower(s.Profiles[j].Name)
	})
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fstxn.Change{}, err
	}
	return fstxn.Change{Path: "profiles.json", Data: raw}, nil
}

func (s *Store) ByID(id string) *Profile {
	for i := range s.Profiles {
		if s.Profiles[i].ID == id {
			return &s.Profiles[i]
		}
	}
	return nil
}

func (s *Store) ByName(name string) *Profile {
	for i := range s.Profiles {
		if strings.EqualFold(s.Profiles[i].Name, name) {
			return &s.Profiles[i]
		}
	}
	return nil
}

// Add validates and appends. The caller stores credentials in the vault
// under p.PassSecret()/p.KeySecret() afterwards.
func (s *Store) Add(p Profile) (*Profile, error) {
	if p.ID == "" {
		p.ID = NewID()
	}
	if err := Validate(&p); err != nil {
		return nil, err
	}
	for _, other := range s.Profiles {
		if strings.EqualFold(other.ID, p.ID) {
			return nil, fmt.Errorf("duplicate profile ID %q", p.ID)
		}
	}
	if s.ByName(p.Name) != nil {
		return nil, fmt.Errorf("a profile named %q already exists", p.Name)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	p.CreatedAt, p.UpdatedAt = now, now
	s.Profiles = append(s.Profiles, p)
	return &s.Profiles[len(s.Profiles)-1], nil
}

func (s *Store) Update(p Profile) error {
	cur := s.ByID(p.ID)
	if cur == nil {
		return fmt.Errorf("no profile with id %s", p.ID)
	}
	if err := Validate(&p); err != nil {
		return err
	}
	for i := range s.Profiles {
		if &s.Profiles[i] != cur && strings.EqualFold(s.Profiles[i].ID, p.ID) {
			return fmt.Errorf("duplicate profile ID %q", p.ID)
		}
	}
	if other := s.ByName(p.Name); other != nil && other.ID != p.ID {
		return fmt.Errorf("a profile named %q already exists", p.Name)
	}
	p.CreatedAt = cur.CreatedAt
	p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	*cur = p
	return nil
}

// Remove deletes the profile and returns its vault secret names so the
// caller can purge them.
func (s *Store) Remove(id string) ([]string, error) {
	for i := range s.Profiles {
		if s.Profiles[i].ID == id {
			p := s.Profiles[i]
			s.Profiles = append(s.Profiles[:i], s.Profiles[i+1:]...)
			return []string{p.PassSecret(), p.KeySecret(), p.PassphraseSecret()}, nil
		}
	}
	return nil, fmt.Errorf("no profile with id %s", id)
}

var (
	nameRe = regexp.MustCompile(`^[\pL\pN][\pL\pN ._-]*$`)
	hostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)
	userRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*\$?$|^[A-Za-z0-9._-]+$`)
)

func Validate(p *Profile) error {
	// Drafts may omit ID; Add generates it and store serialization requires it.
	if p.ID != "" {
		if err := ValidateID(p.ID); err != nil {
			return err
		}
	}
	if p.IdentityID != "" {
		if err := ValidateID(p.IdentityID); err != nil {
			return err
		}
	}
	if err := validateAuth(p.Auth); err != nil {
		return err
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Host = strings.TrimSpace(p.Host)
	p.User = strings.TrimSpace(p.User)
	if err := ValidateName(p.Name); err != nil {
		return err
	}
	if err := ValidateHost(p.Host); err != nil {
		return err
	}
	if p.Port == 0 {
		p.Port = 22
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("port must be 1-65535")
	}
	// An identity-backed profile takes user + auth from the identity.
	if p.IdentityID == "" {
		if err := ValidateUser(p.User); err != nil {
			return err
		}
		if len(p.Auth) == 0 {
			return errors.New("profile needs at least one auth method (password or key)")
		}
	}
	if p.ProxyJump != "" {
		if err := ValidateProxyJump(p.ProxyJump); err != nil {
			return err
		}
	}
	return nil
}

// ValidateName and ValidateUser also serve field-level editor validation.
func ValidateName(name string) error {
	if name == "" || !nameRe.MatchString(name) {
		return errors.New("name must start with a letter/number (letters, numbers, spaces, . _ -)")
	}
	return nil
}

func ValidateUser(user string) error {
	if user == "" || !userRe.MatchString(user) {
		return errors.New("user looks invalid")
	}
	return nil
}

// ValidateID accepts the existing secret-prefix format, including legacy IDs.
func ValidateID(id string) error {
	if id == "" || strings.Contains(id, "..") || !idRe.MatchString(id) {
		return fmt.Errorf("invalid metadata ID %q", id)
	}
	return nil
}

var idRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

func validateAuth(auth []AuthKind) error {
	seen := map[AuthKind]bool{}
	for _, a := range auth {
		if (a != AuthPassword && a != AuthKey) || seen[a] {
			return fmt.Errorf("invalid or duplicate auth method %q", a)
		}
		seen[a] = true
	}
	return nil
}

// ValidateHost accepts an IP (v4/v6) or a plausible DNS name.
func ValidateHost(h string) error {
	if h == "" {
		return errors.New("host is required")
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	if len(h) > 253 || !hostRe.MatchString(h) {
		return fmt.Errorf("%q is not a valid IP or DNS name", h)
	}
	return nil
}

// ValidateProxyJump accepts [user@]host[:port][,more...] like OpenSSH.
func ValidateProxyJump(pj string) error {
	for _, hop := range strings.Split(pj, ",") {
		hop = strings.TrimSpace(hop)
		if at := strings.LastIndex(hop, "@"); at >= 0 {
			hop = hop[at+1:]
		}
		if h, _, err := net.SplitHostPort(hop); err == nil {
			hop = h
		}
		if err := ValidateHost(strings.Trim(hop, "[]")); err != nil {
			return fmt.Errorf("proxy jump: %w", err)
		}
	}
	return nil
}

// NewID returns a short random hex ID; it doubles as the vault secret prefix.
func NewID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return "p" + hex.EncodeToString(b)
}
