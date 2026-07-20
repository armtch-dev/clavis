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
)

const storeVersion = 1

type AuthKind string

const (
	AuthPassword AuthKind = "password"
	AuthKey      AuthKind = "key"
)

type Profile struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Host      string     `json:"host"` // DNS name or IP
	Port      int        `json:"port"`
	User      string     `json:"user"`
	Auth      []AuthKind `json:"auth"` // which credentials exist in the vault
	ProxyJump string     `json:"proxy_jump,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	Notes     string     `json:"notes,omitempty"`
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
	Path     string
	Version  int       `json:"version"`
	Profiles []Profile `json:"profiles"`
}

func LoadStore(configDir string) (*Store, error) {
	s := &Store{Path: filepath.Join(configDir, "profiles.json"), Version: storeVersion}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("profiles.json is corrupt: %w", err)
	}
	return s, nil
}

func (s *Store) Save() error {
	sort.Slice(s.Profiles, func(i, j int) bool {
		return strings.ToLower(s.Profiles[i].Name) < strings.ToLower(s.Profiles[j].Name)
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
	p.Name = strings.TrimSpace(p.Name)
	p.Host = strings.TrimSpace(p.Host)
	p.User = strings.TrimSpace(p.User)
	if p.Name == "" || !nameRe.MatchString(p.Name) {
		return errors.New("name must start with a letter/number (letters, numbers, spaces, . _ -)")
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
	if p.User == "" || !userRe.MatchString(p.User) {
		return errors.New("user looks invalid")
	}
	if len(p.Auth) == 0 {
		return errors.New("profile needs at least one auth method (password or key)")
	}
	if p.ProxyJump != "" {
		if err := ValidateProxyJump(p.ProxyJump); err != nil {
			return err
		}
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
