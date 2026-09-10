// Package vault stores secrets as age-encrypted files. The X25519 identity is
// never persisted in plaintext; only its recipient and an encrypted canary are
// stored in vault.meta. Machine-local FIDO wrapping has a separate identity.
package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/armtch-dev/clavis/internal/fstxn"
)

const (
	metaVersion  = 1
	canaryText   = "clavis-canary-v1"
	AgeHeader    = "age-encryption.org/v1"
	fidoKeyPath  = "local/master-key.fido2.age"
	fidoMetaPath = "local/fido2.json"
)

var (
	ErrLocked       = errors.New("vault is locked: master key required")
	ErrWrongKey     = errors.New("this key does not match the vault (recipient mismatch)")
	ErrNotFound     = errors.New("secret not found")
	ErrNotInited    = errors.New("vault not initialized — run clavis once to set it up")
	ErrAlreadyExist = errors.New("vault already initialized")
	ErrStale        = errors.New("vault recipient changed on disk; reload and unlock before retrying")
	secretNameRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
)

type meta struct {
	Version   int    `json:"version"`
	Recipient string `json:"recipient"`
	Canary    string `json:"canary"`
	CreatedAt string `json:"created_at"`
}

// Vault is single-owner in-memory state. Disk operations acquire an exclusive
// config-directory lock; Locked variants instead require caller-owned locking.
type Vault struct {
	ConfigDir string
	Dir       string
	LocalDir  string
	metaPath  string
	recipient *age.X25519Recipient
	identity  *age.X25519Identity
}

func layout(configDir string) *Vault {
	return &Vault{ConfigDir: configDir, Dir: filepath.Join(configDir, "vault"), LocalDir: filepath.Join(configDir, "local"), metaPath: filepath.Join(configDir, "vault.meta")}
}

// Init returns a new vault and its master key for one-time display.
func Init(configDir string) (*Vault, string, error) {
	l, err := fstxn.Acquire(configDir)
	if err != nil {
		return nil, "", err
	}
	defer l.Close()
	return InitLocked(l)
}

// InitLocked initializes only an absent vault under the caller's ownership.
// It never acquires a second lock; Init remains the blocking convenience API.
func InitLocked(l *fstxn.Lock) (*Vault, string, error) {
	if _, err := l.ReadFile("vault.meta"); err == nil {
		return nil, "", ErrAlreadyExist
	} else if !os.IsNotExist(err) {
		return nil, "", err
	}
	v := layout(l.Dir())
	// Keep the existing empty directory layout. Mkdir never follows a new link.
	if _, err := l.ReadDir("vault"); os.IsNotExist(err) {
		if err := os.Mkdir(v.Dir, 0700); err != nil {
			return nil, "", err
		}
	} else if err != nil {
		return nil, "", err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, "", err
	}
	c, err := metadataChange(id.Recipient())
	if err != nil {
		return nil, "", err
	}
	if err := l.Apply([]fstxn.Change{c}); err != nil {
		return nil, "", err
	}
	v.recipient, v.identity = id.Recipient(), id
	return v, id.String(), nil
}

// Load recovers abandoned changes before reading metadata, then returns locked.
func Load(configDir string) (*Vault, error) {
	l, err := fstxn.Acquire(configDir)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return LoadLocked(l)
}

func LoadLocked(l *fstxn.Lock) (*Vault, error) {
	m, err := readMeta(l)
	if err != nil {
		return nil, err
	}
	rec, err := age.ParseX25519Recipient(m.Recipient)
	if err != nil {
		return nil, err
	}
	v := layout(l.Dir())
	v.recipient = rec
	return v, nil
}

func readMeta(l *fstxn.Lock) (meta, error) {
	var m meta
	raw, err := l.ReadFile("vault.meta")
	if os.IsNotExist(err) {
		return m, ErrNotInited
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("vault.meta is corrupt: %w", err)
	}
	if m.Version != metaVersion {
		return m, fmt.Errorf("unsupported vault.meta version %d", m.Version)
	}
	if _, err := age.ParseX25519Recipient(m.Recipient); err != nil {
		return m, fmt.Errorf("vault.meta recipient is corrupt: %w", err)
	}
	ct, err := debase64(m.Canary)
	if err != nil || !bytes.HasPrefix(ct, []byte(AgeHeader+"\n")) {
		return m, errors.New("vault.meta canary is corrupt")
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return m, errors.New("vault.meta creation date is corrupt")
	}
	return m, nil
}

func metadataChange(rec *age.X25519Recipient) (fstxn.Change, error) {
	ct, err := encryptTo(rec, []byte(canaryText))
	if err != nil {
		return fstxn.Change{}, err
	}
	raw, err := json.MarshalIndent(meta{Version: metaVersion, Recipient: rec.String(), Canary: base64std(ct), CreatedAt: time.Now().UTC().Format(time.RFC3339)}, "", "  ")
	return fstxn.Change{Path: "vault.meta", Data: raw}, err
}

// CheckCurrentLocked prevents an old in-memory recipient from writing secrets
// after another process rotates or sync replaces vault.meta. It never locks.
func (v *Vault) CheckCurrentLocked(l *fstxn.Lock) error {
	if l.Dir() != v.ConfigDir {
		return errors.New("vault and storage lock directories differ")
	}
	m, err := readMeta(l)
	if err != nil {
		return err
	}
	if v.recipient == nil || m.Recipient != v.recipient.String() {
		return ErrStale
	}
	return nil
}

func (v *Vault) Unlock(identityStr string) error {
	id, err := age.ParseX25519Identity(strings.TrimSpace(identityStr))
	if err != nil {
		return errors.New("not a valid key")
	}
	if id.Recipient().String() != v.recipient.String() {
		return ErrWrongKey
	}
	v.identity = id
	return nil
}

func (v *Vault) Unlocked() bool    { return v.identity != nil }
func (v *Vault) Recipient() string { return v.recipient.String() }
func (v *Vault) Lock()             { v.identity = nil }
func (v *Vault) Identity() (string, error) {
	if v.identity == nil {
		return "", ErrLocked
	}
	return v.identity.String(), nil
}

func secretPath(name string, local bool) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	if local && strings.EqualFold(name, "master-key.fido2") {
		return "", errors.New("FIDO master-key envelope is not a vault local secret")
	}
	dir := "vault"
	if local {
		dir = "local"
	}
	return dir + "/" + name + ".age", nil
}

// SecretChangeLocked encrypts in memory and returns a ciphertext-only change for
// a larger transaction. It verifies the on-disk recipient under the given lock.
func (v *Vault) SecretChangeLocked(l *fstxn.Lock, name string, secret []byte, local bool) (fstxn.Change, error) {
	p, err := secretPath(name, local)
	if err != nil {
		return fstxn.Change{}, err
	}
	if err := v.CheckCurrentLocked(l); err != nil {
		return fstxn.Change{}, err
	}
	ct, err := encryptTo(v.recipient, secret)
	return fstxn.Change{Path: p, Data: ct}, err
}

// DeleteChange returns a validated deletion; callers composing a transaction
// must also call CheckCurrentLocked before applying vault changes.
func DeleteChange(name string, local bool) (fstxn.Change, error) {
	p, err := secretPath(name, local)
	return fstxn.Change{Path: p, Delete: true}, err
}

func (v *Vault) Put(name string, secret []byte) error      { return v.put(name, secret, false) }
func (v *Vault) PutLocal(name string, secret []byte) error { return v.put(name, secret, true) }
func (v *Vault) put(name string, secret []byte, local bool) error {
	l, err := fstxn.Acquire(v.ConfigDir)
	if err != nil {
		return err
	}
	defer l.Close()
	c, err := v.SecretChangeLocked(l, name, secret, local)
	if err != nil {
		return err
	}
	return l.Apply([]fstxn.Change{c})
}

func (v *Vault) Get(name string) ([]byte, error)      { return v.get(name, false) }
func (v *Vault) GetLocal(name string) ([]byte, error) { return v.get(name, true) }
func (v *Vault) get(name string, local bool) ([]byte, error) {
	l, err := fstxn.Acquire(v.ConfigDir)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return v.GetLocked(l, name, local)
}

func (v *Vault) GetLocked(l *fstxn.Lock, name string, local bool) ([]byte, error) {
	p, err := secretPath(name, local)
	if err != nil {
		return nil, err
	}
	if v.identity == nil {
		return nil, ErrLocked
	}
	if err := v.CheckCurrentLocked(l); err != nil {
		return nil, err
	}
	ct, err := l.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return decryptWith(v.identity, ct)
}

func (v *Vault) Has(name string) bool      { return v.has(name, false) }
func (v *Vault) HasLocal(name string) bool { return v.has(name, true) }
func (v *Vault) has(name string, local bool) bool {
	l, err := fstxn.Acquire(v.ConfigDir)
	if err != nil {
		return false
	}
	defer l.Close()
	return v.HasLocked(l, name, local) == nil
}

// HasLocked checks for a required regular ciphertext file without unlocking.
// It returns ErrNotFound for absence and preserves unsafe-path/IO diagnostics.
func (v *Vault) HasLocked(l *fstxn.Lock, name string, local bool) error {
	p, err := secretPath(name, local)
	if err != nil {
		return err
	}
	if err := v.CheckCurrentLocked(l); err != nil {
		return err
	}
	ct, err := l.ReadFile(p)
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(ct, []byte(AgeHeader+"\n")) {
		return fmt.Errorf("%s: not age ciphertext", p)
	}
	return nil
}

func (v *Vault) Delete(name string) error {
	l, err := fstxn.Acquire(v.ConfigDir)
	if err != nil {
		return err
	}
	defer l.Close()
	if err := v.CheckCurrentLocked(l); err != nil {
		return err
	}
	c, err := DeleteChange(name, false)
	if err != nil {
		return err
	}
	return l.Apply([]fstxn.Change{c})
}

func (v *Vault) List() ([]string, error) {
	l, err := fstxn.Acquire(v.ConfigDir)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	if err := v.CheckCurrentLocked(l); err != nil {
		return nil, err
	}
	paths, err := secretPaths(l, false)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, p := range paths {
		if strings.HasPrefix(p, "vault/") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(p, "vault/"), ".age"))
		}
	}
	return names, nil
}

func secretPaths(l *fstxn.Lock, includeFIDO bool) ([]string, error) {
	var paths []string
	for _, dir := range []string{"vault", "local"} {
		entries, err := l.ReadDir(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			p := dir + "/" + e.Name()
			fido := strings.EqualFold(p, fidoKeyPath)
			if !strings.HasSuffix(e.Name(), ".age") && !fido {
				continue
			}
			if err := checkName(e.Name()[:len(e.Name())-len(".age")]); err != nil {
				return nil, err
			}
			// Includes the FIDO path in safety checks even when not decrypted.
			if _, err := l.ReadFile(p); err != nil {
				return nil, err
			}
			if !includeFIDO && fido {
				continue
			}
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// VerifyAll verifies vault-owned ciphertext only. FIDO's scrypt envelope cannot
// be authenticated with a vault identity; its hardware ceremony is separate.
func (v *Vault) VerifyAll() error {
	l, err := fstxn.Acquire(v.ConfigDir)
	if err != nil {
		return err
	}
	defer l.Close()
	return v.VerifyAllLocked(l)
}

func (v *Vault) VerifyAllLocked(l *fstxn.Lock) error {
	if v.identity == nil {
		return ErrLocked
	}
	if err := v.CheckCurrentLocked(l); err != nil {
		return err
	}
	m, err := readMeta(l)
	if err != nil {
		return err
	}
	ct, _ := debase64(m.Canary)
	pt, err := decryptWith(v.identity, ct)
	valid := string(pt) == canaryText
	wipe(pt)
	if err != nil || !valid {
		return errors.New("canary check failed")
	}
	paths, err := secretPaths(l, false)
	if err != nil {
		return err
	}
	for _, p := range paths {
		ct, err := l.ReadFile(p)
		if err != nil {
			return err
		}
		pt, err := decryptWith(v.identity, ct)
		wipe(pt)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

// Reset is the explicit lost-key escape hatch. Changes are recoverable as one
// transaction; profile metadata and the persistent lock inode are preserved.
func Reset(configDir string) (*Vault, string, error) {
	l, err := fstxn.Acquire(configDir)
	if err != nil {
		return nil, "", err
	}
	defer l.Close()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, "", err
	}
	paths, err := secretPaths(l, true)
	if err != nil {
		return nil, "", err
	}
	var changes []fstxn.Change
	for _, p := range paths {
		changes = append(changes, fstxn.Change{Path: p, Delete: true})
	}
	changes = append(changes, fstxn.Change{Path: fidoMetaPath, Delete: true})
	c, err := metadataChange(id.Recipient())
	if err != nil {
		return nil, "", err
	}
	changes = append(changes, c)
	if err := l.Apply(changes); err != nil {
		return nil, "", err
	}
	v := layout(l.Dir())
	v.recipient, v.identity = id.Recipient(), id
	return v, id.String(), nil
}

func checkName(name string) error {
	if !secretNameRe.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid secret name %q", name)
	}
	return nil
}

func encryptTo(rec age.Recipient, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rec)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decryptWith(id age.Identity, ciphertext []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, err
	}
	pt, err := io.ReadAll(r)
	if err != nil {
		wipe(pt)
		return nil, err
	}
	return pt, nil
}

// Best effort: Go may have made other copies, but don't retain plaintext buffers.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
