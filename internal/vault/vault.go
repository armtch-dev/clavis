// Package vault stores secrets (SSH passwords, private keys, tokens) as
// age-encrypted files. The X25519 identity is the master key: generated once
// at install, shown to the user, and never persisted inside the config dir.
// Only the recipient (public key) is stored, so writing secrets never needs
// the identity — reading them does.
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
	"strings"
	"time"

	"filippo.io/age"
)

const (
	metaVersion = 1
	canaryText  = "clavis-canary-v1"
	// AgeHeader is the first line of every age v1 file; the gitsync plaintext
	// guard checks vault files against it before any push.
	AgeHeader = "age-encryption.org/v1"
)

var (
	ErrLocked       = errors.New("vault is locked: master key required")
	ErrWrongKey     = errors.New("this key does not match the vault (recipient mismatch)")
	ErrNotFound     = errors.New("secret not found")
	ErrNotInited    = errors.New("vault not initialized — run clavis once to set it up")
	ErrAlreadyExist = errors.New("vault already initialized")

	secretNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
)

type meta struct {
	Version   int    `json:"version"`
	Recipient string `json:"recipient"`
	Canary    string `json:"canary"` // age-encrypted canaryText, base64-free (raw file would be binary; stored hex-less via armor? no: stored as separate file)
	CreatedAt string `json:"created_at"`
}

// Vault manages two secret directories under configDir:
//   - vault/  — synced to git (encrypted)
//   - local/  — machine-only (encrypted, gitignored; e.g. GitHub PAT)
type Vault struct {
	ConfigDir string
	Dir       string // synced secrets
	LocalDir  string // machine-local secrets
	metaPath  string

	recipient *age.X25519Recipient
	identity  *age.X25519Identity
}

// Init creates a brand-new vault and returns the identity string
// (AGE-SECRET-KEY-1…) for one-time display to the user. It is never written
// to disk by clavis.
func Init(configDir string) (*Vault, string, error) {
	v := layout(configDir)
	if _, err := os.Stat(v.metaPath); err == nil {
		return nil, "", ErrAlreadyExist
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, "", err
	}
	if err := v.writeMeta(id.Recipient()); err != nil {
		return nil, "", err
	}
	v.recipient = id.Recipient()
	v.identity = id
	return v, id.String(), nil
}

// Load opens an existing vault in the locked state.
func Load(configDir string) (*Vault, error) {
	v := layout(configDir)
	raw, err := os.ReadFile(v.metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotInited
		}
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("vault.meta is corrupt: %w", err)
	}
	rec, err := age.ParseX25519Recipient(m.Recipient)
	if err != nil {
		return nil, fmt.Errorf("vault.meta recipient is corrupt: %w", err)
	}
	v.recipient = rec
	return v, nil
}

func layout(configDir string) *Vault {
	return &Vault{
		ConfigDir: configDir,
		Dir:       filepath.Join(configDir, "vault"),
		LocalDir:  filepath.Join(configDir, "local"),
		metaPath:  filepath.Join(configDir, "vault.meta"),
	}
}

func (v *Vault) writeMeta(rec *age.X25519Recipient) error {
	for _, d := range []string{v.ConfigDir, v.Dir, v.LocalDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	canary, err := encryptTo(rec, []byte(canaryText))
	if err != nil {
		return err
	}
	m := meta{
		Version:   metaVersion,
		Recipient: rec.String(),
		Canary:    base64std(canary),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(v.metaPath, raw, 0o600)
}

// Unlock verifies the identity against the stored recipient and arms decryption.
func (v *Vault) Unlock(identityStr string) error {
	id, err := age.ParseX25519Identity(strings.TrimSpace(identityStr))
	if err != nil {
		return fmt.Errorf("not a valid key: %w", err)
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

// Put encrypts and stores a synced secret. Works while locked.
func (v *Vault) Put(name string, secret []byte) error { return v.put(v.Dir, name, secret) }

// PutLocal stores a machine-local secret (never synced).
func (v *Vault) PutLocal(name string, secret []byte) error { return v.put(v.LocalDir, name, secret) }

func (v *Vault) put(dir, name string, secret []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	ct, err := encryptTo(v.recipient, secret)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, name+".age"), ct, 0o600)
}

// Get decrypts a synced secret. Requires Unlock.
func (v *Vault) Get(name string) ([]byte, error) { return v.get(v.Dir, name) }

// GetLocal decrypts a machine-local secret. Requires Unlock.
func (v *Vault) GetLocal(name string) ([]byte, error) { return v.get(v.LocalDir, name) }

func (v *Vault) get(dir, name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if v.identity == nil {
		return nil, ErrLocked
	}
	ct, err := os.ReadFile(filepath.Join(dir, name+".age"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return decryptWith(v.identity, ct)
}

func (v *Vault) Has(name string) bool {
	if checkName(name) != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(v.Dir, name+".age"))
	return err == nil
}

func (v *Vault) HasLocal(name string) bool {
	if checkName(name) != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(v.LocalDir, name+".age"))
	return err == nil
}

func (v *Vault) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(v.Dir, name+".age"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// List returns the names of all synced secrets.
func (v *Vault) List() ([]string, error) {
	ents, err := os.ReadDir(v.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".age"); ok && !e.IsDir() {
			names = append(names, n)
		}
	}
	return names, nil
}

// VerifyAll decrypts the canary and every secret in both dirs; used by doctor.
func (v *Vault) VerifyAll() error {
	if v.identity == nil {
		return ErrLocked
	}
	raw, err := os.ReadFile(v.metaPath)
	if err != nil {
		return err
	}
	var m meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	can, err := debase64(m.Canary)
	if err != nil {
		return fmt.Errorf("canary corrupt: %w", err)
	}
	pt, err := decryptWith(v.identity, can)
	if err != nil || string(pt) != canaryText {
		return fmt.Errorf("canary check failed: %v", err)
	}
	for _, dir := range []string{v.Dir, v.LocalDir} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".age") {
				continue
			}
			ct, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return err
			}
			if _, err := decryptWith(v.identity, ct); err != nil {
				return fmt.Errorf("%s: %w", e.Name(), err)
			}
		}
	}
	return nil
}

// Rekey decrypts every secret with the current identity, generates a fresh
// identity, re-encrypts everything, and returns the new identity string for
// one-time display.
func (v *Vault) Rekey() (string, error) {
	if v.identity == nil {
		return "", ErrLocked
	}
	newID, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	// Decrypt everything into memory first so a failure can't leave a
	// half-rekeyed vault.
	type entry struct {
		dir, name string
		plaintext []byte
	}
	var entries []entry
	for _, dir := range []string{v.Dir, v.LocalDir} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".age") {
				continue
			}
			ct, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return "", err
			}
			pt, err := decryptWith(v.identity, ct)
			if err != nil {
				return "", fmt.Errorf("rekey aborted, %s failed to decrypt: %w", e.Name(), err)
			}
			entries = append(entries, entry{dir, e.Name(), pt})
		}
	}
	for _, en := range entries {
		ct, err := encryptTo(newID.Recipient(), en.plaintext)
		wipe(en.plaintext)
		if err != nil {
			return "", err
		}
		if err := atomicWrite(filepath.Join(en.dir, en.name), ct, 0o600); err != nil {
			return "", err
		}
	}
	if err := v.writeMeta(newID.Recipient()); err != nil {
		return "", err
	}
	v.recipient = newID.Recipient()
	v.identity = newID
	return newID.String(), nil
}

// Reset wipes all secrets and mints a new identity — the lost-key escape
// hatch. Profile metadata is untouched; every credential must be re-entered.
func Reset(configDir string) (*Vault, string, error) {
	v := layout(configDir)
	for _, d := range []string{v.Dir, v.LocalDir} {
		if err := os.RemoveAll(d); err != nil {
			return nil, "", err
		}
	}
	if err := os.Remove(v.metaPath); err != nil && !os.IsNotExist(err) {
		return nil, "", err
	}
	return Init(configDir)
}

// --- helpers ---

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
	return io.ReadAll(r)
}

// atomicWrite writes to a temp file in the same dir then renames, so a crash
// can never leave a truncated secret, and perms are set before content lands.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// wipe zeroes a secret buffer. Best-effort: Go's GC may have copied it, but
// this shrinks the window plaintext sits in memory.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
