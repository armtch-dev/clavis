// Package fido2 wraps the vault master key with a FIDO2 security key
// (YubiKey etc.) via the hmac-secret extension. No cgo: it shells out to
// the libfido2 CLI tools, the same way gitsync shells out to git.
//
//	fido2-token -L    — find the first connected authenticator
//	fido2-cred -M -h  — register a credential with hmac-secret enabled
//	fido2-assert -G -h — re-derive the per-credential hmac secret (touch)
//
// The derived secret never touches disk. It is used as an age scrypt
// passphrase to encrypt the identity string into
// local/master-key.fido2.age; local/fido2.json holds only non-secret
// metadata (credential id, salt, rpid). Both files are machine-local
// (local/ is gitignored by gitsync) and recreatable by re-enrolling.
package fido2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/vault"
)

const rpID = "clavis"

// meta is the on-disk schema of local/fido2.json. Nothing in it is secret:
// the salt alone is useless without the physical key, which holds the hmac
// seed the secret is derived from.
type meta struct {
	CredentialID string `json:"credential_id"` // base64, as printed by fido2-cred
	Salt         string `json:"salt"`          // base64, 32-byte hmac-secret salt
	RPID         string `json:"rpid"`
}

func metaPath(configDir string) string {
	return filepath.Join(configDir, "local", "fido2.json")
}

func keyPath(configDir string) string {
	return filepath.Join(configDir, "local", "master-key.fido2.age")
}

// Available reports whether the fido2 CLI tools are installed.
func Available() bool {
	for _, tool := range []string{"fido2-token", "fido2-cred", "fido2-assert"} {
		if _, err := exec.LookPath(tool); err != nil {
			return false
		}
	}
	return true
}

// Present reports whether a security key is currently connected.
func Present() bool {
	return PresentContext(context.Background())
}

func PresentContext(ctx context.Context) bool {
	_, err := firstDeviceContext(ctx)
	return err == nil
}

// Enrolled reports whether this machine has a security-key enrollment.
func Enrolled(configDir string) bool {
	_, errM := os.Stat(metaPath(configDir))
	entries, err := os.ReadDir(filepath.Join(configDir, "local"))
	if errM != nil || err != nil {
		return false
	}
	for _, e := range entries {
		if strings.EqualFold(e.Name(), "master-key.fido2.age") && e.Type().IsRegular() {
			return true
		}
	}
	return false
}

func envelopePathLocked(l *fstxn.Lock) (string, error) {
	entries, err := l.ReadDir("local")
	if err != nil {
		return "", err
	}
	path := ""
	for _, e := range entries {
		if strings.EqualFold(e.Name(), "master-key.fido2.age") {
			if path != "" {
				return "", fmt.Errorf("multiple case-aliased FIDO envelopes")
			}
			path = "local/" + e.Name()
		}
	}
	if path == "" {
		path = "local/master-key.fido2.age"
	}
	return path, nil
}

// run executes a fido2 tool with the given stdin lines, returning stdout.
// Only stderr goes into the error — the tools print secrets on stdout only.
func run(stdin []string, name string, args ...string) (string, error) {
	return runContext(context.Background(), stdin, name, args...)
}

func runContext(ctx context.Context, stdin []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	if stdin != nil {
		cmd.Stdin = strings.NewReader(strings.Join(stdin, "\n") + "\n")
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %v: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// firstDevice returns the first authenticator listed by `fido2-token -L`,
// which prints one device per line as "<path>: vendor=..., product=...".
func firstDevice() (string, error) {
	return firstDeviceContext(context.Background())
}

func firstDeviceContext(ctx context.Context) (string, error) {
	out, err := runContext(ctx, nil, "fido2-token", "-L")
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	dev, _, ok := strings.Cut(line, ": ")
	if !ok || dev == "" {
		return "", fmt.Errorf("no FIDO2 security key connected")
	}
	return dev, nil
}

func randB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// assert runs `fido2-assert -G -h` (the user must touch the key) and returns
// the derived hmac secret, base64 as printed.
func assert(dev, credID, salt string) (string, error) {
	return assertContext(context.Background(), dev, credID, salt)
}

func assertContext(ctx context.Context, dev, credID, salt string) (string, error) {
	cdh, err := randB64(32)
	if err != nil {
		return "", err
	}
	// fido2-assert(1) -G reads, in order: client data hash (base64),
	// relying party id, credential id (base64, non-resident), hmac salt
	// (base64, since -h is set).
	out, err := runContext(ctx, []string{cdh, rpID, credID, salt}, "fido2-assert", "-G", "-h", dev)
	if err != nil {
		return "", err
	}
	// Output: client data hash, rpid, authenticator data, signature, then —
	// our credential is non-resident, so no user id line — the hmac secret
	// last. Take the last line so a resident-key line couldn't shift it.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 5 {
		return "", fmt.Errorf("fido2-assert: unexpected output (%d lines)", len(lines))
	}
	return strings.TrimSpace(lines[len(lines)-1]), nil
}

// Enroll registers a credential on the connected security key (user must
// touch it, twice: once to create the credential, once to derive the
// secret), then stores fido2.json and master-key.fido2.age under
// <configDir>/local/.
func Enroll(configDir, identity string) error {
	return EnrollContext(context.Background(), configDir, identity)
}

func EnrollContext(ctx context.Context, configDir, identity string) error {
	dev, err := firstDeviceContext(ctx)
	if err != nil {
		return err
	}
	cdh, err := randB64(32)
	if err != nil {
		return err
	}
	userID, err := randB64(32)
	if err != nil {
		return err
	}
	salt, err := randB64(32)
	if err != nil {
		return err
	}
	// fido2-cred(1) -M reads, in order: client data hash (base64), relying
	// party id, user name, user id (base64). -h enables hmac-secret.
	out, err := runContext(ctx, []string{cdh, rpID, rpID, userID}, "fido2-cred", "-M", "-h", dev)
	if err != nil {
		return err
	}
	// Output: client data hash, rpid, format, authenticator data, credential
	// id, signature, certificate (if present). We only need line 5.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 5 {
		return fmt.Errorf("fido2-cred: unexpected output (%d lines)", len(lines))
	}
	credID := strings.TrimSpace(lines[4])

	secret, err := assertContext(ctx, dev, credID, salt)
	if err != nil {
		return err
	}
	wrapped, err := wrap(secret, identity)
	if err != nil {
		return err
	}
	mj, err := json.Marshal(meta{CredentialID: credID, Salt: salt, RPID: rpID})
	if err != nil {
		return err
	}
	// Hardware work happens without ownership. Revalidate the wrapped identity
	// under the lock so a concurrent rekey cannot install a retired enrollment.
	l, err := fstxn.AcquireContext(ctx, configDir)
	if err != nil {
		return err
	}
	defer l.Close()
	v, err := vault.LoadLocked(l)
	if err != nil {
		return err
	}
	if err := v.Unlock(identity); err != nil {
		return fmt.Errorf("vault changed during enrollment; unlock and retry: %w", err)
	}
	path, err := envelopePathLocked(l)
	if err != nil {
		return err
	}
	return l.Apply([]fstxn.Change{{Path: "local/fido2.json", Data: mj}, {Path: path, Data: wrapped}})
}

// Unlock asserts against the enrolled credential (user must touch the key),
// re-derives the hmac secret, and returns the decrypted identity string.
func Unlock(configDir string) (string, error) {
	return UnlockContext(context.Background(), configDir)
}

func UnlockContext(ctx context.Context, configDir string) (string, error) {
	l, err := fstxn.AcquireContext(ctx, configDir)
	if err != nil {
		return "", err
	}
	raw, err := l.ReadFile("local/fido2.json")
	path, pathErr := envelopePathLocked(l)
	if pathErr != nil {
		l.Close()
		return "", pathErr
	}
	ct, ctErr := l.ReadFile(path)
	l.Close()
	if err != nil {
		return "", err
	}
	if ctErr != nil {
		return "", ctErr
	}
	var m meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("fido2.json: %v", err)
	}
	dev, err := firstDeviceContext(ctx)
	if err != nil {
		return "", err
	}
	secret, err := assertContext(ctx, dev, m.CredentialID, m.Salt)
	if err != nil {
		return "", err
	}
	id, err := age.NewScryptIdentity(secret)
	if err != nil {
		return "", fmt.Errorf("fido2 unlock: %v", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		// Deliberately generic: never surface the secret or age's detail.
		return "", fmt.Errorf("security key secret does not unlock the stored master key (wrong key, or enrollment files tampered?)")
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("security key secret does not unlock the stored master key (wrong key, or enrollment files tampered?)")
	}
	l, err = fstxn.AcquireContext(ctx, configDir)
	if err != nil {
		return "", err
	}
	defer l.Close()
	if err := fstxn.RevisionOf(raw).Check(l, "local/fido2.json"); err != nil {
		return "", err
	}
	if err := fstxn.RevisionOf(ct).Check(l, path); err != nil {
		return "", err
	}
	v, err := vault.LoadLocked(l)
	if err != nil {
		return "", err
	}
	if err := v.Unlock(string(plain)); err != nil {
		return "", err
	}
	return string(plain), nil
}

// wrap encrypts the identity to the hmac secret used as an age scrypt
// passphrase. The secret is 32 random bytes, so scrypt's defaults are
// already overkill — no tuning.
func wrap(secret, identity string) ([]byte, error) {
	r, err := age.NewScryptRecipient(secret)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, identity); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Remove deletes the enrollment files (the credential on the key is
// untouched — nothing secret lives there without the salt anyway).
func Remove(configDir string) error {
	l, err := fstxn.Acquire(configDir)
	if err != nil {
		return err
	}
	defer l.Close()
	return RemoveLocked(l)
}

func RemoveLocked(l *fstxn.Lock) error {
	changes := []fstxn.Change{{Path: "local/fido2.json", Delete: true}}
	entries, err := l.ReadDir("local")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.EqualFold(e.Name(), "master-key.fido2.age") {
			changes = append(changes, fstxn.Change{Path: "local/" + e.Name(), Delete: true})
		}
	}
	return l.Apply(changes)
}
