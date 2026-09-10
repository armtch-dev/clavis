package vault

import (
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/armtch-dev/clavis/internal/fstxn"
)

// RekeyPreparation owns the directory lock until Commit or Close. Preparation
// leaves the old generation active, and retains only ciphertext changes and the
// new identity in memory. No new plaintext key is journaled or written to disk.
type RekeyPreparation struct {
	v       *Vault
	lock    *fstxn.Lock
	id      *age.X25519Identity
	changes []fstxn.Change
}

// PrepareRekey validates/decrypts the complete old generation, then encrypts a
// replacement in memory. Call Key, deliver it successfully, and let the user
// store it BEFORE calling Commit. Always defer Close to abort on output/input
// errors. Do not call auto-locking storage APIs while this object is open.
func (v *Vault) PrepareRekey() (*RekeyPreparation, error) {
	if v.identity == nil {
		return nil, ErrLocked
	}
	l, err := fstxn.Acquire(v.ConfigDir)
	if err != nil {
		return nil, err
	}
	r := &RekeyPreparation{v: v, lock: l}
	success := false
	defer func() {
		if !success {
			r.Close()
		}
	}()
	if err := v.VerifyAllLocked(l); err != nil {
		return nil, err
	}
	r.id, err = age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	paths, err := secretPaths(l, true)
	if err != nil {
		return nil, err
	}
	foundFIDO := false
	for _, p := range paths {
		if strings.EqualFold(p, fidoKeyPath) {
			foundFIDO = true
			// Preserve the actual spelling for deletion and rollback, including
			// on case-sensitive filesystems holding a legacy mixed-case entry.
			r.changes = append(r.changes, fstxn.Change{Path: p, Delete: true})
			continue
		}
		old, err := l.ReadFile(p)
		if err != nil {
			return nil, err
		}
		pt, err := decryptWith(v.identity, old)
		if err != nil {
			return nil, fmt.Errorf("rekey %s: %w", p, err)
		}
		ct, err := encryptTo(r.id.Recipient(), pt)
		wipe(pt)
		if err != nil {
			return nil, err
		}
		r.changes = append(r.changes, fstxn.Change{Path: p, Data: ct})
	}
	// FIDO wraps the OLD master key using a hardware-derived scrypt identity.
	// Retire both files in the same transaction, so rollback restores enrollment.
	if !foundFIDO {
		r.changes = append(r.changes, fstxn.Change{Path: fidoKeyPath, Delete: true})
	}
	r.changes = append(r.changes, fstxn.Change{Path: fidoMetaPath, Delete: true})
	c, err := metadataChange(r.id.Recipient())
	if err != nil {
		return nil, err
	}
	r.changes = append(r.changes, c)
	success = true
	return r, nil
}

func (r *RekeyPreparation) Key() string {
	if r.id == nil {
		return ""
	}
	return r.id.String()
}

// Commit is the caller's explicit assertion that Key was successfully delivered
// and saved. A crash after commit but before return is safe because the user
// already has the key. Without that acknowledgement, call Close instead.
// Commit closes the preparation on both success and failure; never retry it.
func (r *RekeyPreparation) Commit() error {
	if r.lock == nil || r.id == nil {
		return errors.New("rekey preparation is closed")
	}
	defer r.Close()
	if err := r.lock.Apply(r.changes); err != nil {
		return err
	}
	r.v.recipient, r.v.identity = r.id.Recipient(), r.id
	return nil
}

// Close aborts an uncommitted preparation and releases the lock (idempotent).
func (r *RekeyPreparation) Close() error {
	r.id, r.changes = nil, nil
	if r.lock == nil {
		return nil
	}
	err := r.lock.Close()
	r.lock = nil
	return err
}
