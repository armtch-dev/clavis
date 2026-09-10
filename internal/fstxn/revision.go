package fstxn

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
)

var ErrStale = errors.New("files changed on disk; reload before saving")

// Revision is an optimistic read version, not a lock. Its zero value means absent.
// Check and Apply must occur under the SAME exclusive lock.
type Revision struct {
	sum    [32]byte
	exists bool
}

func RevisionOf(raw []byte) Revision {
	if raw == nil {
		return Revision{}
	}
	return Revision{sum: sha256.Sum256(raw), exists: raw != nil}
}

func (r Revision) Check(l *Lock, path string) error {
	raw, err := l.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if r != RevisionOf(raw) {
		return fmt.Errorf("%s: %w", path, ErrStale)
	}
	return nil
}
