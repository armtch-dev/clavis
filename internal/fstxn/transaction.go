// Package fstxn coordinates config-directory access and recoverable file changes.
// Callers must hold one Lock for a complete read/modify/write or sync operation.
// Locks are exclusive, cross-process, and NOT reentrant. Pass the lock to Locked
// APIs; never call an auto-locking API while holding it. A Lock is single-owner
// and must not be used concurrently. Only metadata and ciphertext belong here.
package fstxn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	lockPath    = "local/.clavis.lock"
	pendingPath = "local/.clavis-transaction.json"
	donePath    = "local/.clavis-committed.json"
	tempPath    = "local/.clavis-write.tmp"
)

var secretFileRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*\.age$`)

// Change replaces a regular file with Data (0600), or removes it when Delete is
// true. Path is a clean config-relative path. Data must be non-secret JSON
// metadata or age ciphertext; plaintext credentials must be encrypted first.
type Change struct {
	Path   string `json:"path"`
	Data   []byte `json:"data,omitempty"`
	Delete bool   `json:"delete,omitempty"`
}

type journal struct {
	Version int      `json:"version"`
	Before  []Change `json:"before"`
	After   []Change `json:"after"`
}

type Lock struct {
	dir   string
	root  *os.Root
	file  *os.File
	fault func(string) error // Per-owner IO boundary injection for recovery tests.
}

// Acquire creates private support files under local/ (already gitignored),
// obtains an advisory flock, and recovers an abandoned transaction BEFORE return.
// Keep local/.clavis.lock in place: unlinking it would split lock ownership.
func Acquire(dir string) (*Lock, error) {
	return AcquireContext(context.Background(), dir)
}

var ErrBusy = errors.New("config directory is busy")

// TryAcquire never waits for another owner. Recovery still completes before return.
func TryAcquire(dir string) (*Lock, error) {
	return acquire(context.Background(), dir, false)
}

// AcquireContext preserves Acquire's recovery/ownership contract, but cancels waiting.
func AcquireContext(ctx context.Context, dir string) (*Lock, error) {
	return acquire(ctx, dir, true)
}

func acquire(ctx context.Context, dir string, wait bool) (*Lock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("unsafe config directory %s", abs)
	}
	r, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	l := &Lock{dir: abs, root: r}
	if err := l.ensureDir("local"); err != nil {
		r.Close()
		return nil, err
	}
	if err := l.check(lockPath); err != nil {
		r.Close()
		return nil, err
	}
	f, err := r.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		r.Close()
		return nil, err
	}
	l.file = f
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			l.Close()
			return nil, err
		}
		if !wait {
			l.Close()
			return nil, ErrBusy
		}
		select {
		case <-ctx.Done():
			l.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := l.recover(); err != nil {
		l.Close()
		return nil, fmt.Errorf("storage recovery: %w", err)
	}
	return l, nil
}

func (l *Lock) Dir() string { return l.dir }

// Close releases ownership. It is idempotent, but must not race other methods.
func (l *Lock) Close() error {
	if l.file == nil {
		return nil
	}
	err := errors.Join(unix.Flock(int(l.file.Fd()), unix.LOCK_UN), l.file.Close(), l.root.Close())
	l.file, l.root = nil, nil
	return err
}

func (l *Lock) step(s string) error {
	if l.fault != nil {
		return l.fault(s)
	}
	return nil
}

// check rejects symlinks in every component, non-regular targets, and traversal.
// os.Root additionally prevents escape if a noncooperating writer races checks.
func (l *Lock) check(path string) error {
	if l.root == nil {
		return errors.New("storage lock is closed")
	}
	if !fs.ValidPath(path) || strings.Contains(path, "\\") {
		return fmt.Errorf("unsafe path %q", path)
	}
	parts := strings.Split(path, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		fi, err := l.root.Lstat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !fi.IsDir()) || (i == len(parts)-1 && !fi.Mode().IsRegular()) {
			return fmt.Errorf("unsafe non-regular path %q", p)
		}
	}
	return nil
}

func (l *Lock) ensureDir(dir string) error {
	if dir == "." {
		return nil
	}
	// Check using a nonexistent regular leaf so all directory components are checked.
	if err := l.check(dir + "/.clavis-directory-check"); err != nil {
		return err
	}
	parts := strings.Split(dir, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		if err := l.root.Mkdir(p, 0700); err != nil {
			if !os.IsExist(err) {
				return err
			}
		} else if err := l.syncDir(filepath.ToSlash(filepath.Dir(p))); err != nil {
			return err
		}
	}
	return nil
}

func (l *Lock) ReadFile(path string) ([]byte, error) {
	if err := l.check(path); err != nil {
		return nil, err
	}
	f, err := l.root.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ReadDir rejects a symlink directory and returns its immediate entries. File
// contents must still be read through ReadFile to reject symlink entries.
func (l *Lock) ReadDir(path string) ([]os.DirEntry, error) {
	if err := l.check(path + "/.clavis-directory-check"); err != nil {
		return nil, err
	}
	f, err := l.root.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

func validate(c Change) error {
	if !fs.ValidPath(c.Path) || strings.Contains(c.Path, "\\") {
		return fmt.Errorf("unsafe transaction path %q", c.Path)
	}
	metadata := false
	switch c.Path {
	case "profiles.json", "identities.json", "scripts.json", "config.json", "vault.meta", "local/fido2.json":
		metadata = true
	default:
		parts := strings.Split(c.Path, "/")
		if len(parts) != 2 || (parts[0] != "vault" && parts[0] != "local") {
			return fmt.Errorf("unsupported transaction path %q", c.Path)
		}
		// Recognize every casing of the hardware envelope, including its suffix,
		// while still requiring an ASCII basename. Normalize only for validation;
		// preserve the actual legacy directory entry for installation/restoration.
		name := parts[1]
		if strings.EqualFold(c.Path, "local/master-key.fido2.age") {
			name = name[:len(name)-len(".age")] + ".age"
		}
		if !secretFileRe.MatchString(name) || strings.Contains(name, "..") {
			return fmt.Errorf("unsupported transaction path %q", c.Path)
		}
	}
	if c.Delete {
		if len(c.Data) != 0 {
			return errors.New("delete change contains data")
		}
		return nil
	}
	if metadata {
		if !json.Valid(c.Data) {
			return fmt.Errorf("%s: metadata must be JSON", c.Path)
		}
	} else if !bytes.HasPrefix(c.Data, []byte("age-encryption.org/v1\n")) {
		return fmt.Errorf("%s: refusing non-age secret", c.Path)
	}
	return nil
}

// Apply durably stages all before/after images, installs the replacements, and
// commits. Errors before commit roll back; failed rollback retains the journal
// and blocks future access until recovery succeeds. A crash before the durable
// commit marker rolls back on Acquire. The last committed journal is retained
// across reads/loads for explicit RestoreLast, including ambiguous commit IO
// failures. The next nonempty mutation retires this previous recovery backup.
// After an error, close and reacquire before consuming metadata: recovery itself
// may have failed, leaving before-images in the journal and mixed live files.
// ponytail: whole before/after images are held in memory; use separate journal
// blobs only if vault size makes these bounded-to-the-transaction copies costly.
func (l *Lock) Apply(changes []Change) error {
	if err := l.recover(); err != nil {
		return err
	}
	if len(changes) == 0 {
		return nil
	}
	j := journal{Version: 1, After: changes}
	seen := map[string]bool{}
	for _, c := range changes {
		if err := validate(c); err != nil {
			return err
		}
		// ASCII paths use a conservative policy on every filesystem: case-only
		// aliases may not name multiple targets in one transaction.
		key := strings.ToLower(c.Path)
		if seen[key] {
			return fmt.Errorf("duplicate transaction path %s", c.Path)
		}
		seen[key] = true
		raw, err := l.ReadFile(c.Path)
		old := Change{Path: c.Path, Data: raw}
		if os.IsNotExist(err) {
			old.Delete = true
		} else if err != nil {
			return err
		}
		if err := validate(old); err != nil {
			return fmt.Errorf("cannot back up %s: %w", c.Path, err)
		}
		j.Before = append(j.Before, old)
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	// All validation precedes retirement. The current generation is still live;
	// its own before-images are staged below before any target is modified.
	if err := l.remove(donePath); err != nil {
		return err
	}
	if err := l.write(pendingPath, raw); err != nil {
		return errors.Join(err, l.recover())
	}
	for _, c := range changes {
		if err := l.install(c); err != nil {
			return errors.Join(err, l.recover())
		}
	}
	if err := l.step("commit"); err != nil {
		return errors.Join(err, l.recover())
	}
	if err := l.root.Rename(pendingPath, donePath); err != nil {
		return errors.Join(err, l.recover())
	}
	if err := l.syncDir("local"); err != nil {
		// The commit was not acknowledged as durable: restore the rollback marker.
		if e := l.root.Rename(donePath, pendingPath); e != nil {
			return errors.Join(err, e)
		}
		// Make the rollback decision durable BEFORE restoring any target. A
		// second IO failure leaves the complete journal for subsequent recovery.
		if e := l.syncDir("local"); e != nil {
			return errors.Join(err, e)
		}
		return errors.Join(err, l.recover())
	}
	return nil
}

// RestoreLast explicitly restores the last transaction's before-images as a
// new recoverable transaction. Use only by deliberate recovery choice, before
// another mutation replaces the backup. Reload all in-memory stores/vault state
// afterwards. For a rekey rollback the old key is required to decrypt the result.
// An absent backup returns an error matching os.ErrNotExist. This does not lock.
func (l *Lock) RestoreLast() error {
	if err := l.recover(); err != nil {
		return err
	}
	raw, err := l.ReadFile(donePath)
	if err != nil {
		return err
	}
	var j journal
	if err := json.Unmarshal(raw, &j); err != nil {
		return err
	}
	return l.Apply(j.Before)
}

func (l *Lock) recover() error {
	// No target is modified until pendingPath is fully durable. This scratch
	// file is therefore disposable, including after an interrupted rollback.
	if err := l.remove(tempPath); err != nil {
		return err
	}
	raw, err := l.ReadFile(pendingPath)
	committed := false
	if os.IsNotExist(err) {
		raw, err = l.ReadFile(donePath)
		if os.IsNotExist(err) {
			return nil
		}
		committed = true
	}
	if err != nil {
		return err
	}
	if !committed {
		if _, err := l.ReadFile(donePath); !os.IsNotExist(err) {
			return errors.New("conflicting transaction journals; preserve local recovery files")
		}
	}
	var j journal
	if err := json.Unmarshal(raw, &j); err != nil {
		return fmt.Errorf("corrupt transaction journal: %w", err)
	}
	if j.Version != 1 || len(j.Before) == 0 || len(j.Before) != len(j.After) {
		return errors.New("unsupported/corrupt transaction journal")
	}
	seen := map[string]bool{}
	for i, c := range j.Before {
		if err := validate(c); err != nil {
			return err
		}
		if err := validate(j.After[i]); err != nil {
			return err
		}
		key := strings.ToLower(c.Path)
		if c.Path != j.After[i].Path || seen[key] {
			return errors.New("corrupt transaction paths")
		}
		seen[key] = true
		if err := l.check(c.Path); err != nil {
			return err
		}
	}
	if committed {
		return nil
	}
	// Pending may be an unsynchronized reversal of a committed marker after
	// repeated sync failures. Make that rollback decision durable before any
	// target directory can durably receive a before-image.
	if err := l.syncDir("local"); err != nil {
		return err
	}
	for _, c := range j.Before {
		if err := l.install(c); err != nil {
			return fmt.Errorf("rollback %s: %w", c.Path, err)
		}
	}
	return l.remove(pendingPath)
}

func (l *Lock) install(c Change) error {
	if c.Delete {
		return l.remove(c.Path)
	}
	return l.write(c.Path, c.Data)
}

func (l *Lock) syncDir(path string) error {
	if err := l.step("sync-dir:" + path); err != nil {
		return err
	}
	f, err := l.root.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (l *Lock) remove(path string) error {
	if err := l.check(path); err != nil {
		return err
	}
	if _, err := l.root.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := l.step("remove:" + path); err != nil {
		return err
	}
	if err := l.root.Remove(path); err != nil {
		return err
	}
	return l.syncDir(filepath.ToSlash(filepath.Dir(path)))
}

func (l *Lock) write(path string, data []byte) error {
	if err := l.check(path); err != nil {
		return err
	}
	if err := l.ensureDir(filepath.ToSlash(filepath.Dir(path))); err != nil {
		return err
	}
	if err := l.step("write:" + path); err != nil {
		return err
	}
	f, err := l.root.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer l.root.Remove(tempPath)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := l.step("sync-file:" + path); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := l.step("rename:" + path); err != nil {
		return err
	}
	if err := l.root.Rename(tempPath, path); err != nil {
		return err
	}
	if err := l.syncDir(filepath.ToSlash(filepath.Dir(path))); err != nil {
		return err
	}
	if filepath.Dir(path) != "local" {
		return l.syncDir("local")
	}
	return nil
}
