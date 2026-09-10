package fstxn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTransactionFaultsAndInterruptedRecovery(t *testing.T) {
	changes := []Change{{Path: "profiles.json", Data: []byte(`{"version":1,"profiles":[]}`)}, {Path: "vault/a.age", Data: []byte("age-encryption.org/v1\nnew ciphertext")}, {Path: "local/fido2.json", Delete: true}}
	seed := func(t *testing.T) (*Lock, string) {
		t.Helper()
		dir := t.TempDir()
		l, err := Acquire(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Apply([]Change{{Path: "profiles.json", Data: []byte(`{"version":1,"profiles":null}`)}, {Path: "local/fido2.json", Data: []byte(`{"old":true}`)}}); err != nil {
			t.Fatal(err)
		}
		return l, dir
	}
	l, _ := seed(t)
	var steps []string
	l.fault = func(step string) error { steps = append(steps, step); return nil }
	if err := l.Apply(changes); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if len(steps) == 0 {
		t.Fatal("no IO boundaries exercised")
	}
	for n := range steps {
		for _, crash := range []bool{false, true} {
			t.Run(steps[n]+map[bool]string{true: "/crash", false: "/error"}[crash], func(t *testing.T) {
				l, dir := seed(t)
				i := 0
				l.fault = func(string) error {
					i++
					if i == n+1 {
						if crash {
							panic("interrupted")
						}
						return errors.New("injected IO failure")
					}
					return nil
				}
				var applyErr error
				func() {
					defer func() {
						if p := recover(); p != nil && p != "interrupted" {
							panic(p)
						}
					}()
					applyErr = l.Apply(changes)
				}()
				l.Close()
				l, err := Acquire(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				p, err := l.ReadFile("profiles.json")
				if err != nil {
					t.Fatal(err)
				}
				_, secretErr := l.ReadFile("vault/a.age")
				fido, fidoErr := l.ReadFile("local/fido2.json")
				old := bytes.Equal(p, []byte(`{"version":1,"profiles":null}`)) && os.IsNotExist(secretErr) && fidoErr == nil && string(fido) == `{"old":true}`
				new := bytes.Equal(p, changes[0].Data) && secretErr == nil && os.IsNotExist(fidoErr)
				if !old && !new {
					t.Fatalf("mixed generation after recovery: metadata=%s secret=%v fido=%v", p, secretErr, fidoErr)
				}
				if applyErr != nil && !old {
					t.Fatal("IO error retired the old generation")
				}
				if err := l.Apply([]Change{{Path: "config.json", Data: []byte(`{}`)}}); err != nil {
					t.Fatalf("recovery not reusable: %v", err)
				}
			})
		}
	}
}

// Open the same lock without automatic recovery so faults can be installed at
// the startup recovery boundary. Production callers always use Acquire.
func recoveryLock(t *testing.T, dir string) *Lock {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := r.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		r.Close()
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		r.Close()
		t.Fatal(err)
	}
	l := &Lock{dir: dir, root: r, file: f}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestRecoveryDurableRollbackAfterRepeatedCommitSyncFailure(t *testing.T) {
	for _, mode := range []string{"failed barrier", "interrupted restore"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			l, err := Acquire(dir)
			if err != nil {
				t.Fatal(err)
			}
			old := []Change{{Path: "vault/a.age", Data: []byte("age-encryption.org/v1\nold")}, {Path: "vault.meta", Data: []byte(`{"generation":"old"}`)}}
			next := []Change{{Path: "vault/a.age", Data: []byte("age-encryption.org/v1\nnew")}, {Path: "vault.meta", Data: []byte(`{"generation":"new"}`)}}
			if err := l.Apply(old); err != nil {
				t.Fatal(err)
			}
			committing, syncFailures := false, 0
			l.fault = func(step string) error {
				if step == "commit" {
					committing = true
				}
				if committing && step == "sync-dir:local" {
					syncFailures++
					return errors.New("commit directory sync failed")
				}
				return nil
			}
			if err := l.Apply(next); err == nil || syncFailures != 2 {
				t.Fatalf("expected both commit/undo sync failures: %v, %d", err, syncFailures)
			}
			journalBefore, err := l.ReadFile(pendingPath)
			if err != nil {
				t.Fatal(err)
			}
			l.Close()
			l = recoveryLock(t, dir)
			rollbackDurable, mutating := false, false
			l.fault = func(step string) error {
				if strings.HasPrefix(step, "write:vault") || strings.HasPrefix(step, "remove:vault") {
					mutating = true
					if !rollbackDurable {
						t.Error("target mutation preceded rollback-marker durability")
					}
				}
				if step == "sync-dir:local" {
					if mode == "failed barrier" {
						return errors.New("rollback marker sync still failing")
					}
					if mutating {
						panic("modeled power loss")
					}
					// The real sync runs immediately after this hook and succeeds.
					rollbackDurable = true
				}
				return nil
			}
			var recoveryErr error
			interrupted := false
			func() {
				defer func() {
					if p := recover(); p != nil {
						if p != "modeled power loss" {
							panic(p)
						}
						interrupted = true
					}
				}()
				recoveryErr = l.recover()
			}()
			if mode == "failed barrier" {
				if recoveryErr == nil {
					t.Fatal("barrier failure ignored")
				}
				for _, c := range next {
					got, err := l.ReadFile(c.Path)
					if err != nil || !bytes.Equal(got, c.Data) {
						t.Errorf("failed barrier changed %s", c.Path)
					}
				}
				got, err := l.ReadFile(pendingPath)
				if err != nil || !bytes.Equal(got, journalBefore) {
					t.Fatal("journal not retained", err)
				}
			} else {
				if !interrupted {
					t.Fatalf("recovery did not reach the interruption boundary: %v", recoveryErr)
				}
				got, err := l.ReadFile(old[0].Path)
				if err != nil || !bytes.Equal(got, old[0].Data) {
					t.Fatal("interruption did not follow first target restore", err)
				}
				got, err = l.ReadFile(next[1].Path)
				if err != nil || !bytes.Equal(got, next[1].Data) {
					t.Fatal("interruption did not precede metadata restore", err)
				}
			}
			// Model independent directory durability: an unsynchronized rollback
			// rename may revert to committed while a vault/ target write survives.
			if !rollbackDurable {
				if err := l.root.Rename(pendingPath, donePath); err != nil {
					t.Fatal(err)
				}
			}
			l.Close()
			l, err = Acquire(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			want := old
			if !rollbackDurable {
				want = next
			}
			for _, c := range want {
				got, err := l.ReadFile(c.Path)
				if err != nil || !bytes.Equal(got, c.Data) {
					t.Errorf("mixed generation after modeled restart: %s", c.Path)
				}
			}
		})
	}
}

func TestRejectUnsafePathsAndPlaintextSecrets(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Symlink(outside, filepath.Join(dir, "vault")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Change{
		{Path: "../escape", Data: []byte("x")}, {Path: "/absolute", Delete: true},
		{Path: "local/../profiles.json", Data: []byte(`{}`)}, {Path: "vault/a.age", Data: []byte("age-encryption.org/v1\nct")},
		{Path: "local/token.age", Data: []byte("plaintext")}, {Path: "local/.clavis.lock", Delete: true},
		{Path: "local/bad\nname.age", Data: []byte("age-encryption.org/v1\nct")},
		{Path: "local/-flag.age", Data: []byte("age-encryption.org/v1\nct")},
		{Path: "local/maſter-key.fido2.age", Data: []byte("age-encryption.org/v1\nct")},
	} {
		if err := l.Apply([]Change{c}); err == nil {
			t.Errorf("accepted unsafe change %s", c.Path)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "p"), filepath.Join(dir, "profiles.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.ReadFile("profiles.json"); err == nil {
		t.Fatal("symlink read accepted")
	}
	if err := l.Apply([]Change{{Path: "profiles.json", Data: []byte(`{}`)}}); err == nil {
		t.Fatal("symlink replacement accepted")
	}
}

func TestDirectoryLockAcrossProcesses(t *testing.T) {
	if dir := os.Getenv("CLAVIS_TEST_LOCK_DIR"); dir != "" {
		l, err := Acquire(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if err := l.Apply([]Change{{Path: "config.json", Data: []byte(`{}`)}}); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDirectoryLockAcrossProcesses$")
	cmd.Env = append(os.Environ(), "CLAVIS_TEST_LOCK_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		t.Fatalf("second process bypassed lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("lock not released")
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptJournalsBlockAccessAndRemainRecoverable(t *testing.T) {
	for _, path := range []string{pendingPath, donePath} {
		t.Run(path, func(t *testing.T) {
			dir := t.TempDir()
			l, err := Acquire(dir)
			if err != nil {
				t.Fatal(err)
			}
			l.Close()
			raw := []byte(`{"version":99,"before":[]}`)
			if err := os.WriteFile(filepath.Join(dir, path), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if l, err := Acquire(dir); err == nil {
				l.Close()
				t.Fatal("unrecognized recovery data silently discarded")
			}
			got, err := os.ReadFile(filepath.Join(dir, path))
			if err != nil || !bytes.Equal(raw, got) {
				t.Fatal("recovery evidence lost", err)
			}
		})
	}
}

func TestPersistentRollbackFailureRetainsJournal(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := []Change{{Path: "profiles.json", Data: []byte(`{"old":true}`)}, {Path: "config.json", Data: []byte(`{"old":true}`)}}
	if err := l.Apply(old); err != nil {
		t.Fatal(err)
	}
	l.fault = func(step string) error {
		if step == "write:config.json" {
			return errors.New("persistent disk failure")
		}
		return nil
	}
	if err := l.Apply([]Change{{Path: "profiles.json", Data: []byte(`{"new":true}`)}, {Path: "config.json", Data: []byte(`{"new":true}`)}}); err == nil {
		t.Fatal("expected write and rollback failure")
	}
	if _, err := os.Stat(filepath.Join(dir, pendingPath)); err != nil {
		t.Fatal("lost rollback journal", err)
	}
	l.Close()
	l, err = Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, c := range old {
		got, err := l.ReadFile(c.Path)
		if err != nil || !bytes.Equal(got, c.Data) {
			t.Fatal("failed recovery", c.Path, err)
		}
	}
}

func TestProcessDeathDuringTransaction(t *testing.T) {
	if dir := os.Getenv("CLAVIS_TEST_CRASH_DIR"); dir != "" {
		l, err := Acquire(dir)
		if err != nil {
			t.Fatal(err)
		}
		l.fault = func(step string) error {
			if step == "write:config.json" {
				os.Exit(73)
			}
			return nil
		}
		if err := l.Apply([]Change{{Path: "profiles.json", Data: []byte(`{"new":true}`)}, {Path: "config.json", Data: []byte(`{"new":true}`)}}); err != nil {
			t.Fatal(err)
		}
		t.Fatal("crash boundary not reached")
	}
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := []Change{{Path: "profiles.json", Data: []byte(`{"old":true}`)}, {Path: "config.json", Data: []byte(`{"old":true}`)}}
	if err := l.Apply(old); err != nil {
		t.Fatal(err)
	}
	l.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessDeathDuringTransaction$")
	cmd.Env = append(os.Environ(), "CLAVIS_TEST_CRASH_DIR="+dir)
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("expected abrupt child exit: %v", err)
	}
	// Prove the child really installed a partial generation, with a durable journal.
	raw, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil || string(raw) != `{"new":true}` {
		t.Fatal("did not interrupt a partial installation", err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, pendingPath))
	if err != nil {
		t.Fatal(err)
	}
	var j journal
	if err := json.Unmarshal(raw, &j); err != nil || len(j.Before) != 2 {
		t.Fatal("journal was not fully staged", err)
	}
	l, err = Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, c := range old {
		got, err := l.ReadFile(c.Path)
		if err != nil || !bytes.Equal(got, c.Data) {
			t.Fatal("failed recovery after process death", c.Path, err)
		}
	}
}

func TestAcquireRejectsSymlinkedSupportPaths(t *testing.T) {
	for _, path := range []string{"local", lockPath, pendingPath, donePath, tempPath} {
		t.Run(path, func(t *testing.T) {
			dir, outside := t.TempDir(), t.TempDir()
			if path != "local" {
				if err := os.Mkdir(filepath.Join(dir, "local"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outside, filepath.Join(dir, path)); err != nil {
				t.Fatal(err)
			}
			if l, err := Acquire(dir); err == nil {
				l.Close()
				t.Fatal("followed symlinked transaction support path")
			}
		})
	}
}

func TestTransactionRejectsCaseAliasesBeforeMutation(t *testing.T) {
	for _, deleteAlias := range []bool{false, true} {
		t.Run(fmt.Sprint("delete=", deleteAlias), func(t *testing.T) {
			l, err := Acquire(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			original := Change{Path: "vault/pA.pass.age", Data: []byte("age-encryption.org/v1\noriginal")}
			if err := l.Apply([]Change{original}); err != nil {
				t.Fatal(err)
			}
			backup, err := l.ReadFile(donePath)
			if err != nil {
				t.Fatal(err)
			}
			alias := Change{Path: "vault/pa.pass.age", Data: []byte("age-encryption.org/v1\nalias")}
			if deleteAlias {
				alias.Data = nil
				alias.Delete = true
			}
			if err := l.Apply([]Change{{Path: original.Path, Data: []byte("age-encryption.org/v1\nreplacement")}, alias}); err == nil {
				t.Error("accepted case-only target conflict")
			}
			got, err := l.ReadFile(original.Path)
			if err != nil || !bytes.Equal(got, original.Data) {
				t.Error("alias conflict changed original target")
			}
			got, err = l.ReadFile(donePath)
			if err != nil || !bytes.Equal(got, backup) {
				t.Error("alias conflict retired backup")
			}
		})
	}
}

func TestRecoveryRejectsCaseAliasJournalBeforeFirstRestore(t *testing.T) {
	for _, path := range []string{pendingPath, donePath} {
		t.Run(path, func(t *testing.T) {
			dir := t.TempDir()
			l, err := Acquire(dir)
			if err != nil {
				t.Fatal(err)
			}
			l.Close()
			live := []byte(`{"live":true}`)
			if err := os.WriteFile(filepath.Join(dir, "profiles.json"), live, 0600); err != nil {
				t.Fatal(err)
			}
			before := []Change{{Path: "profiles.json", Data: []byte(`{"old":true}`)}, {Path: "vault/pA.pass.age", Delete: true}, {Path: "vault/pa.pass.age", Delete: true}}
			after := []Change{{Path: "profiles.json", Data: live}, {Path: "vault/pA.pass.age", Data: []byte("age-encryption.org/v1\na")}, {Path: "vault/pa.pass.age", Data: []byte("age-encryption.org/v1\nb")}}
			raw, err := json.Marshal(journal{Version: 1, Before: before, After: after})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, path), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if l, err := Acquire(dir); err == nil {
				l.Close()
				t.Error("accepted aliasing journal")
			}
			got, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
			if err != nil || !bytes.Equal(got, live) {
				t.Error("restored valid first entry before rejecting later alias")
			}
			got, err = os.ReadFile(filepath.Join(dir, path))
			if err != nil || !bytes.Equal(got, raw) {
				t.Error("conflicting journal not retained")
			}
		})
	}
}
