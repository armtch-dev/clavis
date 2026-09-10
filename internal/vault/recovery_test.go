package vault

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/armtch-dev/clavis/internal/fstxn"
)

func TestRekeyMetadataFailurePreservesOldGeneration(t *testing.T) {
	v, old, dir := newVault(t)
	if err := v.Put("p1.pass", []byte("retained")); err != nil {
		t.Fatal(err)
	}
	// A metadata target that cannot be replaced; secret writes themselves work.
	if err := os.Rename(v.metaPath, v.metaPath+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(v.metaPath, 0700); err != nil {
		t.Fatal(err)
	}
	if r, err := v.PrepareRekey(); err == nil {
		r.Close()
		t.Fatal("expected metadata failure")
	}
	if err := os.Remove(v.metaPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(v.metaPath+".original", v.metaPath); err != nil {
		t.Fatal(err)
	}
	v2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v2.Unlock(old); err != nil {
		t.Fatal(err)
	}
	got, err := v2.Get("p1.pass")
	if err != nil || string(got) != "retained" {
		t.Fatalf("old generation lost: %v", err)
	}
}

func seedFIDO(t *testing.T, v *Vault, old string) []byte {
	t.Helper()
	r, err := age.NewScryptRecipient("synthetic-hardware-secret")
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(1)
	ct, err := encryptTo(r, []byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(v.LocalDir, "master-key.fido2.age"), ct, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(v.LocalDir, "fido2.json"), []byte(`{"credential_id":"Y3JlZA==","salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","rpid":"clavis"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return ct
}

func TestMaintenanceSeparatesFIDOEnvelope(t *testing.T) {
	v, old, _ := newVault(t)
	ct := seedFIDO(t, v, old)
	if err := v.PutLocal("github-token", []byte("synthetic-token")); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyAll(); err != nil {
		t.Fatalf("valid hardware envelope rejected: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(v.LocalDir, "master-key.fido2.age"))
	if !bytes.Equal(got, ct) {
		t.Fatal("verification modified enrollment")
	}
	r, err := v.PrepareRekey()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"master-key.fido2.age", "fido2.json"} {
		if _, err := os.Stat(filepath.Join(v.LocalDir, n)); !os.IsNotExist(err) {
			t.Fatalf("stale enrollment survived: %s", n)
		}
	}
}

func TestRekeyPreparationAbortAndCommitFailurePreserveFIDO(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{true: "commit failure", false: "aborted before acknowledgement"}[fail], func(t *testing.T) {
			v, old, dir := newVault(t)
			ct := seedFIDO(t, v, old)
			if err := v.Put("p1.pass", []byte("original\nsecret")); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(v.metaPath)
			r, err := v.PrepareRekey()
			if err != nil {
				t.Fatal(err)
			}
			newKey := r.Key()
			if newKey == old {
				t.Fatal("key did not rotate")
			}
			after, _ := os.ReadFile(v.metaPath)
			if !bytes.Equal(before, after) {
				t.Fatal("preparation replaced live metadata")
			}
			if fail {
				// Fail late transaction preflight with a non-replaceable FIDO metadata target.
				p := filepath.Join(v.LocalDir, "fido2.json")
				if err := os.Rename(p, p+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
				if err := r.Commit(); err == nil {
					t.Fatal("expected commit failure")
				}
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(p+".original", p); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			v2, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := v2.Unlock(old); err != nil {
				t.Fatal(err)
			}
			got, err := v2.Get("p1.pass")
			if err != nil || string(got) != "original\nsecret" {
				t.Fatalf("old credential lost: %v", err)
			}
			got, _ = os.ReadFile(filepath.Join(v.LocalDir, "master-key.fido2.age"))
			if !bytes.Equal(ct, got) {
				t.Fatal("failed rotation changed FIDO envelope")
			}
			if err := filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if d.IsDir() {
					return nil
				}
				raw, e := os.ReadFile(p)
				if e != nil {
					return e
				}
				if bytes.Contains(raw, []byte(newKey)) || bytes.Contains(raw, []byte(old)) || bytes.Contains(raw, []byte("original\nsecret")) {
					t.Error("plaintext secret persisted")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStaleVaultCannotWriteAfterRotation(t *testing.T) {
	v, _, dir := newVault(t)
	stale, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := v.PrepareRekey()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := stale.Put("late.pass", []byte("lost")); err == nil {
		t.Fatal("stale recipient wrote undecryptable secret")
	}
	if v.Has("late.pass") {
		t.Fatal("stale write reached disk")
	}
}

func TestCommittedRotationKeepsOldCiphertextRecoverableAcrossLoad(t *testing.T) {
	v, old, dir := newVault(t)
	if err := v.Put("p1.pass", []byte("recoverable credential")); err != nil {
		t.Fatal(err)
	}
	fidoCiphertext := seedFIDO(t, v, old)
	r, err := v.PrepareRekey()
	if err != nil {
		t.Fatal(err)
	}
	newKey := r.Key()
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	fresh, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Unlock(newKey); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "local/.clavis-committed.json"))
	if err != nil {
		t.Fatal("old recovery images lost on commit/load", err)
	}
	var backup struct {
		Before []fstxn.Change `json:"before"`
	}
	if err := json.Unmarshal(raw, &backup); err != nil {
		t.Fatal(err)
	}
	id, err := age.ParseX25519Identity(old)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range backup.Before {
		if c.Path != "vault/p1.pass.age" {
			continue
		}
		pt, err := decryptWith(id, c.Data)
		if err != nil || string(pt) != "recoverable credential" {
			t.Fatal("old key cannot recover archived credential", err)
		}
		found = true
	}
	if !found {
		t.Fatal("backup omits old credential")
	}
	if bytes.Contains(raw, []byte(old)) || bytes.Contains(raw, []byte(newKey)) || bytes.Contains(raw, []byte("recoverable credential")) {
		t.Fatal("backup contains plaintext")
	}
	l, err := fstxn.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RestoreLast(); err != nil {
		l.Close()
		t.Fatal(err)
	}
	l.Close()
	restored, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Unlock(old); err != nil {
		t.Fatal("restored generation rejected old key", err)
	}
	if err := restored.VerifyAll(); err != nil {
		t.Fatal("restored generation is inconsistent", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "local/master-key.fido2.age"))
	if err != nil || !bytes.Equal(got, fidoCiphertext) {
		t.Fatal("restoring old generation did not restore enrollment", err)
	}
}

func TestLoadRejectsUnsupportedVaultAndSymlinks(t *testing.T) {
	for _, raw := range []string{`{"version":99}`, `null`, `{"version":1,"recipient":"bad","canary":"bad"}`} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "vault.meta"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Fatal("invalid vault metadata accepted")
		}
	}
	v, _, _ := newVault(t)
	outside := filepath.Join(t.TempDir(), "secret.age")
	if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(v.Dir, "p1.pass.age")); err != nil {
		t.Fatal(err)
	}
	if err := v.Put("p1.pass", []byte("replacement")); err == nil {
		t.Fatal("symlink write accepted")
	}
	if _, err := v.Get("p1.pass"); err == nil {
		t.Fatal("symlink read accepted")
	}
}

func TestFIDOCaseAliasesRemainReserved(t *testing.T) {
	v, old, _ := newVault(t)
	ct := seedFIDO(t, v, old)
	for _, name := range []string{"Master-key.fido2", "MASTER-KEY.FIDO2"} {
		if err := v.PutLocal(name, []byte("not hardware ciphertext")); err == nil {
			t.Errorf("generic PutLocal accepted %s", name)
		}
		if _, err := DeleteChange(name, true); err == nil {
			t.Errorf("generic DeleteChange accepted %s", name)
		}
		if _, err := v.GetLocal(name); err == nil {
			t.Errorf("generic GetLocal accepted %s", name)
		}
	}
	got, err := os.ReadFile(filepath.Join(v.LocalDir, "master-key.fido2.age"))
	if err != nil || !bytes.Equal(got, ct) {
		t.Fatal("reserved envelope overwritten", err)
	}
}

func TestMaintenanceRecognizesLegacyFIDOCase(t *testing.T) {
	for _, name := range []string{"Master-Key.FIDO2.age", "MASTER-KEY.FIDO2.AGE"} {
		t.Run(name, func(t *testing.T) {
			v, old, dir := newVault(t)
			ct := seedFIDO(t, v, old)
			path := filepath.Join(v.LocalDir, name)
			// Two renames ensure the directory entry spelling changes on all filesystems.
			tmp := filepath.Join(v.LocalDir, "enrollment.tmp")
			if err := os.Rename(filepath.Join(v.LocalDir, "master-key.fido2.age"), tmp); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Fatal(err)
			}
			if err := v.VerifyAll(); err != nil {
				t.Fatal("case-variant FIDO envelope treated as vault ciphertext", err)
			}
			r, err := v.PrepareRekey()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if err := r.Commit(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("stale case-variant envelope survived rotation", err)
			}
			l, err := fstxn.Acquire(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := l.RestoreLast(); err != nil {
				l.Close()
				t.Fatal(err)
			}
			l.Close()
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, ct) {
				t.Fatal("legacy envelope not restored", err)
			}
			entries, err := os.ReadDir(v.LocalDir)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range entries {
				if e.Name() == name {
					found = true
				}
			}
			if !found {
				t.Fatal("legacy spelling was silently normalized")
			}
		})
	}
}

func TestRekeyRetiresCanonicalFIDOAbsentAtPreparation(t *testing.T) {
	v, old, _ := newVault(t)
	r, err := v.PrepareRekey()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// The existing FIDO writer is not yet lock-aware. Preserve the prior
	// canonical deletion even if enrollment appears after preparation.
	seedFIDO(t, v, old)
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(v.LocalDir, "master-key.fido2.age")); !os.IsNotExist(err) {
		t.Fatal("canonical enrollment survived rotation", err)
	}
}
