package profile_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"github.com/armtch-dev/clavis/internal/vault"
)

func TestStoresRelocateLegacyPaths(t *testing.T) {
	for _, name := range []string{"profiles.json", "identities.json", "scripts.json"} {
		t.Run(name, func(t *testing.T) {
			src, dst := t.TempDir(), t.TempDir()
			save := func(dir string) error {
				switch name {
				case "profiles.json":
					s, err := profile.LoadStore(dir)
					if err != nil {
						return err
					}
					return s.Save()
				case "identities.json":
					s, err := profile.LoadIdentities(dir)
					if err != nil {
						return err
					}
					return s.Save()
				default:
					s, err := script.LoadStore(dir)
					if err != nil {
						return err
					}
					return s.Save()
				}
			}
			if err := save(src); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(src, name))
			if err != nil {
				t.Fatal(err)
			}
			var legacy map[string]any
			if err := json.Unmarshal(raw, &legacy); err != nil {
				t.Fatal(err)
			}
			legacy["Path"] = filepath.Join(src, name)
			raw, _ = json.Marshal(legacy)
			if err := os.WriteFile(filepath.Join(dst, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(src, name))
			if err := save(dst); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(filepath.Join(src, name))
			if !bytes.Equal(before, after) {
				t.Fatal("relocated save changed source")
			}
			out, _ := os.ReadFile(filepath.Join(dst, name))
			if bytes.Contains(out, []byte(`"Path"`)) || bytes.Contains(out, []byte(src)) {
				t.Fatal("runtime path survives destination save")
			}
		})
	}
}

func TestAbandonedCiphertextTransactionRecoversBeforeMetadataLoad(t *testing.T) {
	dir := t.TempDir()
	v, oldKey, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "synthetic credential must never appear in a journal"
	if err := v.Put("p1.pass", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	s, err := profile.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(profile.Profile{ID: "p1", Name: "original", Host: "h", User: "u", Auth: []profile.AuthKind{profile.AuthPassword}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	newDir := t.TempDir()
	nv, newKey, err := vault.Init(newDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := nv.Put("p1.pass", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	var before, after []fstxn.Change
	for _, p := range []string{"profiles.json", "vault/p1.pass.age", "vault.meta"} {
		old, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		var next []byte
		if p == "profiles.json" {
			next = []byte(`{"version":1,"profiles":[]}`)
		} else {
			next, err = os.ReadFile(filepath.Join(newDir, p))
			if err != nil {
				t.Fatal(err)
			}
		}
		before = append(before, fstxn.Change{Path: p, Data: old})
		after = append(after, fstxn.Change{Path: p, Data: next})
	}
	journal, err := json.Marshal(map[string]any{"version": 1, "before": before, "after": after})
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{secret, oldKey, newKey} {
		if bytes.Contains(journal, []byte(plaintext)) {
			t.Fatal("plaintext journal")
		}
	}
	// A new transaction retires the preceding committed backup before staging.
	if err := os.Remove(filepath.Join(dir, "local/.clavis-committed.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "local/.clavis-transaction.json"), journal, 0600); err != nil {
		t.Fatal(err)
	}
	// Simulate interruption after the profile and credential switches, before meta.
	for _, c := range after[:2] {
		if err := os.WriteFile(filepath.Join(dir, c.Path), c.Data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err = profile.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Profiles) != 1 || s.Profiles[0].Name != "original" {
		t.Fatal("metadata was consumed before recovery")
	}
	v, err = vault.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(oldKey); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get("p1.pass")
	if err != nil || string(got) != secret {
		t.Fatal("old encrypted credential not recovered", err)
	}
}

func TestCallerOwnedMetadataAndSecretTransaction(t *testing.T) {
	dir := t.TempDir()
	v, _, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := fstxn.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s, err := profile.LoadStoreLocked(l)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Add(profile.Profile{Name: "together", Host: "h", User: "u", Auth: []profile.AuthKind{profile.AuthPassword}})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := s.Change()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := v.SecretChangeLocked(l, p.PassSecret(), []byte(" exact secret "), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Apply([]fstxn.Change{metadata, secret}); err != nil {
		t.Fatal(err)
	}
	s, err = profile.LoadStoreLocked(l)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Profiles) != 1 {
		t.Fatal("metadata missing after transaction")
	}
	got, err := v.GetLocked(l, s.Profiles[0].PassSecret(), false)
	if err != nil || string(got) != " exact secret " {
		t.Fatal("credential missing or altered", err)
	}
	deletion, err := vault.DeleteChange(s.Profiles[0].PassSecret(), false)
	if err != nil {
		t.Fatal(err)
	}
	s.Profiles = nil
	metadata, err = s.Change()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.CheckCurrentLocked(l); err != nil {
		t.Fatal(err)
	}
	if err := l.Apply([]fstxn.Change{metadata, deletion}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.ReadFile(secret.Path); !os.IsNotExist(err) {
		t.Fatal("secret survived coordinated removal", err)
	}
}

func TestStoresRejectCorruptMetadata(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"profiles.json", `{"version":99,"profiles":[]}`},
		{"identities.json", `{"version":99,"identities":[]}`},
		{"scripts.json", `{"version":99,"scripts":[]}`},
		{"profiles.json", `null`},
		{"identities.json", `{}`},
		{"scripts.json", `{"version":1,"scripts":[{"id":"s1","name":"empty"}]}`},
		{"profiles.json", `{"version":1,"profiles":[{"id":"../escape","name":"web","host":"h","user":"u","auth":["key"]}]}`},
		{"identities.json", `{"version":1,"identities":[{"id":"i1","name":"x","user":"u","auth":["unknown"]}]}`},
	} {
		t.Run(tc.name+tc.raw, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.name), []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch tc.name {
			case "profiles.json":
				_, err = profile.LoadStore(dir)
			case "identities.json":
				_, err = profile.LoadIdentities(dir)
			default:
				_, err = script.LoadStore(dir)
			}
			if err == nil {
				t.Fatal("corrupt/unsupported store accepted")
			}
		})
	}
}
