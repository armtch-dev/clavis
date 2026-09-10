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
)

// Adapter over the real stores; mutations below call their actual public APIs.
type metadataStore interface {
	Change() (fstxn.Change, error)
	Save() error
}

func loadMetadata(dir, kind string) (metadataStore, error) {
	switch kind {
	case "profiles":
		return profile.LoadStore(dir)
	case "identities":
		return profile.LoadIdentities(dir)
	default:
		return script.LoadStore(dir)
	}
}

func addMetadata(s metadataStore, id, name string) error {
	switch s := s.(type) {
	case *profile.Store:
		_, err := s.Add(profile.Profile{ID: id, Name: name, Host: "h", User: "u", Auth: []profile.AuthKind{profile.AuthKey}})
		return err
	case *profile.IdentityStore:
		_, err := s.Add(profile.Identity{ID: id, Name: name, User: "u", Auth: []profile.AuthKind{profile.AuthKey}})
		return err
	default:
		_, err := s.(*script.Store).Add(script.Script{ID: id, Name: name, Content: "true"})
		return err
	}
}

func TestStoreMutationRejectsInvalidIDs(t *testing.T) {
	for _, kind := range []string{"profiles", "identities", "scripts"} {
		for _, id := range []string{"../unsafe", "LegacyA", "legacya"} {
			t.Run(kind+"/"+id, func(t *testing.T) {
				dir := t.TempDir()
				s, err := loadMetadata(dir, kind)
				if err != nil {
					t.Fatal(err)
				}
				if err := addMetadata(s, "LegacyA", "original"); err != nil {
					t.Fatal(err)
				}
				if err := s.Save(); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, kind+".json")
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := addMetadata(s, id, "different name"); err == nil {
					t.Error("Add accepted unsafe/duplicate/alias ID")
				}
				if err := s.Save(); err != nil {
					t.Fatal("rejected mutation damaged store", err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Error("rejected Add changed persisted metadata")
				}
				if _, err := loadMetadata(dir, kind); err != nil {
					t.Fatal("saved metadata cannot load", err)
				}
			})
		}
	}
}

func damageMetadata(s metadataStore, violation string) {
	id := ""
	if violation == "unsafe" {
		id = "../unsafe"
	}
	if violation == "duplicate" {
		id = "LegacyA"
	}
	if violation == "case alias" {
		id = "legacya"
	}
	switch s := s.(type) {
	case *profile.Store:
		p := s.Profiles[0]
		p.ID = id
		p.Name = "different name"
		s.Profiles = append(s.Profiles, p)
		if violation == "version" {
			s.Profiles = s.Profiles[:1]
			s.Version = 99
		}
	case *profile.IdentityStore:
		i := s.Identities[0]
		i.ID = id
		i.Name = "different name"
		s.Identities = append(s.Identities, i)
		if violation == "version" {
			s.Identities = s.Identities[:1]
			s.Version = 99
		}
	case *script.Store:
		sc := s.Scripts[0]
		sc.ID = id
		sc.Name = "different name"
		s.Scripts = append(s.Scripts, sc)
		if violation == "version" {
			s.Scripts = s.Scripts[:1]
			s.Version = 99
		}
	}
}

func TestStoreSerializationRejectsInvalidIDs(t *testing.T) {
	for _, kind := range []string{"profiles", "identities", "scripts"} {
		for _, violation := range []string{"empty", "unsafe", "duplicate", "case alias", "version"} {
			t.Run(kind+"/"+violation, func(t *testing.T) {
				dir := t.TempDir()
				s, err := loadMetadata(dir, kind)
				if err != nil {
					t.Fatal(err)
				}
				if err := addMetadata(s, "LegacyA", "original"); err != nil {
					t.Fatal(err)
				}
				if err := s.Save(); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, kind+".json")
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				damageMetadata(s, violation)
				if _, err := s.Change(); err == nil {
					t.Error("Change serialized invalid metadata")
				}
				if err := s.Save(); err == nil {
					t.Error("Save persisted invalid metadata")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Error("failed serialization changed saved metadata")
				}
				if _, err := loadMetadata(dir, kind); err != nil {
					t.Error("previously saved metadata no longer loads", err)
				}
			})
		}
	}
}

func TestStoreLoadRejectsCaseAliasedIDs(t *testing.T) {
	for _, kind := range []string{"profiles", "identities", "scripts"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			s, err := loadMetadata(dir, kind)
			if err != nil {
				t.Fatal(err)
			}
			if err := addMetadata(s, "LegacyA", "original"); err != nil {
				t.Fatal(err)
			}
			damageMetadata(s, "case alias")
			raw, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, kind+".json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadMetadata(dir, kind); err == nil {
				t.Fatal("loaded IDs that alias the same credential filename")
			}
		})
	}
}

func TestProfileReferenceValidatedOnMutation(t *testing.T) {
	dir := t.TempDir()
	s, err := profile.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := profile.Profile{ID: "LegacyA", Name: "original", Host: "h", IdentityID: "../unsafe"}
	if _, err := s.Add(p); err == nil {
		t.Fatal("Add accepted unsafe identity reference")
	}
	p.IdentityID = "MissingButSyntacticallyValid"
	added, err := s.Add(p)
	if err != nil {
		t.Fatal(err)
	}
	p = *added
	p.IdentityID = "../unsafe"
	if err := s.Update(p); err == nil {
		t.Fatal("Update accepted unsafe identity reference")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	p.IdentityID = "MissingButSyntacticallyValid"
	p.Name = "updated"
	if err := s.Update(p); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s, err = profile.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Profiles[0].ID != "LegacyA" || s.Profiles[0].Name != "updated" {
		t.Fatal("valid update did not round trip with legacy ID")
	}
	s.Profiles[0].IdentityID = "../unsafe"
	if _, err := s.Change(); err == nil {
		t.Fatal("direct invalid reference serialized")
	}
}

func updateMetadata(s metadataStore) error {
	switch s := s.(type) {
	case *profile.Store:
		p := s.Profiles[0]
		p.Name = "updated"
		return s.Update(p)
	case *profile.IdentityStore:
		i := s.Identities[0]
		i.Name = "updated"
		return s.Update(i)
	default:
		scripts := s.(*script.Store)
		sc := scripts.Scripts[0]
		sc.Name = "updated"
		return scripts.Update(sc)
	}
}

func TestStoreUpdateRoundTripAndDuplicateRejection(t *testing.T) {
	for _, kind := range []string{"profiles", "identities", "scripts"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			s, err := loadMetadata(dir, kind)
			if err != nil {
				t.Fatal(err)
			}
			if err := addMetadata(s, "LegacyA", "original"); err != nil {
				t.Fatal(err)
			}
			if err := updateMetadata(s); err != nil {
				t.Fatal(err)
			}
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}
			s, err = loadMetadata(dir, kind)
			if err != nil {
				t.Fatal("valid Add/Update/Save failed round trip", err)
			}
			for _, violation := range []string{"duplicate", "case alias"} {
				draft, err := loadMetadata(dir, kind)
				if err != nil {
					t.Fatal(err)
				}
				damageMetadata(draft, violation)
				if err := updateMetadata(draft); err == nil {
					t.Errorf("Update accepted %s ID", violation)
				}
			}
			path := filepath.Join(dir, kind+".json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte(`"LegacyA"`)) || !bytes.Contains(raw, []byte(`"updated"`)) {
				t.Fatal("valid updated fields/legacy ID were not preserved")
			}
		})
	}
}
