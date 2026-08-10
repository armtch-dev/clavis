package profile

import (
	"strings"
	"testing"
)

func sampleIdentity() Identity {
	return Identity{Name: "ops", User: "root", Auth: []AuthKind{AuthKey}}
}

func TestIdentityAddSaveLoad(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadIdentities(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Identities) != 0 {
		t.Fatalf("missing file should load empty store: %+v", s.Identities)
	}
	id, err := s.Add(sampleIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id.ID, "i") || len(id.ID) != 13 {
		t.Fatalf("odd id %q", id.ID)
	}
	if id.CreatedAt == "" || id.UpdatedAt == "" {
		t.Fatalf("timestamps not stamped: %+v", id)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, err := LoadIdentities(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Identities) != 1 || s2.Identities[0].Name != "ops" {
		t.Fatalf("reload mismatch: %+v", s2.Identities)
	}
}

func TestIdentityDuplicateNameRejected(t *testing.T) {
	s := &IdentityStore{}
	if _, err := s.Add(sampleIdentity()); err != nil {
		t.Fatal(err)
	}
	dup := sampleIdentity()
	dup.Name = "OPS" // case-insensitive
	if _, err := s.Add(dup); err == nil {
		t.Fatal("duplicate name accepted")
	}
}

func TestIdentityUpdate(t *testing.T) {
	s := &IdentityStore{}
	a, _ := s.Add(sampleIdentity())
	other := sampleIdentity()
	other.Name = "deploy"
	s.Add(other)

	created := a.CreatedAt
	upd := *a
	upd.User = "admin"
	if err := s.Update(upd); err != nil {
		t.Fatal(err)
	}
	if got := s.ByID(a.ID); got.CreatedAt != created || got.User != "admin" {
		t.Fatalf("update result: %+v", got)
	}

	upd.Name = "Deploy" // collides with the other identity
	if err := s.Update(upd); err == nil {
		t.Fatal("rename onto existing name accepted")
	}
}

func TestIdentityRemoveReturnsSecretNames(t *testing.T) {
	s := &IdentityStore{}
	id, _ := s.Add(sampleIdentity())
	secrets, err := s.Remove(id.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 3 || !strings.HasSuffix(secrets[0], ".pass") ||
		!strings.HasSuffix(secrets[1], ".sshkey") || !strings.HasSuffix(secrets[2], ".passphrase") {
		t.Fatalf("secrets = %v", secrets)
	}
	if len(s.Identities) != 0 {
		t.Fatal("identity not removed")
	}
	if _, err := s.Remove("nope"); err == nil {
		t.Fatal("remove of unknown id accepted")
	}
}

func TestValidateIdentity(t *testing.T) {
	bad := []Identity{
		{Name: "", User: "u", Auth: []AuthKind{AuthKey}},
		{Name: "x", User: "", Auth: []AuthKind{AuthKey}},
		{Name: "x", User: "u", Auth: nil},
	}
	for i, id := range bad {
		if err := ValidateIdentity(&id); err == nil {
			t.Fatalf("bad[%d] accepted: %+v", i, id)
		}
	}
	good := Identity{Name: "prod admin", User: "svc-user", Auth: []AuthKind{AuthKey, AuthPassword}}
	if err := ValidateIdentity(&good); err != nil {
		t.Fatalf("good rejected: %v", err)
	}
}
