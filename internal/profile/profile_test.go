package profile

import (
	"strings"
	"testing"
)

func sample() Profile {
	return Profile{
		Name: "web-01", Host: "192.0.2.10", User: "root",
		Auth: []AuthKind{AuthKey},
	}
}

func TestAddSaveLoad(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Add(sample())
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != 22 {
		t.Fatalf("default port = %d", p.Port)
	}
	if !strings.HasPrefix(p.ID, "p") || len(p.ID) != 13 {
		t.Fatalf("odd id %q", p.ID)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, err := LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Profiles) != 1 || s2.Profiles[0].Name != "web-01" {
		t.Fatalf("reload mismatch: %+v", s2.Profiles)
	}
}

func TestDuplicateNameRejected(t *testing.T) {
	s := &Store{}
	if _, err := s.Add(sample()); err != nil {
		t.Fatal(err)
	}
	dup := sample()
	dup.Name = "WEB-01" // case-insensitive
	if _, err := s.Add(dup); err == nil {
		t.Fatal("duplicate name accepted")
	}
}

func TestValidate(t *testing.T) {
	bad := []Profile{
		{Name: "", Host: "h", User: "u", Auth: []AuthKind{AuthKey}},
		{Name: "x", Host: "not a host!", User: "u", Auth: []AuthKind{AuthKey}},
		{Name: "x", Host: "h.example.com", User: "", Auth: []AuthKind{AuthKey}},
		{Name: "x", Host: "h.example.com", User: "u", Auth: nil},
		{Name: "x", Host: "h.example.com", User: "u", Port: 99999, Auth: []AuthKind{AuthKey}},
		{Name: "x", Host: "h", User: "u", ProxyJump: "bad host!", Auth: []AuthKind{AuthKey}},
	}
	for i, p := range bad {
		if err := Validate(&p); err == nil {
			t.Fatalf("bad[%d] accepted: %+v", i, p)
		}
	}
	good := []Profile{
		{Name: "a", Host: "192.168.1.1", User: "root", Auth: []AuthKind{AuthPassword}},
		{Name: "b 2", Host: "srv.example.com", User: "svc-user", Auth: []AuthKind{AuthKey, AuthPassword}},
		{Name: "c", Host: "::1", User: "u", Auth: []AuthKind{AuthKey}},
		{Name: "d", Host: "h", User: "u", ProxyJump: "jump@bastion.example.com:2222", Auth: []AuthKind{AuthKey}},
	}
	for i, p := range good {
		if err := Validate(&p); err != nil {
			t.Fatalf("good[%d] rejected: %v", i, err)
		}
	}
}

func TestRemoveReturnsSecretNames(t *testing.T) {
	s := &Store{}
	p, _ := s.Add(sample())
	secrets, err := s.Remove(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 3 || !strings.HasSuffix(secrets[0], ".pass") {
		t.Fatalf("secrets = %v", secrets)
	}
	if len(s.Profiles) != 0 {
		t.Fatal("profile not removed")
	}
}
