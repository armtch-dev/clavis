package profile_test

import (
	"errors"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
	"testing"
)

func TestStaleStoresRejectNextSave(t *testing.T) {
	dir := t.TempDir()
	a, _ := profile.LoadStore(dir)
	b, _ := profile.LoadStore(dir)
	a.Add(profile.Profile{Name: "remote", Host: "example.test", Port: 22, User: "user", Auth: []profile.AuthKind{profile.AuthKey}})
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	if err := b.Save(); !errors.Is(err, fstxn.ErrStale) {
		t.Fatalf("profiles: %v", err)
	}
	ia, _ := profile.LoadIdentities(dir)
	ib, _ := profile.LoadIdentities(dir)
	ia.Add(profile.Identity{Name: "remote", User: "user", Auth: []profile.AuthKind{profile.AuthKey}})
	if err := ia.Save(); err != nil {
		t.Fatal(err)
	}
	if err := ib.Save(); !errors.Is(err, fstxn.ErrStale) {
		t.Fatalf("identities: %v", err)
	}
	sa, _ := script.LoadStore(dir)
	sb, _ := script.LoadStore(dir)
	sa.Add(script.Script{Name: "remote", Content: "true"})
	if err := sa.Save(); err != nil {
		t.Fatal(err)
	}
	if err := sb.Save(); !errors.Is(err, fstxn.ErrStale) {
		t.Fatalf("scripts: %v", err)
	}
}
