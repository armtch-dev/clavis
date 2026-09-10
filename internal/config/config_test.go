package config

import (
	"errors"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"testing"
)

func TestStaleConfigDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	a.Sync.Remote = "remote-a"
	if err := a.Save(dir); err != nil {
		t.Fatal(err)
	}
	b.Sync.AutoSync = true
	if err := b.Save(dir); !errors.Is(err, fstxn.ErrStale) {
		t.Fatalf("stale save: %v", err)
	}
	got, err := Load(dir)
	if err != nil || got.Sync.Remote != "remote-a" || got.Sync.AutoSync {
		t.Fatalf("remote settings overwritten: %+v %v", got, err)
	}
}
