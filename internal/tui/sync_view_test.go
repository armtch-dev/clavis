package tui

import (
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"testing"
	"time"
)

func TestSyncViewsNeverWaitOnStorageOrQueryKeychain(t *testing.T) {
	m := newTestModel(t)
	p, err := m.store.Add(profile.Profile{Name: "view", Host: "127.0.0.1", Port: 1, User: "user", Auth: []profile.AuthKind{profile.AuthKey}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Put(p.KeySecret(), []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	m.wizard = newWizard(m, p)
	m.wizard.setStep(stepKeySource)
	m.settings = newSettings(m)
	// A real security executable must never be reachable from this regression.
	t.Setenv("PATH", t.TempDir())
	l, err := fstxn.Acquire(m.cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); m.wizard.view(80, 24); m.settings.view(80, 24) }()
	select {
	case <-done:
		l.Close()
	case <-time.After(200 * time.Millisecond):
		l.Close()
		<-done
		t.Fatal("view waited on storage lock")
	}
}
