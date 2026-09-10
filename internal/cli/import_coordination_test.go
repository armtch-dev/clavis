package cli

import (
	"bytes"
	"errors"
	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/vault"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestImportOwnsLockThroughCredentialAndMetadata(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := vault.Init(dir); err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	fifo := filepath.Join(source, "key")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(source, "config")
	if err := os.WriteFile(ssh, []byte("Host imported\n HostName 127.0.0.1\n User user\n IdentityFile "+fifo+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- ImportSSHConfig(&bytes.Buffer{}, dir, ssh) }()
	opened := make(chan *os.File, 1)
	go func() { f, _ := os.OpenFile(fifo, os.O_WRONLY, 0600); opened <- f }()
	var f *os.File
	select {
	case f = <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("import never reached credential read")
	}
	l, err := fstxn.TryAcquire(dir)
	if l != nil {
		l.Close()
	}
	_, writeErr := f.Write([]byte("synthetic key"))
	f.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("import deadlocked")
	}
	if !errors.Is(err, fstxn.ErrBusy) {
		t.Fatalf("import released coordination between load and write: %v", err)
	}
	s, err := profile.LoadStore(dir)
	if err != nil || s.ByName("imported") == nil {
		t.Fatalf("import metadata missing: %v", err)
	}
}
