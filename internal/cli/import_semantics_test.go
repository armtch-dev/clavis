package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/vault"
)

func TestImportPreservesOpenSSHSyntaxThroughVault(t *testing.T) {
	dir, source := t.TempDir(), t.TempDir()
	v, _, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(source, "Key #Case=Value")
	if err := os.WriteFile(key, []byte("synthetic credential"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(source, "config")
	text := "Host *\n User\tDeploy\n Port=22\nHost imported\n HostName=LocalHost\n Port 2222\n IdentityFile \"" + key + "\"\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := ImportSSHConfig(&out, dir, path); err != nil {
		t.Fatal(err)
	}
	store, err := profile.LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := store.ByName("imported")
	if p == nil || p.User != "Deploy" || p.Host != "LocalHost" || p.Port != 22 {
		t.Fatalf("wrong imported profile: %+v", p)
	}
	if raw, err := v.Get(p.KeySecret()); err != nil || string(raw) != "synthetic credential" {
		t.Fatalf("wrong imported key %q: %v", raw, err)
	}
	before, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text+"Host malformed\n Port nonsense\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ImportSSHConfig(&out, dir, path); err == nil {
		t.Fatal("malformed import accepted")
	}
	after, err := os.ReadFile(store.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("malformed import changed metadata")
	}
}
