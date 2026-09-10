package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/armtch-dev/clavis/internal/fstxn"
)

func TestStartupRecoversBeforeConfigParsing(t *testing.T) {
	dir := t.TempDir()
	l, err := fstxn.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	j, err := json.Marshal(map[string]any{"version": 1, "before": []fstxn.Change{{Path: "config.json", Data: []byte(`{}`)}}, "after": []fstxn.Change{{Path: "config.json", Data: []byte(`{"sync":{}}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "local/.clavis-transaction.json"), j, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("unparseable live metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := buildModel(dir)
	if err != nil {
		t.Fatal("config parsed before recovery", err)
	}
	m.Close()
}

func TestStartupRejectsConfigSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if m, err := buildModel(dir); err == nil {
		m.Close()
		t.Fatal("startup followed metadata symlink")
	}
}
