package script

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := s.Add(Script{Name: "disk check", Content: "df -h\n"})
	if err != nil {
		t.Fatal(err)
	}
	if sc.ID == "" || sc.CreatedAt == "" {
		t.Errorf("Add left ID/CreatedAt empty: %+v", sc)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	s2, err := LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.ByName("DISK CHECK") // lookup is case-insensitive
	if got == nil || got.Content != "df -h\n" {
		t.Fatalf("reloaded store: ByName = %+v", got)
	}
	if s2.ByID(sc.ID) == nil {
		t.Error("ByID misses the saved script")
	}
}

func TestStoreValidationAndDuplicates(t *testing.T) {
	s := &Store{}
	if _, err := s.Add(Script{Name: "", Content: "x"}); err == nil {
		t.Error("empty name accepted")
	}
	if _, err := s.Add(Script{Name: "a", Content: "  \n "}); err == nil {
		t.Error("blank content accepted")
	}
	if _, err := s.Add(Script{Name: "uptime", Content: "uptime"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(Script{Name: "Uptime", Content: "w"}); err == nil {
		t.Error("duplicate name (case-insensitive) accepted")
	}
}

func TestStoreUpdateRemove(t *testing.T) {
	s := &Store{}
	a, _ := s.Add(Script{Name: "a", Content: "1"})
	b, _ := s.Add(Script{Name: "b", Content: "2"})

	if err := s.Update(Script{ID: a.ID, Name: "b", Content: "1"}); err == nil {
		t.Error("rename onto an existing name accepted")
	}
	if err := s.Update(Script{ID: a.ID, Name: "a2", Content: "11"}); err != nil {
		t.Fatal(err)
	}
	if got := s.ByID(a.ID); got.Name != "a2" || got.Content != "11" || got.CreatedAt != a.CreatedAt {
		t.Errorf("update result: %+v", got)
	}

	if err := s.Remove(b.ID); err != nil {
		t.Fatal(err)
	}
	if s.ByID(b.ID) != nil {
		t.Error("removed script still present")
	}
	if err := s.Remove("nope"); err == nil {
		t.Error("removing a missing id succeeded")
	}
}

func TestCorruptStoreRefusesToLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scripts.json"), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStore(dir); err == nil {
		t.Error("corrupt scripts.json loaded without error")
	}
}
