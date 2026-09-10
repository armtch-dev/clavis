package profile_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/script"
)

func TestStoresRelocateLegacyPaths(t *testing.T) {
	for _, name := range []string{"profiles.json", "identities.json", "scripts.json"} {
		t.Run(name, func(t *testing.T) {
			src, dst := t.TempDir(), t.TempDir()
			save := func(dir string) error {
				switch name {
				case "profiles.json":
					s, err := profile.LoadStore(dir)
					if err != nil {
						return err
					}
					return s.Save()
				case "identities.json":
					s, err := profile.LoadIdentities(dir)
					if err != nil {
						return err
					}
					return s.Save()
				default:
					s, err := script.LoadStore(dir)
					if err != nil {
						return err
					}
					return s.Save()
				}
			}
			if err := save(src); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(src, name))
			if err != nil {
				t.Fatal(err)
			}
			var legacy map[string]any
			if err := json.Unmarshal(raw, &legacy); err != nil {
				t.Fatal(err)
			}
			legacy["Path"] = filepath.Join(src, name)
			raw, _ = json.Marshal(legacy)
			if err := os.WriteFile(filepath.Join(dst, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(src, name))
			if err := save(dst); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(filepath.Join(src, name))
			if !bytes.Equal(before, after) {
				t.Fatal("relocated save changed source")
			}
			out, _ := os.ReadFile(filepath.Join(dst, name))
			if bytes.Contains(out, []byte(`"Path"`)) || bytes.Contains(out, []byte(src)) {
				t.Fatal("runtime path survives destination save")
			}
		})
	}
}

func TestStoresRejectCorruptMetadata(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"profiles.json", `{"version":99,"profiles":[]}`},
		{"identities.json", `{"version":99,"identities":[]}`},
		{"scripts.json", `{"version":99,"scripts":[]}`},
		{"profiles.json", `null`},
		{"identities.json", `{}`},
		{"scripts.json", `{"version":1,"scripts":[{"id":"s1","name":"empty"}]}`},
		{"profiles.json", `{"version":1,"profiles":[{"id":"../escape","name":"web","host":"h","user":"u","auth":["key"]}]}`},
		{"identities.json", `{"version":1,"identities":[{"id":"i1","name":"x","user":"u","auth":["unknown"]}]}`},
	} {
		t.Run(tc.name+tc.raw, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.name), []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch tc.name {
			case "profiles.json":
				_, err = profile.LoadStore(dir)
			case "identities.json":
				_, err = profile.LoadIdentities(dir)
			default:
				_, err = script.LoadStore(dir)
			}
			if err == nil {
				t.Fatal("corrupt/unsupported store accepted")
			}
		})
	}
}
