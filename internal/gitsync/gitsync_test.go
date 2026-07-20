package gitsync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armtch-dev/clavis/internal/vault"
)

// newRepo builds a config dir with a real vault so vault files are genuine
// age ciphertext, plus an initialized git repo.
func newRepo(t *testing.T) (*Client, *vault.Vault) {
	t.Helper()
	dir := t.TempDir()
	v, _, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := New(dir, "fake-token")
	if err := c.EnsureRepo(); err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "profiles.json"), []byte(`{"version":1}`), 0o600)
	return c, v
}

func TestGuardAllowsCleanTree(t *testing.T) {
	c, v := newRepo(t)
	if err := v.Put("p1.pass", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := c.Guard(); err != nil {
		t.Fatalf("Guard on clean tree: %v", err)
	}
}

func TestGuardBlocksStrayFile(t *testing.T) {
	c, _ := newRepo(t)
	os.WriteFile(filepath.Join(c.Dir, "notes.txt"), []byte("password: hunter2"), 0o600)
	err := c.Guard()
	if err == nil || !strings.Contains(err.Error(), "notes.txt") {
		t.Fatalf("Guard = %v, want notes.txt offender", err)
	}
}

func TestGuardBlocksPlaintextInVaultDir(t *testing.T) {
	c, _ := newRepo(t)
	// Attacker/bug scenario: a plaintext file with a .age name inside vault/.
	os.WriteFile(filepath.Join(c.Dir, "vault", "evil.pass.age"), []byte("hunter2"), 0o600)
	err := c.Guard()
	if err == nil || !strings.Contains(err.Error(), "not age ciphertext") {
		t.Fatalf("Guard = %v, want ciphertext refusal", err)
	}
	// And a non-.age file in vault/.
	os.Remove(filepath.Join(c.Dir, "vault", "evil.pass.age"))
	os.WriteFile(filepath.Join(c.Dir, "vault", "id_backup"), []byte("x"), 0o600)
	if err := c.Guard(); err == nil {
		t.Fatal("Guard allowed non-.age file in vault/")
	}
}

func TestGuardIgnoresLocalDir(t *testing.T) {
	c, v := newRepo(t)
	if err := v.PutLocal("github-token", []byte("ghp_x")); err != nil {
		t.Fatal(err)
	}
	if err := c.Guard(); err != nil {
		t.Fatalf("Guard should ignore gitignored local/: %v", err)
	}
}

func TestCommitRefusesWhenGuardFails(t *testing.T) {
	c, _ := newRepo(t)
	os.WriteFile(filepath.Join(c.Dir, "creds-backup.txt"), []byte("PRIVATE"), 0o600)
	if _, err := c.Commit("test"); err == nil {
		t.Fatal("Commit succeeded despite guard offender")
	}
	// Nothing may be staged after a refused commit.
	out, _ := c.git("diff", "--cached", "--name-only")
	if strings.TrimSpace(out) != "" {
		t.Fatalf("files were staged despite guard failure: %q", out)
	}
}

func TestCommitHappyPath(t *testing.T) {
	c, v := newRepo(t)
	if err := v.Put("p1.pass", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	did, err := c.Commit("initial")
	if err != nil || !did {
		t.Fatalf("Commit = %v, %v", did, err)
	}
	// local/ must not be in the commit.
	out, _ := c.git("ls-tree", "-r", "--name-only", "HEAD")
	if strings.Contains(out, "local/") {
		t.Fatalf("local/ leaked into commit:\n%s", out)
	}
	if !strings.Contains(out, "vault.meta") || !strings.Contains(out, "profiles.json") {
		t.Fatalf("expected files missing from commit:\n%s", out)
	}
	// Idempotent: nothing new to commit.
	did, err = c.Commit("again")
	if err != nil || did {
		t.Fatalf("second Commit = %v, %v; want no-op", did, err)
	}
}

func TestSanitizeScrubsToken(t *testing.T) {
	got := sanitize("fatal: auth failed for https://ghp_SECRET@github.com", "ghp_SECRET")
	if strings.Contains(got, "ghp_SECRET") {
		t.Fatal("token survived sanitize")
	}
}
