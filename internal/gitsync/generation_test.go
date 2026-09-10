package gitsync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armtch-dev/clavis/internal/vault"
)

func generationPair(t *testing.T) (*Client, *vault.Vault, *Client, *vault.Vault) {
	t.Helper()
	a, av := newRepo(t)
	if err := av.Put("shared.pass", []byte("shared")); err != nil {
		t.Fatal(err)
	}
	remote := t.TempDir()
	if _, err := a.git("init", "--bare", "-b", "main", remote); err != nil {
		t.Fatal(err)
	}
	if err := a.SetRemote(remote); err != nil {
		t.Fatal(err)
	}
	if err := a.Sync("initial"); err != nil {
		t.Fatal(err)
	}
	b := New(t.TempDir(), "")
	if err := b.Bootstrap(remote); err != nil {
		t.Fatal(err)
	}
	bv, err := vault.Load(b.Dir)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := av.Identity()
	if err := bv.Unlock(old); err != nil {
		t.Fatal(err)
	}
	return a, av, b, bv
}

func rotateGeneration(t *testing.T, v *vault.Vault) string {
	t.Helper()
	r, err := v.PrepareRekey()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	key := r.Key()
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	return key
}

func gitValue(t *testing.T, c *Client, args ...string) string {
	t.Helper()
	out, err := c.git(args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReviewGenerationDivergencePreservesBothTrees(t *testing.T) {
	for _, scenario := range []string{"remote-rotation-add", "remote-rotation-modify", "local-rotation-remote-add", "both-rotate"} {
		t.Run(scenario, func(t *testing.T) {
			a, av, b, bv := generationPair(t)
			localKey, _ := bv.Identity()
			switch scenario {
			case "remote-rotation-add", "remote-rotation-modify":
				rotateGeneration(t, av)
				name := "offline.pass"
				if scenario == "remote-rotation-modify" {
					name = "shared.pass"
				}
				if err := bv.Put(name, []byte("offline edit")); err != nil {
					t.Fatal(err)
				}
			case "local-rotation-remote-add":
				localKey = rotateGeneration(t, bv)
				if err := av.Put("remote.pass", []byte("remote edit")); err != nil {
					t.Fatal(err)
				}
			case "both-rotate":
				rotateGeneration(t, av)
				localKey = rotateGeneration(t, bv)
			}
			if err := a.Sync("remote changes"); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Commit("local changes"); err != nil {
				t.Fatal(err)
			}
			before := gitValue(t, b, "reflog", "--format=%H:%gs")
			remoteBefore := gitValue(t, a, "ls-remote", "origin", "refs/heads/main")
			for attempt := 0; attempt < 2; attempt++ {
				err := b.Sync("retry local changes")
				if err == nil {
					t.Fatal("sync pushed a mixed/divergent recipient generation")
				}
				if !strings.Contains(err.Error(), "recipient") || !strings.Contains(err.Error(), "local commits") {
					t.Fatalf("missing actionable generation error: %v", err)
				}
				if got := gitValue(t, b, "reflog", "--format=%H:%gs"); got != before {
					t.Fatal("generation guard ran after rebase changed local history")
				}
				if got := gitValue(t, a, "ls-remote", "origin", "refs/heads/main"); got != remoteBefore {
					t.Fatal("unsafe generation was pushed")
				}
				v, err := vault.Load(b.Dir)
				if err != nil {
					t.Fatal(err)
				}
				if err := v.Unlock(localKey); err != nil {
					t.Fatal("local recipient changed before refusal")
				}
				if err := v.VerifyAll(); err != nil {
					t.Fatal(err)
				}
				for _, dir := range []string{"rebase-merge", "rebase-apply"} {
					if _, err := os.Stat(filepath.Join(b.Dir, ".git", dir)); !os.IsNotExist(err) {
						t.Fatal("generation refusal stranded rebase")
					}
				}
			}
			if err := av.VerifyAll(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReviewMetadataOnlyEditCanCrossRemoteRotation(t *testing.T) {
	a, av, b, _ := generationPair(t)
	key := rotateGeneration(t, av)
	if err := a.Sync("rotate"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.Dir, "profiles.json"), []byte(`{"version":1,"profiles":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync("metadata only"); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Load(b.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(key); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyAll(); err != nil {
		t.Fatal(err)
	}
}

func TestReviewSameRecipientDivergentAdditionsRemainSyncable(t *testing.T) {
	a, av, b, bv := generationPair(t)
	if err := av.Put("remote.pass", []byte("remote")); err != nil {
		t.Fatal(err)
	}
	if err := bv.Put("offline.pass", []byte("offline")); err != nil {
		t.Fatal(err)
	}
	if err := a.Sync("remote addition"); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync("offline addition"); err != nil {
		t.Fatal(err)
	}
	if err := bv.VerifyAll(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"remote.pass": "remote", "offline.pass": "offline"} {
		raw, err := bv.Get(name)
		if err != nil || string(raw) != want {
			t.Fatalf("lost %s: %v", name, err)
		}
	}
}

func TestReviewPullAlsoRejectsGenerationDivergence(t *testing.T) {
	a, av, b, bv := generationPair(t)
	rotateGeneration(t, av)
	if err := a.Sync("rotate"); err != nil {
		t.Fatal(err)
	}
	if err := bv.Put("offline.pass", []byte("offline")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Commit("offline"); err != nil {
		t.Fatal(err)
	}
	if err := b.Pull(); err == nil {
		t.Fatal("Pull bypassed generation validation")
	}
	if err := bv.VerifyAll(); err != nil {
		t.Fatal(err)
	}
}

func TestReviewPullRetainsUncommittedOldRecipientSecret(t *testing.T) {
	a, av, b, bv := generationPair(t)
	rotateGeneration(t, av)
	if err := a.Sync("rotate"); err != nil {
		t.Fatal(err)
	}
	if err := bv.Put("offline.pass", []byte("uncommitted")); err != nil {
		t.Fatal(err)
	}
	if err := b.Pull(); err == nil {
		t.Fatal("Pull crossed generation with uncommitted ciphertext")
	}
	if err := bv.VerifyAll(); err != nil {
		t.Fatal(err)
	}
}
