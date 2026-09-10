package gitsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/armtch-dev/clavis/internal/vault"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuardRequiresCompleteHeaderAndRegularMode(t *testing.T) {
	for _, content := range []string{"age-encryption.org/v1", "age-encryption.org/v1EVIL\n"} {
		t.Run(content, func(t *testing.T) {
			c, _ := newRepo(t)
			if err := os.WriteFile(filepath.Join(c.Dir, "vault", "bad.age"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := c.git("add", "vault/bad.age"); err != nil {
				t.Fatal(err)
			}
			if err := c.guardStaged(); err == nil {
				t.Fatal("accepted incomplete age header")
			}
		})
	}
}

func TestSyncRejectsUnsafeIncomingTreeBeforeCheckout(t *testing.T) {
	a, _ := newRepo(t)
	remote := t.TempDir()
	if _, err := a.git("init", "--bare", "-b", "main", remote); err != nil {
		t.Fatal(err)
	}
	a.SetRemote(remote)
	if err := a.Sync("initial"); err != nil {
		t.Fatal(err)
	}
	b := New(t.TempDir(), "")
	if err := b.Bootstrap(remote); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.Dir, "local", "injected"), []byte("unsafe"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "-f", "local/injected"}, {"commit", "-m", "unsafe remote fixture"}, {"push", "origin", "main"}} {
		if _, err := a.git(args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Sync("pull"); err == nil {
		t.Fatal("unsafe remote accepted")
	}
	if _, err := os.Stat(filepath.Join(b.Dir, "local", "injected")); !os.IsNotExist(err) {
		t.Fatal("unsafe tree reached worktree")
	}
	fresh := New(t.TempDir(), "")
	if err := fresh.Bootstrap(remote); err == nil {
		t.Fatal("restore accepted unsafe remote")
	}
}

func countGit(t testing.TB) (func() int, func()) {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	wrapper := "#!/bin/sh\nprintf 'git\\n' >> '" + log + "'\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() int { b, _ := os.ReadFile(log); return bytes.Count(b, []byte("\n")) }, func() {
		if err := os.WriteFile(log, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func stagedFiles(t testing.TB, n int) *Client {
	t.Helper()
	dir := t.TempDir()
	v, _, err := vault.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put("p0", bytes.Repeat([]byte("\x00\xff\nFAKE blob 123\n"), 8192)); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "vault", "p0.age"))
	if err != nil {
		t.Fatal(err)
	}
	c := New(dir, "")
	if err := c.EnsureRepo(); err != nil {
		t.Fatal(err)
	}
	// Real binary age ciphertext, larger than a pipe buffer. Encryption and
	// setup are excluded; repeated OIDs also exercise multiple complete frames.
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, "vault", fmt.Sprintf("p%d.age", i)), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.git("add", "-A"); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBatchGuardConstantProcessesAndBinaryFrames(t *testing.T) {
	count, reset := countGit(t)
	for _, n := range []int{10, 100, 1000} {
		c := stagedFiles(t, n)
		reset()
		if err := c.guardStaged(); err != nil {
			t.Fatal(err)
		}
		if got := count(); got != 2 {
			t.Fatalf("%d files launched %d processes, want 2", n, got)
		}
	}
}

func BenchmarkGuardStaged(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			count, reset := countGit(b)
			c := stagedFiles(b, n)
			reset()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := c.guardStaged(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(count())/float64(b.N), "git-processes/op")
		})
	}
}

func TestGitCancellationKillsChildrenAndStripsMasterKey(t *testing.T) {
	dir := t.TempDir()
	bin := t.TempDir()
	script := "#!/bin/sh\nif [ -n \"$CLAVIS_KEY\" ]; then printf 'leaked'; exit 0; fi\nsleep 10 &\nwait\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CLAVIS_KEY", "synthetic-master-key")
	c := New(dir, "synthetic-token")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c.Context = ctx
	start := time.Now()
	out, err := c.git("status")
	if err == nil || strings.Contains(out, "leaked") {
		t.Fatalf("command wasn't canceled or leaked master key: %q %v", out, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancel left a child holding pipes")
	}
}

func TestEnsureRepoRejectsSupportSymlinksBeforeWrite(t *testing.T) {
	for _, name := range []string{".gitignore", ".git"} {
		t.Run(name, func(t *testing.T) {
			dir, outside := t.TempDir(), t.TempDir()
			target := filepath.Join(outside, "keep")
			if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			link := target
			if name == ".git" {
				link = outside
			}
			if err := os.Symlink(link, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if err := New(dir, "").EnsureRepo(); err == nil {
				t.Fatal("unsafe support symlink accepted")
			}
			got, err := os.ReadFile(target)
			if err != nil || string(got) != "unchanged" {
				t.Fatal("support write escaped config root")
			}
		})
	}
}

func TestChangedOriginClearsOldPushURL(t *testing.T) {
	c, _ := newRepo(t)
	first, second := t.TempDir(), t.TempDir()
	for _, dir := range []string{first, second} {
		if _, err := c.git("init", "--bare", "-b", "main", dir); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.SetRemote(first); err != nil {
		t.Fatal(err)
	}
	if _, err := c.git("config", "remote.origin.pushurl", first); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRemote(second); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync("changed destination"); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		dir    string
		exists bool
	}{{first, false}, {second, true}} {
		cmd := exec.Command("git", "--git-dir", item.dir, "rev-parse", "--verify", "refs/heads/main")
		err := cmd.Run()
		if (err == nil) != item.exists {
			t.Fatalf("wrong destination: %s %v", item.dir, err)
		}
	}
}

func TestBatchFrameSubprocess(t *testing.T) {
	encoded := os.Getenv("TEST_CLAVIS_BATCH_FRAME")
	if encoded == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		os.Exit(2)
	}
	os.Stdout.Write(raw)
	os.Exit(0)
}

func TestBatchRejectsMalformedFrames(t *testing.T) {
	oid := strings.Repeat("a", 40)
	prefix := "age-encryption.org/v1\n"
	for name, frame := range map[string]string{
		"missing":            oid + " missing\n",
		"wrong oid":          strings.Repeat("b", 40) + " blob 21\n" + prefix + "\n",
		"wrong type":         oid + " commit 21\n" + prefix + "\n",
		"negative":           oid + " blob -1\n",
		"truncated header":   oid + " blob 21\n" + prefix[:10],
		"truncated body":     oid + " blob 100\n" + prefix + "short\n",
		"bad terminator":     oid + " blob 21\n" + prefix + "X",
		"partial age header": oid + " blob 21\n" + "age-encryption.org/v1X\n",
	} {
		t.Run(name, func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nexec '"+exe+"' -test.run=^TestBatchFrameSubprocess$\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			t.Setenv("TEST_CLAVIS_BATCH_FRAME", base64.StdEncoding.EncodeToString([]byte(frame)))
			if err := New(t.TempDir(), "").guardEntries("100644 " + oid + " 0\tvault/key.age\x00"); err == nil {
				t.Fatal("malformed frame accepted")
			}
		})
	}
}

func TestGuardRejectsGitlinkAndUnmergedMetadata(t *testing.T) {
	c, _ := newRepo(t)
	for _, entry := range []string{"160000 " + strings.Repeat("a", 40) + " 0\tprofiles.json\x00", "100644 " + strings.Repeat("a", 40) + " 2\tprofiles.json\x00"} {
		if err := c.guardEntries(entry); err == nil {
			t.Fatal("nonregular/unmerged metadata accepted")
		}
	}
}

func TestGuardRejectsCaseAliasedSecretPaths(t *testing.T) {
	c, _ := newRepo(t)
	oid := strings.Repeat("a", 40)
	if err := c.guardEntries("100644 " + oid + " 0\tvault/p.age\x00100644 " + oid + " 0\tvault/P.age\x00"); err == nil || !strings.Contains(err.Error(), "alias") {
		t.Fatalf("case alias wasn't rejected before blob reads: %v", err)
	}
}

func TestCanceledRebaseStillAborts(t *testing.T) {
	a, _ := newRepo(t)
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
	for _, item := range []struct {
		c    *Client
		data string
	}{{a, `{"version":1,"profiles":[]}`}, {b, `{"version":1,"profiles":null}`}} {
		if err := os.WriteFile(filepath.Join(item.c.Dir, "profiles.json"), []byte(item.data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Sync("remote edit"); err != nil {
		t.Fatal(err)
	}
	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	ready := filepath.Join(bin, "ready")
	wrapper := `#!/bin/sh
case "$*" in
 *" rebase FETCH_HEAD") "$TEST_REAL_GIT" "$@"; result=$?; printf ready > "$TEST_REBASE_READY"; sleep 10; exit "$result";;
 *) exec "$TEST_REAL_GIT" "$@";;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TEST_REAL_GIT", real)
	t.Setenv("TEST_REBASE_READY", ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Context = ctx
	done := make(chan error, 1)
	go func() { done <- b.Sync("local edit") }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rebase did not reach conflict")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "rebase aborted") {
			t.Fatalf("cancel cleanup: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abort remained canceled or hung")
	}
	if _, err := os.Stat(filepath.Join(b.Dir, ".git", "rebase-merge")); !os.IsNotExist(err) {
		t.Fatal("canceled rebase stranded state")
	}
	raw, err := os.ReadFile(filepath.Join(b.Dir, "profiles.json"))
	if err != nil || string(raw) != `{"version":1,"profiles":null}` {
		t.Fatal("canceled rebase lost local commit")
	}
}

func TestPullConflictAbortsRebase(t *testing.T) {
	a, _ := newRepo(t)
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
	for _, item := range []struct {
		c    *Client
		data string
	}{{a, `{"version":1,"profiles":[]}`}, {b, `{"version":1,"profiles":null}`}} {
		if err := os.WriteFile(filepath.Join(item.c.Dir, "profiles.json"), []byte(item.data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Sync("A"); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync("B"); err == nil {
		t.Fatal("expected conflict")
	}
	for _, name := range []string{"rebase-merge", "rebase-apply"} {
		if _, err := os.Stat(filepath.Join(b.Dir, ".git", name)); !os.IsNotExist(err) {
			t.Fatalf("stranded %s: %v", name, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(b.Dir, "profiles.json"))
	if err != nil || string(raw) != `{"version":1,"profiles":null}` {
		t.Fatalf("local commit lost: %s %v", raw, err)
	}
}
