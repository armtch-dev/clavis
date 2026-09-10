// Package gitsync mirrors the clavis config dir to a git remote. Two hard
// rules, enforced here rather than by convention:
//
//  1. The guard: nothing gets committed unless it's on the allowlist, and
//     vault files must actually be age ciphertext. A stray plaintext file
//     fails the sync instead of leaking.
//  2. The GitHub token is never written into .git/config or a command line —
//     it reaches git via an env var read by an inline credential helper.
package gitsync

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/armtch-dev/clavis/internal/fstxn"
	"github.com/armtch-dev/clavis/internal/vault"
)

const (
	tokenEnv      = "CLAVIS_GIT_TOKEN"
	DefaultBranch = "main"
	// credential helper reads the token from the environment, so the secret
	// never appears in argv or on disk.
	credHelper = `!f() { echo "username=x-access-token"; echo "password=${` + tokenEnv + `}"; }; f`
)

type Settings struct {
	Remote   string `json:"remote,omitempty"`
	AutoSync bool   `json:"auto_sync"`
}

type Client struct {
	Dir     string          // the clavis config dir == the repo worktree
	Token   string          // decrypted PAT; lives only in memory
	Context context.Context // nil uses Background; each command is still bounded
}

func New(dir, token string) *Client { return &Client{Dir: dir, Token: token} }

func (c *Client) command(args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx := c.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	full := append([]string{
		"-c", "credential.helper=",
		"-c", "credential.helper=" + credHelper,
		"-c", "user.name=clavis",
		"-c", "user.email=clavis@localhost",
		"-c", "core.hooksPath=/dev/null",
		"-c", "commit.gpgsign=false",
		"-c", "core.sshCommand=ssh -oBatchMode=yes -oConnectTimeout=10",
	}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = c.Dir
	// Do not pass vault master keys or inherited Git overrides to helpers/hooks.
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		if strings.HasPrefix(name, "CLAVIS_") || strings.HasPrefix(name, "GIT_") {
			continue
		}
		cmd.Env = append(cmd.Env, e)
	}
	if len(args) > 0 && (args[0] == "fetch" || args[0] == "pull" || args[0] == "push") {
		cmd.Env = append(cmd.Env, tokenEnv+"="+c.Token)
	}
	cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0", "GIT_EDITOR=true", "GIT_SEQUENCE_EDITOR=true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	return cmd, cancel
}

func (c *Client) git(args ...string) (string, error) {
	cmd, cancel := c.command(args...)
	defer cancel()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), errors.New(sanitize(fmt.Sprintf("git %s: %v\n%s", strings.Join(args, " "), err, out.String()), c.Token))
	}
	return out.String(), nil
}

// sanitize scrubs the token from any surface an error message could expose.
func sanitize(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "•••")
}

func (c *Client) IsRepo() bool {
	_, err := os.Stat(filepath.Join(c.Dir, ".git"))
	return err == nil
}

// EnsureRepo initializes the repo and its protective .gitignore.
func (c *Client) EnsureRepo() error {
	l, err := fstxn.AcquireContext(c.context(), c.Dir)
	if err != nil {
		return err
	}
	defer l.Close()
	return c.ensureRepo()
}

func (c *Client) ensureRepo() error {
	if fi, err := os.Lstat(filepath.Join(c.Dir, ".git")); err == nil {
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe .git path; expected a local repository directory")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if !c.IsRepo() {
		if _, err := c.git("init", "-b", DefaultBranch); err != nil {
			return err
		}
	}
	return c.ensureIgnore()
}

// ensureIgnore keeps machine-local secrets and plaintext key material out of
// the index even if the guard were somehow bypassed.
func (c *Client) ensureIgnore() error {
	const ignore = `# clavis — do not edit; regenerated on every sync
local/
*.tmp
.tmp-*
*.pem
*.key
id_rsa*
id_ed25519*
*.identity
AGE-SECRET-KEY-*
`
	path := filepath.Join(c.Dir, ".gitignore")
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("unsafe .gitignore: not a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = io.WriteString(f, ignore)
	return errors.Join(err, f.Close())
}

// allowedPath is the sync allowlist: only these repo-relative paths may ever
// be committed. Content checks happen separately (worktree pre-check and
// staged-blob check).
func allowedPath(rel string) error {
	rel = filepath.ToSlash(rel)
	switch rel {
	case "profiles.json", "identities.json", "scripts.json", "config.json", "vault.meta", ".gitignore", "README.md":
		return nil
	}
	if strings.HasPrefix(rel, "vault/") {
		if filepath.Base(rel) != strings.TrimPrefix(rel, "vault/") || strings.ContainsAny(rel, "\\\n\r") {
			return fmt.Errorf("%s: unsafe vault path", rel)
		}
		if !strings.HasSuffix(rel, ".age") {
			return fmt.Errorf("%s: only .age files may live in vault/", rel)
		}
		_, err := vault.DeleteChange(strings.TrimSuffix(strings.TrimPrefix(rel, "vault/"), ".age"), false)
		return err
	}
	return fmt.Errorf("%s: not on the sync allowlist", rel)
}

// allowedFile = path allowlist + on-disk content check (worktree pre-check).
func allowedFile(dir, rel string) error {
	if err := allowedPath(rel); err != nil {
		return err
	}
	if !strings.HasPrefix(filepath.ToSlash(rel), "vault/") {
		return nil
	}
	// Symlinks would make the guard validate different bytes than git stores.
	if fi, err := os.Lstat(filepath.Join(dir, rel)); err != nil {
		return fmt.Errorf("%s: %v", rel, err)
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed in vault/", rel)
	}
	f, err := os.Open(filepath.Join(dir, rel))
	if err != nil {
		return fmt.Errorf("%s: %v", rel, err)
	}
	defer f.Close()
	head := make([]byte, len(vault.AgeHeader)+1)
	if _, err := io.ReadFull(f, head); err != nil || string(head) != vault.AgeHeader+"\n" {
		return fmt.Errorf("%s: not age ciphertext — refusing to sync", rel)
	}
	return nil
}

// guardStaged validates what will ACTUALLY be committed: every entry in the
// index, by staged blob content, after `git add`. This closes the gap where
// a file passes the worktree check and is swapped before staging (TOCTOU).
func (c *Client) guardStaged() error {
	out, err := c.git("ls-files", "--stage", "-z")
	if err != nil {
		return err
	}
	return c.guardEntries(out)
}

// The same framed object validation protects fetched trees BEFORE checkout.
func (c *Client) guardTree(ref string) error {
	out, err := c.git("ls-tree", "-r", "-z", "--format=%(objectmode) %(objectname) 0%x09%(path)", ref)
	if err != nil {
		return err
	}
	return c.guardEntries(out)
}

func (c *Client) guardEntries(out string) error {
	var offenders []string
	seen := map[string]bool{}
	type blob struct{ oid, path string }
	var blobs []blob
	for _, ent := range strings.Split(out, "\x00") {
		if strings.TrimSpace(ent) == "" {
			continue
		}
		// format: <mode> <oid> <stage>\t<path>
		tab := strings.IndexByte(ent, '\t')
		if tab < 0 {
			return fmt.Errorf("malformed index entry")
		}
		meta, rel := strings.Fields(ent[:tab]), ent[tab+1:]
		alias := strings.ToLower(rel)
		if seen[alias] {
			return fmt.Errorf("%s: duplicate/case-aliased path in Git tree", rel)
		}
		seen[alias] = true
		if len(meta) != 3 || meta[2] != "0" {
			return fmt.Errorf("unmerged or malformed index entry: %s", rel)
		}
		if meta[0] == "120000" {
			offenders = append(offenders, rel+": symlinks are never synced")
			continue
		}
		if meta[0] != "100644" && meta[0] != "100755" {
			return fmt.Errorf("%s: unsupported index mode %s", rel, meta[0])
		}
		if err := allowedPath(rel); err != nil {
			offenders = append(offenders, err.Error())
			continue
		}
		if strings.HasPrefix(filepath.ToSlash(rel), "vault/") {
			blobs = append(blobs, blob{meta[1], rel})
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		return fmt.Errorf("sync blocked, unsafe staged content:\n  %s", strings.Join(offenders, "\n  "))
	}
	if len(blobs) == 0 {
		return nil
	}
	cmd, cancel := c.command("cat-file", "--batch")
	defer cancel()
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		in.Close()
		if cmd.ProcessState == nil {
			cmd.Cancel()
			cmd.Wait()
		}
	}()
	r := bufio.NewReader(outPipe)
	for _, b := range blobs {
		if _, err := io.WriteString(in, b.oid+"\n"); err != nil {
			return err
		}
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		parts := strings.Fields(line)
		if len(parts) != 3 || parts[0] != b.oid || parts[1] != "blob" {
			return fmt.Errorf("%s: invalid batch object header", b.path)
		}
		size, err := strconv.ParseInt(parts[2], 10, 64)
		header := vault.AgeHeader + "\n"
		if err != nil || size < int64(len(header)) {
			return fmt.Errorf("%s: staged content is not age ciphertext", b.path)
		}
		prefix := make([]byte, len(header))
		if _, err := io.ReadFull(r, prefix); err != nil {
			return err
		}
		if string(prefix) != header {
			return fmt.Errorf("%s: staged content is not age ciphertext", b.path)
		}
		if _, err := io.CopyN(io.Discard, r, size-int64(len(header))); err != nil {
			return err
		}
		if sep, err := r.ReadByte(); err != nil || sep != '\n' {
			return fmt.Errorf("%s: invalid batch frame terminator", b.path)
		}
	}
	in.Close()
	return cmd.Wait()
}

// Guard inspects everything that would be committed (tracked + untracked,
// respecting .gitignore) and returns an error naming every offender.
func (c *Client) Guard() error {
	out, err := c.git("status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return err
	}
	var offenders []string
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if len(line) < 4 {
			continue
		}
		status, rel := line[:2], strings.TrimSpace(line[3:])
		// renames show "old -> new"
		if i := strings.Index(rel, " -> "); i >= 0 {
			rel = rel[i+4:]
		}
		rel = strings.Trim(rel, `"`)
		if strings.HasPrefix(status, "D") || strings.HasSuffix(status, "D") {
			continue // deletions can't leak content
		}
		if err := allowedFile(c.Dir, rel); err != nil {
			offenders = append(offenders, err.Error())
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		return fmt.Errorf("sync blocked, unsafe files present:\n  %s", strings.Join(offenders, "\n  "))
	}
	return nil
}

// Commit stages and commits everything — worktree guard first (fast fail),
// then the authoritative staged-blob guard; on failure the stage is rolled
// back so nothing unsafe lingers in the index.
func (c *Client) Commit(msg string) (bool, error) {
	l, err := fstxn.AcquireContext(c.context(), c.Dir)
	if err != nil {
		return false, err
	}
	defer l.Close()
	return c.commit(msg)
}

func (c *Client) commit(msg string) (bool, error) {
	if err := c.ensureIgnore(); err != nil {
		return false, err
	}
	if err := c.Guard(); err != nil {
		return false, err
	}
	if _, err := c.git("add", "-A"); err != nil {
		return false, err
	}
	if err := c.guardStaged(); err != nil {
		c.git("reset", "-q")
		return false, err
	}
	staged, err := c.git("diff", "--cached", "--name-only")
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(staged) == "" {
		return false, nil
	}
	if _, err := c.git("commit", "-m", msg); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) SetRemote(remote string) error {
	l, err := fstxn.AcquireContext(c.context(), c.Dir)
	if err != nil {
		return err
	}
	defer l.Close()
	return c.setRemote(remote)
}

func (c *Client) setRemote(remote string) error {
	if remote == "" || strings.HasPrefix(remote, "-") || strings.ContainsAny(remote, "\r\n\x00") {
		return fmt.Errorf("invalid sync destination")
	}
	if u, err := url.Parse(remote); err == nil && u.User != nil {
		if _, has := u.User.Password(); has {
			return fmt.Errorf("sync URL must not contain a password/token")
		}
	}
	if _, err := c.git("remote", "get-url", "origin"); err == nil {
		if _, err = c.git("config", "--replace-all", "remote.origin.url", remote); err != nil {
			return err
		}
		// An old pushurl otherwise silently overrides the selected destination.
		if out, err := c.git("config", "--get-all", "remote.origin.pushurl"); err == nil && strings.TrimSpace(out) != "" {
			if _, err := c.git("config", "--unset-all", "remote.origin.pushurl"); err != nil {
				return err
			}
		}
		return nil
	}
	_, err := c.git("remote", "add", "origin", remote)
	return err
}

func (c *Client) RemoteURL() string {
	out, err := c.git("remote", "get-url", "origin")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// DestinationURL is Git's resolved push destination (including URL rewrites).
func (c *Client) DestinationURL() string {
	out, err := c.git("remote", "get-url", "--push", "origin")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// Sync = guarded commit, pull --rebase (tolerating an empty/new remote), push.
func (c *Client) Sync(msg string) error {
	l, err := fstxn.AcquireContext(c.context(), c.Dir)
	if err != nil {
		return err
	}
	defer l.Close()
	return c.SyncLocked(l, c.RemoteURL(), msg)
}

func (c *Client) context() context.Context {
	if c.Context != nil {
		return c.Context
	}
	return context.Background()
}

// SyncLocked requires exclusive ownership through the caller's coherent reload.
func (c *Client) SyncLocked(l *fstxn.Lock, remote, msg string) error {
	if abs, err := filepath.Abs(c.Dir); err != nil || abs != l.Dir() {
		return fmt.Errorf("sync lock directory mismatch")
	}
	if err := c.ensureRepo(); err != nil {
		return err
	}
	if err := c.setRemote(remote); err != nil {
		return err
	}
	if err := c.checkRebase(); err != nil {
		return err
	}
	branch, err := c.git("symbolic-ref", "--short", "HEAD")
	if err != nil {
		return err
	}
	if strings.TrimSpace(branch) != DefaultBranch {
		return fmt.Errorf("sync requires branch %s; switch branches before retrying", DefaultBranch)
	}
	if _, err := c.commit(msg); err != nil {
		return err
	}
	if out, err := c.git("fetch", "origin", DefaultBranch); err != nil {
		benign := strings.Contains(out, "couldn't find remote ref") || // brand-new empty repo
			strings.Contains(out, "no such ref was fetched")
		if !benign {
			return err
		}
	} else {
		if err := c.guardTree("FETCH_HEAD"); err != nil {
			return err
		}
		if _, err := c.git("rebase", "FETCH_HEAD"); err != nil {
			return c.abortRebase(err)
		}
	}
	// Rebase may have produced new objects; validate the final index as well.
	if err := c.guardStaged(); err != nil {
		return err
	}
	_, err = c.git("push", "-u", "origin", DefaultBranch)
	return err
}

// Bootstrap points the config dir at an existing remote and makes the local
// tree match origin/main — the fresh-machine restore path. reset --hard (not
// clone: the dir may already hold local files; not pull: nothing to rebase)
// so fetched tracked files win over anything local.
func (c *Client) Bootstrap(url string) error {
	l, err := fstxn.AcquireContext(c.context(), c.Dir)
	if err != nil {
		return err
	}
	defer l.Close()
	return c.BootstrapLocked(l, url)
}

func (c *Client) BootstrapLocked(l *fstxn.Lock, url string) error {
	if abs, err := filepath.Abs(c.Dir); err != nil || abs != l.Dir() {
		return fmt.Errorf("restore lock directory mismatch")
	}
	if err := c.ensureRepo(); err != nil {
		return err
	}
	if err := c.setRemote(url); err != nil {
		return err
	}
	if _, err := c.git("fetch", "origin", DefaultBranch); err != nil {
		return err
	}
	if err := c.guardTree("FETCH_HEAD"); err != nil {
		return err
	}
	_, err := c.git("reset", "--hard", "FETCH_HEAD")
	return err
}

func (c *Client) Pull() error {
	l, err := fstxn.AcquireContext(c.context(), c.Dir)
	if err != nil {
		return err
	}
	defer l.Close()
	if err := c.checkRebase(); err != nil {
		return err
	}
	if _, err := c.git("fetch", "origin", DefaultBranch); err != nil {
		return err
	}
	if err := c.guardTree("FETCH_HEAD"); err != nil {
		return err
	}
	_, err = c.git("rebase", "FETCH_HEAD")
	if err != nil {
		return c.abortRebase(err)
	}
	return nil
}

func (c *Client) checkRebase() error {
	for _, name := range []string{"rebase-merge", "rebase-apply", "MERGE_HEAD"} {
		if _, err := os.Stat(filepath.Join(c.Dir, ".git", name)); err == nil {
			return fmt.Errorf("unfinished Git operation (%s); resolve or abort it before syncing", name)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (c *Client) abortRebase(cause error) error {
	if c.checkRebase() == nil {
		return cause
	}
	cleanup := *c
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cleanup.Context = ctx
	if _, err := cleanup.git("rebase", "--abort"); err != nil {
		return fmt.Errorf("%w; automatic abort failed: %v; local commits retained, run git rebase --abort before retrying", cause, err)
	}
	return fmt.Errorf("%w; rebase aborted, local commits retained; reconcile conflicting edits before retrying", cause)
}

// --- GitHub bootstrap ---

// CreateGitHubRepo creates a PRIVATE repo for the authenticated user and
// returns its clone URL. Callers must get explicit user confirmation first.
func CreateGitHubRepo(token, name, description string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"name":        name,
		"description": description,
		"private":     true,
		"has_issues":  false,
		"has_wiki":    false,
	})
	req, err := http.NewRequest("POST", "https://api.github.com/user/repos", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var parsed struct {
		CloneURL string `json:"clone_url"`
		Message  string `json:"message"`
		Private  bool   `json:"private"`
		Errors   []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("github: unexpected response (%s)", resp.Status)
	}
	if resp.StatusCode != http.StatusCreated {
		msg := parsed.Message
		if len(parsed.Errors) > 0 {
			msg += ": " + parsed.Errors[0].Message
		}
		return "", fmt.Errorf("github repo creation failed (%s): %s", resp.Status, msg)
	}
	if !parsed.Private {
		return "", fmt.Errorf("github created the repo but it is NOT private — aborting; delete %s and retry", parsed.CloneURL)
	}
	return parsed.CloneURL, nil
}

// ValidateToken checks the PAT and returns the login it belongs to.
func ValidateToken(token string) (string, error) {
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github rejected the token (%s)", resp.Status)
	}
	var u struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return "", err
	}
	return u.Login, nil
}
