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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	Branch   string `json:"branch,omitempty"`
	AutoSync bool   `json:"auto_sync"`
}

type Client struct {
	Dir   string // the clavis config dir == the repo worktree
	Token string // decrypted PAT; lives only in memory
}

func New(dir, token string) *Client { return &Client{Dir: dir, Token: token} }

func (c *Client) git(args ...string) (string, error) {
	full := append([]string{
		"-c", "credential.helper=",
		"-c", "credential.helper=" + credHelper,
		"-c", "user.name=clavis",
		"-c", "user.email=clavis@localhost",
	}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), tokenEnv+"="+c.Token, "GIT_TERMINAL_PROMPT=0")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("git %s: %v\n%s", strings.Join(args, " "), err, sanitize(out.String(), c.Token))
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
	return os.WriteFile(filepath.Join(c.Dir, ".gitignore"), []byte(ignore), 0o600)
}

// allowedPath is the sync allowlist: only these repo-relative paths may ever
// be committed. Content checks happen separately (worktree pre-check and
// staged-blob check).
func allowedPath(rel string) error {
	rel = filepath.ToSlash(rel)
	switch rel {
	case "profiles.json", "config.json", "vault.meta", ".gitignore", "README.md":
		return nil
	}
	if strings.HasPrefix(rel, "vault/") {
		if !strings.HasSuffix(rel, ".age") {
			return fmt.Errorf("%s: only .age files may live in vault/", rel)
		}
		return nil
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
	head := make([]byte, len(vault.AgeHeader))
	if _, err := io.ReadFull(f, head); err != nil || string(head) != vault.AgeHeader {
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
	var offenders []string
	for _, ent := range strings.Split(out, "\x00") {
		if strings.TrimSpace(ent) == "" {
			continue
		}
		// format: <mode> <oid> <stage>\t<path>
		tab := strings.IndexByte(ent, '\t')
		if tab < 0 {
			continue
		}
		meta, rel := strings.Fields(ent[:tab]), ent[tab+1:]
		if len(meta) < 1 {
			continue
		}
		if meta[0] == "120000" {
			offenders = append(offenders, rel+": symlinks are never synced")
			continue
		}
		if err := allowedPath(rel); err != nil {
			offenders = append(offenders, err.Error())
			continue
		}
		if strings.HasPrefix(filepath.ToSlash(rel), "vault/") {
			blob, err := c.git("cat-file", "blob", ":"+rel)
			if err != nil || !strings.HasPrefix(blob, vault.AgeHeader) {
				offenders = append(offenders, rel+": staged content is not age ciphertext — refusing to sync")
			}
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		return fmt.Errorf("sync blocked, unsafe staged content:\n  %s", strings.Join(offenders, "\n  "))
	}
	return nil
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
	staged, _ := c.git("diff", "--cached", "--name-only")
	if strings.TrimSpace(staged) == "" {
		return false, nil
	}
	if _, err := c.git("commit", "-m", msg); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) SetRemote(url string) error {
	if _, err := c.git("remote", "get-url", "origin"); err == nil {
		_, err = c.git("remote", "set-url", "origin", url)
		return err
	}
	_, err := c.git("remote", "add", "origin", url)
	return err
}

func (c *Client) RemoteURL() string {
	out, err := c.git("remote", "get-url", "origin")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// Sync = guarded commit, pull --rebase (tolerating an empty/new remote), push.
func (c *Client) Sync(msg string) error {
	if _, err := c.Commit(msg); err != nil {
		return err
	}
	if out, err := c.git("pull", "--rebase", "origin", DefaultBranch); err != nil {
		benign := strings.Contains(out, "couldn't find remote ref") || // brand-new empty repo
			strings.Contains(out, "no such ref was fetched")
		if !benign {
			return err
		}
	}
	_, err := c.git("push", "-u", "origin", DefaultBranch)
	return err
}

func (c *Client) Pull() error {
	_, err := c.git("pull", "--rebase", "origin", DefaultBranch)
	return err
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
