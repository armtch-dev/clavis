// Package cli implements clavis's non-TUI subcommands (doctor, vault
// rekey/reset, ssh-config import). Every function writes plain, script- and
// CI-friendly output to an io.Writer and returns an error — no lipgloss, no
// terminal-only assumptions beyond the interactive key prompt.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/armtch-dev/clavis/internal/gitsync"
	"github.com/armtch-dev/clavis/internal/profile"
	"github.com/armtch-dev/clavis/internal/sshconfig"
	"github.com/armtch-dev/clavis/internal/vault"
)

// Doctor runs a battery of health checks against the clavis install rooted at
// configDir, printing a ✓/✗/⚠ line per check. It returns an error if any hard
// check failed; sync-related findings are informational only.
func Doctor(w io.Writer, configDir string) error {
	hardFailed := false
	ok := func(format string, args ...any) {
		fmt.Fprintf(w, "✓ %s\n", fmt.Sprintf(format, args...))
	}
	fail := func(format string, args ...any) {
		hardFailed = true
		fmt.Fprintf(w, "✗ %s\n", fmt.Sprintf(format, args...))
	}
	info := func(format string, args ...any) {
		fmt.Fprintf(w, "⚠ %s\n", fmt.Sprintf(format, args...))
	}

	fmt.Fprintf(w, "clavis doctor — %s\n\n", configDir)

	// Config directory: exists, is a dir, and isn't group/world accessible.
	if fi, err := os.Stat(configDir); err != nil {
		fail("config directory: %v", err)
	} else if !fi.IsDir() {
		fail("config directory: %s exists but is not a directory", configDir)
	} else if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		fail("config directory permissions %04o are group/world accessible (want 0700)", perm)
	} else {
		ok("config directory (%s, %04o)", configDir, fi.Mode().Perm())
	}

	// Vault presence gates every check below it — if it's not initialized
	// there is nothing to unlock or verify, and prompting for a key would be
	// pointless (and would hang non-interactive callers).
	v, err := vault.Load(configDir)
	if err != nil {
		fail("vault: %v", err)
	} else {
		ok("vault initialized (recipient %s)", v.Recipient())

		identity, source := vault.ResolveIdentity()
		if identity == "" {
			identity, err = promptKey(w)
			source = "interactive prompt"
		}
		switch {
		case err != nil:
			fail("master key: %v", err)
		case identity == "":
			fail("master key: no key provided")
		default:
			ok("master key resolved (%s)", source)
			if err := v.Unlock(identity); err != nil {
				fail("vault unlock: %v", err)
			} else {
				ok("vault unlocked")
				if err := v.VerifyAll(); err != nil {
					fail("vault integrity check: %v", err)
				} else {
					ok("vault integrity check (all secrets decrypt)")
				}
			}
		}
	}

	// Git sync is optional — report status, never fail doctor over it.
	gc := gitsync.New(configDir, "")
	if !gc.IsRepo() {
		info("git sync not configured (no repository at %s)", configDir)
	} else if remote := gc.RemoteURL(); remote == "" {
		info("git repository present but no remote configured")
	} else {
		ok("git sync remote: %s", remote)
	}

	if path, err := exec.LookPath("ssh"); err != nil {
		fail("ssh binary not found on PATH: %v", err)
	} else {
		ok("ssh binary on PATH (%s)", path)
	}

	fmt.Fprintln(w)
	if hardFailed {
		fmt.Fprintln(w, "doctor: one or more checks failed")
		return errors.New("doctor: one or more checks failed")
	}
	fmt.Fprintln(w, "doctor: all checks passed")
	return nil
}

// VaultRekey displays a prepared key and asks for acknowledgement before commit.
func VaultRekey(w io.Writer, configDir string) error {
	return VaultRekeyWithInput(w, os.Stdin, configDir)
}

// VaultRekeyWithInput shares one buffered reader across key and confirmation
// prompts, including piped input. No destructive retirement precedes successful
// key output (and Flush, where supported) plus an explicit "saved" response.
func VaultRekeyWithInput(w io.Writer, r io.Reader, configDir string) error {
	v, err := vault.Load(configDir)
	if err != nil {
		return err
	}

	input := bufio.NewReader(r)
	identity, source := vault.ResolveIdentity()
	if identity == "" {
		if r == os.Stdin && term.IsTerminal(int(os.Stdin.Fd())) {
			identity, err = promptKey(w)
		} else {
			if _, err = fmt.Fprint(w, "Enter clavis master key (AGE-SECRET-KEY-1...): "); err != nil {
				return err
			}
			if f, ok := w.(interface{ Flush() error }); ok {
				if err := f.Flush(); err != nil {
					return err
				}
			}
			identity, err = input.ReadString('\n')
			if errors.Is(err, io.EOF) {
				err = nil
			}
		}
		if err != nil {
			return fmt.Errorf("reading master key: %w", err)
		}
		source = "interactive prompt"
	}
	if err := v.Unlock(identity); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "vault unlocked (key via %s)\n", source); err != nil {
		return err
	}

	rotation, err := v.PrepareRekey()
	if err != nil {
		return fmt.Errorf("rekey failed: %w", err)
	}
	defer rotation.Close()
	newIdentity := rotation.Key()
	if err := PrintKeyBanner(w, newIdentity); err != nil {
		return fmt.Errorf("new key output failed; rotation aborted: %w", err)
	}
	if _, err := fmt.Fprint(w, "Store the NEW key now. The old vault is still active.\nType \"saved\" only after storing the new key outside this machine: "); err != nil {
		return err
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		if err := f.Flush(); err != nil {
			return fmt.Errorf("new key output failed; rotation aborted: %w", err)
		}
	}
	line, err := input.ReadString('\n')
	if err != nil {
		return fmt.Errorf("rotation aborted before key acknowledgement: %w", err)
	}
	if strings.TrimSpace(line) != "saved" {
		return errors.New("rotation aborted: new key was not acknowledged as saved")
	}
	if err := rotation.Commit(); err != nil {
		return fmt.Errorf("rekey failed (retain both keys and the local recovery journal; storage recovery may be needed): %w", err)
	}
	if _, err := fmt.Fprintln(w, "\nVault rotated. The new key unlocks the current generation; retain the old key for historical Git backups.\nA ciphertext-only recovery backup is kept locally until the next storage change.\nStale FIDO enrollment was removed. Unlock with the new key and re-enroll your security key in Settings.\nSync from this machine, then use the NEW key on every other machine. Update CLAVIS_KEY, key files, or cached keys as applicable."); err != nil {
		return fmt.Errorf("rotation committed using the key you saved, but status output failed: %w", err)
	}

	if source == "macOS Keychain" {
		if err := vault.SaveToKeychain(newIdentity); err != nil {
			fmt.Fprintf(w, "warning: failed to update macOS Keychain entry: %v\n", err)
		} else {
			fmt.Fprintln(w, "macOS Keychain entry updated with the new key.")
		}
	}
	return nil
}

// VaultReset wipes every stored secret and mints a fresh identity — the
// lost-key escape hatch. It requires the user to type "reset" (read from r)
// before touching anything. Profile metadata is left intact; each profile's
// credentials must be re-added afterwards.
func VaultReset(w io.Writer, r io.Reader, configDir string) error {
	fmt.Fprintln(w, "WARNING: this permanently wipes ALL stored credentials in this vault.")
	fmt.Fprintln(w, "Every profile will need its password/key re-entered before it can connect again.")
	fmt.Fprintln(w, "Profile metadata (names, hosts, users, tags) is preserved.")
	fmt.Fprint(w, `Type "reset" to confirm: `)

	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	if strings.TrimSpace(line) != "reset" {
		return errors.New("reset aborted: confirmation text did not match")
	}

	_, newIdentity, err := vault.Reset(configDir)
	if err != nil {
		return fmt.Errorf("reset failed: %w", err)
	}

	fmt.Fprintln(w, "\nvault reset: all secrets wiped, a new master key has been generated.")
	PrintKeyBanner(w, newIdentity)

	if vault.HasKeychain() {
		// The keychain still holds the now-useless old key; refresh it so a
		// later ResolveIdentity() doesn't hand back a key that no longer
		// matches the vault's recipient.
		if err := vault.SaveToKeychain(newIdentity); err != nil {
			fmt.Fprintf(w, "warning: failed to update macOS Keychain entry: %v\n", err)
		} else {
			fmt.Fprintln(w, "macOS Keychain entry updated with the new key.")
		}
	}

	store, err := profile.LoadStore(configDir)
	if err != nil {
		fmt.Fprintf(w, "warning: could not load profiles.json to list affected profiles: %v\n", err)
		return nil
	}
	if len(store.Profiles) == 0 {
		fmt.Fprintln(w, "no profiles are stored; nothing further to do.")
		return nil
	}
	fmt.Fprintf(w, "\n%d profile(s) need credentials re-added:\n", len(store.Profiles))
	for _, p := range store.Profiles {
		fmt.Fprintf(w, "  - %s (%s@%s)\n", p.Name, p.User, p.Host)
	}
	return nil
}

// Uninstall removes clavis completely: the config dir (vault, profiles,
// scripts, machine-local secrets, the sync repo clone), the macOS Keychain
// entry, and the binary itself. A synced remote repository is deliberately
// left alone — it's the user's encrypted backup. exe may be empty (tests):
// binary removal is skipped.
func Uninstall(w io.Writer, r io.Reader, configDir, exe string) error {
	fmt.Fprintln(w, "WARNING: this permanently removes clavis and ALL saved data on this machine:")
	fmt.Fprintf(w, "  - %s (vault, profiles, scripts, machine-local secrets, sync repo)\n", configDir)
	if runtime.GOOS == "darwin" {
		fmt.Fprintln(w, "  - the master-key entry in the macOS Keychain (if cached)")
	}
	if exe != "" {
		fmt.Fprintf(w, "  - the clavis binary at %s\n", exe)
	}
	fmt.Fprintln(w, "A synced GitHub repository is NOT touched — if you ever synced, your")
	fmt.Fprintln(w, "encrypted config survives there and can be restored with your master key.")
	fmt.Fprint(w, `Type "uninstall" to confirm: `)

	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	if strings.TrimSpace(line) != "uninstall" {
		return errors.New("uninstall aborted: confirmation text did not match")
	}

	vault.DeleteFromKeychain()
	if err := os.RemoveAll(configDir); err != nil {
		return fmt.Errorf("removing %s: %w", configDir, err)
	}
	fmt.Fprintf(w, "removed %s\n", configDir)
	if exe != "" {
		// Unlinking the running binary is fine on unix; the process keeps
		// its already-mapped image until exit.
		if err := os.Remove(exe); err != nil {
			fmt.Fprintf(w, "could not remove the binary (%v) — remove it manually:\n  sudo rm %s\n", err, exe)
		} else {
			fmt.Fprintf(w, "removed %s\n", exe)
		}
	}
	fmt.Fprintln(w, "clavis is uninstalled.")
	return nil
}

// ImportSSHConfig parses an OpenSSH config (path, or ~/.ssh/config if path is
// empty) and adds a profile for every entry whose alias doesn't collide with
// an existing profile name. When an entry has a readable IdentityFile, its
// contents are stored in the vault (this works while locked — writes are
// recipient-only encryption); otherwise the profile is still added with
// Auth=[AuthKey] but flagged as missing a credential, which doctor will catch.
func ImportSSHConfig(w io.Writer, configDir, path string) error {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolving home directory: %w", err)
		}
		path = filepath.Join(home, ".ssh", "config")
	}

	entries, err := sshconfig.ParseFile(path)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(entries) == 0 {
		fmt.Fprintf(w, "no importable hosts found in %s\n", path)
		return nil
	}

	store, err := profile.LoadStore(configDir)
	if err != nil {
		return fmt.Errorf("loading profile store: %w", err)
	}
	v, err := vault.Load(configDir)
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	currentUser := ""
	if u, err := user.Current(); err == nil {
		currentUser = u.Username
	}

	type outcome struct{ alias, status string }
	var results []outcome
	imported := 0

	for _, e := range entries {
		if store.ByName(e.Alias) != nil {
			results = append(results, outcome{e.Alias, "skipped (a profile with this name already exists)"})
			continue
		}

		userName := e.User
		if userName == "" {
			userName = currentUser
		}

		added, err := store.Add(profile.Profile{
			Name:      e.Alias,
			Host:      e.HostName,
			Port:      e.Port,
			User:      userName,
			ProxyJump: e.ProxyJump,
			Auth:      []profile.AuthKind{profile.AuthKey},
		})
		if err != nil {
			results = append(results, outcome{e.Alias, fmt.Sprintf("skipped (%v)", err)})
			continue
		}
		imported++

		switch {
		case e.IdentityFile == "":
			results = append(results, outcome{e.Alias, "imported — WARNING: no IdentityFile in ssh config, credential missing (doctor will flag it)"})
		default:
			keyData, rerr := os.ReadFile(e.IdentityFile)
			switch {
			case rerr != nil:
				results = append(results, outcome{e.Alias, fmt.Sprintf("imported — WARNING: identity file %s unreadable (%v), credential missing (doctor will flag it)", e.IdentityFile, rerr)})
			default:
				if perr := v.Put(added.KeySecret(), keyData); perr != nil {
					results = append(results, outcome{e.Alias, fmt.Sprintf("imported — WARNING: failed to store key in vault (%v), credential missing (doctor will flag it)", perr)})
				} else {
					results = append(results, outcome{e.Alias, "imported (key stored in vault)"})
				}
			}
		}
	}

	if err := store.Save(); err != nil {
		return fmt.Errorf("saving profile store: %w", err)
	}

	fmt.Fprintf(w, "imported %d of %d host(s) from %s\n\n", imported, len(entries), path)
	for _, r := range results {
		fmt.Fprintf(w, "  %-20s %s\n", r.alias, r.status)
	}
	return nil
}

// PrintKeyBanner prints identity inside a hard-to-miss box, used whenever a
// master key is first shown or replaced (init, rekey, reset).
func PrintKeyBanner(w io.Writer, identity string) error {
	line := strings.Repeat("=", 70)
	banner := fmt.Sprintf("%s\n  YOUR CLAVIS MASTER KEY — SHOWN EXACTLY ONCE\n\n  %s\n\n  Store this OUTSIDE this machine — a password manager or printed\n  copy in a safe. Clavis never writes a plaintext key into its config.\n  Without this key, you cannot recover the vault's secrets.\n%s\n", line, identity, line)
	n, err := io.WriteString(w, banner)
	if err == nil && n != len(banner) {
		err = io.ErrShortWrite
	}
	return err
}

// promptKey reads a master key from the terminal with no echo, falling back
// to a plain line read when stdin isn't a terminal (e.g. piped input in
// scripts/tests).
func promptKey(w io.Writer) (string, error) {
	fmt.Fprint(w, "Enter clavis master key (AGE-SECRET-KEY-1...): ")

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(w)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
