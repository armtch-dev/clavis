package vault

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Unlock sources, tried in order by ResolveIdentity:
//  1. CLAVIS_KEY            — the identity itself (for scripts/CI)
//  2. CLAVIS_KEY_FILE       — path to a file holding the identity
//  3. macOS Keychain        — only if the user opted in (SaveToKeychain)
//
// If all miss, the caller falls back to an interactive prompt.

const (
	EnvKey     = "CLAVIS_KEY"
	EnvKeyFile = "CLAVIS_KEY_FILE"

	keychainService = "clavis-vault"
	keychainAccount = "master-key"
)

// ResolveIdentity returns (identity, source) from non-interactive sources,
// or ("", "") if the user must be prompted.
func ResolveIdentity() (string, string) {
	if k := strings.TrimSpace(os.Getenv(EnvKey)); k != "" {
		return k, "env " + EnvKey
	}
	if p := strings.TrimSpace(os.Getenv(EnvKeyFile)); p != "" {
		if raw, err := os.ReadFile(p); err == nil {
			if k := firstKeyLine(string(raw)); k != "" {
				return k, "key file " + p
			}
		}
	}
	if k, err := LoadFromKeychain(); err == nil && k != "" {
		return k, "macOS Keychain"
	}
	return "", ""
}

// firstKeyLine tolerates age-keygen output files (comment lines start with #).
func firstKeyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return line
		}
	}
	return ""
}

// SaveToKeychain stores the identity in the login keychain (opt-in; weakens
// the "key lives elsewhere" guarantee, the settings UI says so).
func SaveToKeychain(identity string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("keychain storage is only available on macOS")
	}
	cmd := exec.Command("security", "add-generic-password", "-U",
		"-s", keychainService, "-a", keychainAccount, "-w", identity)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("security add-generic-password: %v: %s", err, out)
	}
	return nil
}

func LoadFromKeychain() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("keychain storage is only available on macOS")
	}
	out, err := exec.Command("security", "find-generic-password",
		"-s", keychainService, "-a", keychainAccount, "-w").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func DeleteFromKeychain() error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	out, err := exec.Command("security", "delete-generic-password",
		"-s", keychainService, "-a", keychainAccount).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "could not be found") {
		return fmt.Errorf("security delete-generic-password: %v", err)
	}
	return nil
}

func base64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func debase64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
