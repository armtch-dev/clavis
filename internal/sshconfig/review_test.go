package sshconfig

import (
	"os/exec"
	"strings"
	"testing"
)

func TestReviewOpenSSHCompatibility(t *testing.T) {
	for _, tc := range []struct{ name, text, field, want string }{
		{"case-positive", "Host WEB*\n User Wrong\nHost web\n User Correct\n", "user", "Correct"},
		{"case-negated", "Host * !WEB*\n User Correct\nHost web\n User Wrong\n", "user", "Correct"},
		{"case-matching-negation", "Host * !web*\n User Wrong\nHost web\n User Correct\n", "user", "Correct"},
		{"canonicalization-disabled", "Host web\n CanonicalizeHostname no\n User Deploy\n", "user", "Deploy"},
		{"proxycommand-disabled", "Host web\n ProxyCommand none\n User Deploy\n", "user", "Deploy"},
		{"quoted-backslash-space", "Host web\n IdentityFile \"/tmp/key\\ name\"\n", "identityfile", "/tmp/key\\ name"},
		{"quoted-space", "Host web\n IdentityFile \"/tmp/key name\"\n", "identityfile", "/tmp/key name"},
		{"quoted-backslash", "Host web\n IdentityFile \"/tmp/key\\\\name\"\n", "identityfile", "/tmp/key\\name"},
		{"quoted-escaped-quote", "Host web\n IdentityFile \"/tmp/key\\\"name\"\n", "identityfile", "/tmp/key\"name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("ssh", "-G", "-F", "/dev/stdin", "--", "web")
			cmd.Stdin = strings.NewReader(tc.text)
			out, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(out), tc.field+" "+tc.want+"\n") {
				t.Fatalf("OpenSSH disagrees with fixture: %s", out)
			}
			entries, err := Parse(tc.text, t.TempDir(), "/home/fixture")
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("entries: %+v", entries)
			}
			got := entries[0].User
			if tc.field == "identityfile" {
				got = entries[0].IdentityFile
			}
			if got != tc.want {
				t.Fatalf("parser %s=%q, OpenSSH=%q", tc.field, got, tc.want)
			}
		})
	}
}

func TestReviewActiveOrMalformedUnsupportedOptionsStillRefused(t *testing.T) {
	for _, option := range []string{"CanonicalizeHostname yes", "CanonicalizeHostname always", "CanonicalizeHostname no extra", "ProxyCommand ssh proxy", "ProxyCommand none extra"} {
		if _, err := Parse("Host web\n "+option+"\n User Deploy\n", t.TempDir(), "/home/fixture"); err == nil {
			t.Errorf("accepted %s", option)
		}
	}
}

func TestReviewDisabledProxyCommandPrecedence(t *testing.T) {
	text := "Host web\n ProxyCommand none\n ProxyJump bastion\n User Deploy\n"
	cmd := exec.Command("ssh", "-G", "-F", "/dev/stdin", "--", "web")
	cmd.Stdin = strings.NewReader(text)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var jump string
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(line, "proxyjump "); ok {
			jump = value
		}
	}
	entries, err := Parse(text, t.TempDir(), "/home/fixture")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ProxyJump != jump {
		t.Fatalf("disabled proxy precedence: parser %+v, OpenSSH jump=%q", entries, jump)
	}
}
