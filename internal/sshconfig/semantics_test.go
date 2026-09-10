package sshconfig

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSupportedOpenSSHSemantics(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "defaults.conf")
	if err := os.WriteFile(inc, []byte("User\tDeploy\nIdentityFile \"/Tmp/Key #Case=Value\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	text := "Host web* !web-no\n Include \"" + inc + "\"\nHost web web-no\n HostName=Case.Example\n Port = 22\n Port 2222\n ProxyJump JumpUser@Bastion\nHost web\n User Later\nHost *\n User Default\n IdentityFile /Tmp/Fallback\n"
	entries, err := Parse(text, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Alias: "web", HostName: "Case.Example", User: "Deploy", Port: 22, IdentityFile: "/Tmp/Key #Case=Value", ProxyJump: "JumpUser@Bastion"},
		{Alias: "web-no", HostName: "Case.Example", User: "Default", Port: 22, IdentityFile: "/Tmp/Fallback", ProxyJump: "JumpUser@Bastion"},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("got %+v; want %+v", entries, want)
	}
	// Reference executes only -G against this synthetic config: no connections,
	// Match exec, ProxyCommand execution, or real user config is involved.
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH reference unavailable")
	}
	for _, e := range entries {
		out, err := exec.Command(ssh, "-G", "-F", path, "--", e.Alias).Output()
		if err != nil {
			t.Fatal(err)
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(out), "\n") {
			k, v, ok := strings.Cut(line, " ")
			if ok {
				if _, set := values[k]; !set {
					values[k] = v
				}
			}
		}
		for k, want := range map[string]string{"hostname": strings.ToLower(e.HostName), "user": e.User, "port": "22", "identityfile": e.IdentityFile, "proxyjump": e.ProxyJump} {
			if got := values[k]; got != want {
				t.Errorf("OpenSSH %s %s=%q; parser %q", e.Alias, k, got, want)
			}
		}
	}
}

func TestDefaultsAndFirstValuesAreNotSentinels(t *testing.T) {
	got, err := Parse("User=Deploy\nHost *\n Port 22\nHost Alias\n HostName Alias\n HostName Wrong\n Port 2200\n IdentityFile /Tmp/Key#Tag=Value\n", t.TempDir(), "/home/test")
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{Alias: "Alias", HostName: "Alias", User: "Deploy", Port: 22, IdentityFile: "/Tmp/Key#Tag=Value"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v; want %+v", got, want)
	}
}

func TestMalformedAndUnsupportedConfigFailsExplicitly(t *testing.T) {
	for _, text := range []string{
		"Host x\n Port invalid", "Host x\n Port 65536", "Host x\n User", "Host x\n User alice bob",
		"Host x\n IdentityFile \"unclosed", "Host", "Host x\n Include [", "Host x\n Match exec true\n User other",
	} {
		if got, err := Parse(text, t.TempDir(), "/home/test"); err == nil {
			t.Errorf("silently accepted %q: %+v", text, got)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "loop")
	if err := os.WriteFile(path, []byte("Include "+path), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFile(path); err == nil {
		t.Fatal("include cycle silently truncated")
	}
}

func TestIncludeScopeAgainstOpenSSH(t *testing.T) {
	dir := t.TempDir()
	for name, text := range map[string]string{
		"a.conf": "Host other\n User Other\n",
		"b.conf": "Port 2222\n",
		"config": "Host target\n Include " + filepath.Join(dir, "*.conf") + "\n User Target\nHost other\nHost *\n User Default\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := ParseFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH unavailable")
	}
	for _, e := range entries {
		out, err := exec.Command(ssh, "-G", "-F", filepath.Join(dir, "config"), "--", e.Alias).Output()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "user "+e.User+"\n") || !strings.Contains(string(out), fmt.Sprintf("port %d\n", e.Port)) {
			t.Errorf("Include scope mismatch for %+v: %s", e, out)
		}
	}
}

func TestParseFileRelativeIncludesUseUserSSHDirectory(t *testing.T) {
	home, source := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "defaults"), []byte("User Correct\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "defaults"), []byte("User Wrong\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(source, "config")
	if err := os.WriteFile(path, []byte("Include defaults\nHost imported\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ParseFile(path)
	if err != nil || len(got) != 1 || got[0].User != "Correct" {
		t.Fatalf("relative Include resolved beside -F file instead of ~/.ssh: %+v, %v", got, err)
	}
}
