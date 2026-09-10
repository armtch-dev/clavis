// Package sshconfig imports the representable subset of OpenSSH configuration.
// It never executes Match exec, proxies, hostname canonicalization or ssh itself.
package sshconfig

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Entry struct {
	Alias        string
	HostName     string
	User         string
	Port         int
	IdentityFile string // first configured identity; OpenSSH itself can try several
	ProxyJump    string
}

type directive struct {
	key      string
	args     []string
	children []directive
}

// Parse evaluates each discovered literal alias against the complete config,
// preserving first-value semantics and active Include context. Relative Includes
// use baseDir at every depth (normally ~/.ssh), not the included file's directory.
// Unknown, unrelated SSH options are ignored. Options requiring execution or
// changing the connection in ways a Profile cannot represent fail explicitly.
func Parse(text string, baseDir, home string) ([]Entry, error) {
	return parseWithDepth(text, baseDir, home, 0)
}

func ParseFile(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	// OpenSSH user config Includes are relative to ~/.ssh even with -F;
	// neither the main file nor a nested include changes that base directory.
	return Parse(string(data), filepath.Join(home, ".ssh"), home)
}

func parseWithDepth(text string, baseDir, home string, depth int) ([]Entry, error) {
	nodes, err := readDirectives(text, baseDir, home, depth)
	if err != nil {
		return nil, err
	}
	var aliases []string
	seen := map[string]bool{}
	var discover func([]directive)
	discover = func(nodes []directive) {
		for _, n := range nodes {
			if n.key == "host" {
				for _, a := range n.args {
					if !strings.ContainsAny(a, "*?!") && !seen[a] {
						seen[a] = true
						aliases = append(aliases, a)
					}
				}
			}
			discover(n.children)
		}
	}
	discover(nodes)
	var entries []Entry
	for _, alias := range aliases {
		values := map[string]string{}
		var evaluate func([]directive, bool)
		evaluate = func(nodes []directive, active bool) {
			for _, n := range nodes {
				switch n.key {
				case "host":
					active = matches(alias, n.args)
				case "include":
					if active {
						evaluate(n.children, active)
					}
				case "proxycommand", "proxyjump":
					// OpenSSH treats these as alternatives: even an explicit
					// ProxyCommand none prevents a later ProxyJump taking effect.
					_, commandSet := values["proxycommand"]
					_, jumpSet := values["proxyjump"]
					if active && !commandSet && !jumpSet {
						values[n.key] = n.args[0]
					}
				default:
					if active {
						if _, set := values[n.key]; !set {
							values[n.key] = n.args[0]
						}
					}
				}
			}
		}
		evaluate(nodes, true)
		e := Entry{Alias: alias, HostName: alias, Port: 22, User: values["user"], IdentityFile: expandHome(values["identityfile"], home), ProxyJump: values["proxyjump"]}
		if v, ok := values["hostname"]; ok {
			e.HostName = v
		}
		if v, ok := values["port"]; ok {
			e.Port, _ = strconv.Atoi(v)
		}
		if e.ProxyJump == "none" {
			e.ProxyJump = ""
		}
		if e.IdentityFile == "none" {
			e.IdentityFile = ""
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func readDirectives(text, baseDir, home string, depth int) ([]directive, error) {
	if depth > 16 {
		return nil, fmt.Errorf("SSH Include nesting exceeds 16 (possible cycle)")
	}
	var nodes []directive
	scanner := bufio.NewScanner(strings.NewReader(text))
	for line := 1; scanner.Scan(); line++ {
		key, args, err := tokenize(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("SSH config line %d: %w", line, err)
		}
		if key == "" {
			continue
		}
		if len(args) == 0 {
			return nil, fmt.Errorf("SSH config line %d: %s requires a value", line, key)
		}
		n := directive{key: key, args: args}
		switch key {
		case "canonicalizehostname":
			if len(args) == 1 && strings.EqualFold(args[0], "no") {
				continue
			}
			return nil, fmt.Errorf("%s requires disabled value 'no' for profile import", key)
		case "proxycommand":
			if len(args) != 1 || !strings.EqualFold(args[0], "none") {
				return nil, fmt.Errorf("%s requires disabled value 'none' for profile import", key)
			}
		case "match", "hostnamecanonicalization":
			return nil, fmt.Errorf("%s is not supported by profile import; resolve this config with OpenSSH before importing", key)
		case "host":
			for _, a := range args {
				if a == "!" || strings.ContainsAny(a, " \t\r\n") {
					return nil, fmt.Errorf("invalid Host pattern %q", a)
				}
			}
		case "include":
			for _, pattern := range args {
				if err := supportedPath(pattern); err != nil {
					return nil, err
				}
				pattern = expandHome(pattern, home)
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(baseDir, pattern)
				}
				files, err := filepath.Glob(pattern)
				if err != nil {
					return nil, fmt.Errorf("Include: %w", err)
				}
				for _, file := range files {
					data, err := os.ReadFile(file)
					if err != nil {
						return nil, fmt.Errorf("Include %s: %w", file, err)
					}
					children, err := readDirectives(string(data), baseDir, home, depth+1)
					if err != nil {
						return nil, fmt.Errorf("Include %s: %w", file, err)
					}
					// OpenSSH restores the caller's active Host context after
					// each file, including individual matches of one Include glob.
					n.children = append(n.children, directive{key: "include", children: children})
				}
			}
		case "hostname", "user", "port", "identityfile", "proxyjump":
			if len(args) != 1 || args[0] == "" {
				return nil, fmt.Errorf("%s requires exactly one non-empty value", key)
			}
			if strings.Contains(args[0], "%") || strings.Contains(args[0], "${") {
				return nil, fmt.Errorf("%s token expansion is not supported by profile import", key)
			}
			if key == "port" {
				port, err := strconv.Atoi(args[0])
				if err != nil || port < 1 || port > 65535 {
					return nil, fmt.Errorf("invalid SSH port %q", args[0])
				}
			}
			if key == "identityfile" {
				if err := supportedPath(args[0]); err != nil {
					return nil, err
				}
			}
		default:
			continue // unrelated transport/UI options are not profile fields
		}
		nodes = append(nodes, n)
	}
	return nodes, scanner.Err()
}

// Split only the directive separator; '=' and '#' inside value tokens are data.
// Quotes can contain whitespace/comments, and escaped quotes stay in the value.
func tokenize(line string) (string, []string, error) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", nil, nil
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), nil, nil
	}
	key := strings.ToLower(line[:i])
	line = strings.TrimLeft(line[i:], " \t")
	if strings.HasPrefix(line, "=") {
		line = strings.TrimLeft(line[1:], " \t")
	}
	var args []string
	for len(line) > 0 && line[0] != '#' {
		var b strings.Builder
		var quote byte
		i := 0
		for i < len(line) {
			c := line[i]
			if quote == 0 && (c == ' ' || c == '\t') {
				break
			}
			if c == '\\' && i+1 < len(line) && (line[i+1] == '"' || line[i+1] == '\'' || line[i+1] == '\\' || quote == 0 && line[i+1] == ' ') {
				i++
				b.WriteByte(line[i])
				i++
				continue
			}
			if quote == 0 && (c == '"' || c == '\'') {
				quote = c
			} else if quote != 0 && c == quote {
				quote = 0
			} else {
				b.WriteByte(c)
			}
			i++
		}
		if quote != 0 {
			return "", nil, fmt.Errorf("unterminated quote")
		}
		args = append(args, b.String())
		line = strings.TrimLeft(line[i:], " \t")
	}
	return key, args, nil
}

func matches(alias string, patterns []string) bool {
	matched := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		rx := regexp.QuoteMeta(p)
		rx = strings.ReplaceAll(strings.ReplaceAll(rx, `\*`, `.*`), `\?`, `.`)
		ok, _ := regexp.MatchString("^"+rx+"$", alias)
		if ok {
			if neg {
				return false
			}
			matched = true
		}
	}
	return matched
}

func supportedPath(path string) error {
	if strings.HasPrefix(path, "~") && path != "~" && !strings.HasPrefix(path, "~/") {
		return fmt.Errorf("named-user tilde expansion is not supported: %q", path)
	}
	if strings.ContainsAny(path, "%") || strings.Contains(path, "${") {
		return fmt.Errorf("SSH path token expansion is not supported: %q", path)
	}
	return nil
}

func expandHome(path, home string) string {
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
