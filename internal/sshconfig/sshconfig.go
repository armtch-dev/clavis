package sshconfig

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Entry represents a parsed SSH config host entry.
type Entry struct {
	Alias        string // the Host token
	HostName     string // HostName directive, or Alias if absent
	User         string // may be empty
	Port         int    // 22 if absent
	IdentityFile string // first IdentityFile, ~ expanded to the home dir, empty if none
	ProxyJump    string // may be empty
}

// Parse parses ssh_config text. baseDir is used to resolve relative Include
// globs (typically ~/.ssh); home is the user home dir for ~ expansion.
func Parse(text string, baseDir, home string) ([]Entry, error) {
	return parseWithDepth(text, baseDir, home, 0)
}

// ParseFile reads path and parses it (baseDir = dir of path, home = os.UserHomeDir()).
func ParseFile(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	baseDir := filepath.Dir(path)
	return Parse(string(data), baseDir, home)
}

func parseWithDepth(text string, baseDir, home string, depth int) ([]Entry, error) {
	const maxDepth = 8
	if depth > maxDepth {
		return nil, nil
	}

	var entries []Entry
	seenAliases := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(text))
	var currentEntries []*Entry // One entry per alias on current Host line

	for scanner.Scan() {
		line := scanner.Text()

		// Strip comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)

		// Skip blank lines
		if line == "" {
			continue
		}

		// Parse directive
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 1 {
			continue
		}

		directive := strings.ToLower(parts[0])
		var value string
		if len(parts) > 1 {
			value = parts[1]
		}

		// Handle key=value syntax
		if strings.Contains(directive, "=") {
			kv := strings.SplitN(directive, "=", 2)
			directive = strings.ToLower(kv[0])
			if len(kv) > 1 {
				value = kv[1]
				if len(parts) > 1 {
					value = kv[1] + " " + value
				}
			}
		} else if strings.Contains(value, "=") {
			// Value contains = sign
			kv := strings.SplitN(value, "=", 2)
			if len(kv) > 1 {
				value = kv[1]
			}
		}

		value = strings.TrimSpace(value)

		switch directive {
		case "host":
			// Save previous entries if they exist
			for _, entry := range currentEntries {
				if entry.Alias != "" && !seenAliases[entry.Alias] {
					entries = append(entries, *entry)
					seenAliases[entry.Alias] = true
				}
			}
			currentEntries = nil

			// Parse Host patterns
			patterns := strings.Fields(value)
			for _, pattern := range patterns {
				// Skip wildcards and negations
				if strings.ContainsAny(pattern, "*?") || strings.HasPrefix(pattern, "!") {
					continue
				}

				// Create new entry for this pattern
				newEntry := &Entry{
					Alias:    pattern,
					HostName: pattern,
					Port:     22,
				}
				currentEntries = append(currentEntries, newEntry)
			}

		case "hostname":
			for _, entry := range currentEntries {
				if entry.HostName == entry.Alias {
					entry.HostName = stripQuotes(value)
				}
			}

		case "user":
			for _, entry := range currentEntries {
				if entry.User == "" {
					entry.User = stripQuotes(value)
				}
			}

		case "port":
			for _, entry := range currentEntries {
				if entry.Port == 22 {
					port, err := strconv.Atoi(stripQuotes(value))
					if err == nil && port > 0 {
						entry.Port = port
					}
				}
			}

		case "identityfile":
			for _, entry := range currentEntries {
				if entry.IdentityFile == "" {
					idFile := stripQuotes(value)
					idFile = expandHome(idFile, home)
					entry.IdentityFile = idFile
				}
			}

		case "proxyjump":
			for _, entry := range currentEntries {
				if entry.ProxyJump == "" {
					entry.ProxyJump = stripQuotes(value)
				}
			}

		case "include":
			// Save current entries before processing includes
			for _, entry := range currentEntries {
				if entry.Alias != "" && !seenAliases[entry.Alias] {
					entries = append(entries, *entry)
					seenAliases[entry.Alias] = true
				}
			}
			currentEntries = nil

			// Parse Include directive - may appear outside Host blocks
			includes := strings.Fields(value)
			for _, include := range includes {
				include = expandHome(include, home)
				// Resolve as glob relative to baseDir
				pattern := include
				if !filepath.IsAbs(include) {
					pattern = filepath.Join(baseDir, include)
				}

				files, err := filepath.Glob(pattern)
				if err != nil {
					continue
				}

				for _, file := range files {
					data, err := os.ReadFile(file)
					if err != nil {
						continue
					}

					newBaseDir := filepath.Dir(file)
					subEntries, _ := parseWithDepth(string(data), newBaseDir, home, depth+1)

					for _, entry := range subEntries {
						if !seenAliases[entry.Alias] {
							entries = append(entries, entry)
							seenAliases[entry.Alias] = true
						}
					}
				}
			}
		}
	}

	// Save the remaining entries if they exist
	for _, entry := range currentEntries {
		if entry.Alias != "" && !seenAliases[entry.Alias] {
			entries = append(entries, *entry)
			seenAliases[entry.Alias] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func expandHome(path, home string) string {
	if strings.HasPrefix(path, "~") {
		if home == "" {
			u, err := user.Current()
			if err != nil {
				return path
			}
			home = u.HomeDir
		}
		return filepath.Join(home, path[1:])
	}
	return path
}
