package sshconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	home := "/home/testuser"

	tests := []struct {
		name    string
		text    string
		baseDir string
		want    []Entry
	}{
		{
			name:    "basic block",
			text:    "Host example\n  HostName example.com\n  User alice\n  Port 2222\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example",
					HostName: "example.com",
					User:     "alice",
					Port:     2222,
				},
			},
		},
		{
			name:    "multiple patterns on one Host line",
			text:    "Host web db\n  HostName prod.local\n  User admin\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "web",
					HostName: "prod.local",
					User:     "admin",
					Port:     22,
				},
				{
					Alias:    "db",
					HostName: "prod.local",
					User:     "admin",
					Port:     22,
				},
			},
		},
		{
			name:    "wildcard skipping",
			text:    "Host *.example.com\n  User alice\n",
			baseDir: "/tmp",
			want:    []Entry{},
		},
		{
			name:    "negation skipping",
			text:    "Host !example.com\n  User alice\n",
			baseDir: "/tmp",
			want:    []Entry{},
		},
		{
			name:    "mixed patterns with wildcards",
			text:    "Host example *.local !staging\n  HostName example.com\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example",
					HostName: "example.com",
					Port:     22,
				},
			},
		},
		{
			name:    "key=value syntax",
			text:    "Host server1\n  HostName=server1.local\n  User=bob\n  Port=3333\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "server1",
					HostName: "server1.local",
					User:     "bob",
					Port:     3333,
				},
			},
		},
		{
			name:    "quoted values",
			text:    "Host quotedhost\n  HostName \"quoted.example.com\"\n  User \"alice\"\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "quotedhost",
					HostName: "quoted.example.com",
					User:     "alice",
					Port:     22,
				},
			},
		},
		{
			name: "comments",
			text: `# Full line comment
Host example # trailing comment
  HostName example.com
  # Another comment
  User alice
`,
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example",
					HostName: "example.com",
					User:     "alice",
					Port:     22,
				},
			},
		},
		{
			name:    "tilde expansion in IdentityFile",
			text:    "Host example\n  HostName example.com\n  IdentityFile ~/.ssh/id_rsa\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:        "example",
					HostName:     "example.com",
					IdentityFile: "/home/testuser/.ssh/id_rsa",
					Port:         22,
				},
			},
		},
		{
			name:    "default port 22",
			text:    "Host example\n  HostName example.com\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example",
					HostName: "example.com",
					Port:     22,
				},
			},
		},
		{
			name: "first-value-wins",
			text: `Host example
  User alice
  User bob
  Port 2222
  Port 3333
  IdentityFile ~/.ssh/id_rsa
  IdentityFile ~/.ssh/id_ed25519
`,
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:        "example",
					HostName:     "example",
					User:         "alice",
					Port:         2222,
					IdentityFile: "/home/testuser/.ssh/id_rsa",
				},
			},
		},
		{
			name: "duplicate alias dropped",
			text: `Host example
  User alice
  HostName example.com

Host example
  User bob
  HostName other.com
`,
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example",
					HostName: "example.com",
					User:     "alice",
					Port:     22,
				},
			},
		},
		{
			name:    "default HostName equals Alias",
			text:    "Host example\n  User alice\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example",
					HostName: "example",
					User:     "alice",
					Port:     22,
				},
			},
		},
		{
			name:    "ProxyJump directive",
			text:    "Host example\n  HostName example.com\n  ProxyJump bastion\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:     "example",
					HostName:  "example.com",
					ProxyJump: "bastion",
					Port:      22,
				},
			},
		},
		{
			name:    "case-insensitive directives",
			text:    "host example\n  hostname example.com\n  user alice\n  port 2222\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example",
					HostName: "example.com",
					User:     "alice",
					Port:     2222,
				},
			},
		},
		{
			name:    "blank lines ignored",
			text:    "Host example\n\n  HostName example.com\n\n  User alice\n\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example",
					HostName: "example.com",
					User:     "alice",
					Port:     22,
				},
			},
		},
		{
			name:    "invalid port skipped",
			text:    "Host example\n  HostName example.com\n  Port invalid\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example",
					HostName: "example.com",
					Port:     22,
				},
			},
		},
		{
			name:    "space or equals separator",
			text:    "Host example1\n  HostName=ex1.com\n\nHost example2\n  HostName ex2.com\n",
			baseDir: "/tmp",
			want: []Entry{
				{
					Alias:    "example1",
					HostName: "ex1.com",
					Port:     22,
				},
				{
					Alias:    "example2",
					HostName: "ex2.com",
					Port:     22,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.text, tt.baseDir, home)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Errorf("Parse() got %d entries, want %d", len(got), len(tt.want))
			}
			for i, entry := range got {
				if i >= len(tt.want) {
					break
				}
				if entry != tt.want[i] {
					t.Errorf("Parse() entry[%d]\ngot:  %+v\nwant: %+v", i, entry, tt.want[i])
				}
			}
		})
	}
}

func TestParseFile(t *testing.T) {
	t.Run("Include with real file", func(t *testing.T) {
		tmpDir := t.TempDir()
		home := tmpDir

		// Create main config file
		mainPath := filepath.Join(tmpDir, ".ssh", "config")
		os.MkdirAll(filepath.Dir(mainPath), 0755)

		included := filepath.Join(tmpDir, ".ssh", "config.d", "servers")
		os.MkdirAll(filepath.Dir(included), 0755)

		// Write included file
		includedContent := `Host server1
  HostName server1.example.com
  User ubuntu
`
		if err := os.WriteFile(included, []byte(includedContent), 0644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		// Write main config with Include
		mainContent := `Host local
  HostName localhost
  User testuser

Include ~/.ssh/config.d/servers
`
		if err := os.WriteFile(mainPath, []byte(mainContent), 0644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		// Parse should work and include entries from both files
		entries, err := parseWithDepth(mainContent, filepath.Dir(mainPath), home, 0)
		if err != nil {
			t.Fatalf("parseWithDepth() error = %v", err)
		}

		if len(entries) != 2 {
			t.Errorf("Expected 2 entries, got %d", len(entries))
		}

		expected := map[string]string{
			"local":   "localhost",
			"server1": "server1.example.com",
		}

		for _, entry := range entries {
			if expectedHost, ok := expected[entry.Alias]; ok {
				if entry.HostName != expectedHost {
					t.Errorf("Entry %s: got HostName=%s, want %s", entry.Alias, entry.HostName, expectedHost)
				}
			} else {
				t.Errorf("Unexpected entry: %s", entry.Alias)
			}
		}
	})

	t.Run("ParseFile with nonexistent file", func(t *testing.T) {
		_, err := ParseFile("/nonexistent/path/config")
		if err == nil {
			t.Error("ParseFile() expected error for nonexistent file")
		}
	})

	t.Run("ParseFile basic", func(t *testing.T) {
		tmpDir := t.TempDir()

		configPath := filepath.Join(tmpDir, "config")
		content := `Host example
  HostName example.com
  User testuser
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		entries, err := ParseFile(configPath)
		if err != nil {
			t.Fatalf("ParseFile() error = %v", err)
		}

		if len(entries) != 1 {
			t.Errorf("ParseFile() got %d entries, want 1", len(entries))
		}

		if entries[0].Alias != "example" {
			t.Errorf("ParseFile() got Alias=%s, want 'example'", entries[0].Alias)
		}
	})
}

func TestExpandHome(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		home     string
		expected string
	}{
		{
			name:     "tilde expansion",
			path:     "~/.ssh/id_rsa",
			home:     "/home/user",
			expected: "/home/user/.ssh/id_rsa",
		},
		{
			name:     "no tilde",
			path:     "/etc/ssh/config",
			home:     "/home/user",
			expected: "/etc/ssh/config",
		},
		{
			name:     "just tilde",
			path:     "~",
			home:     "/home/user",
			expected: "/home/user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandHome(tt.path, tt.home)
			if got != tt.expected {
				t.Errorf("expandHome() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestStripQuotes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "double quoted",
			input:    `"hello world"`,
			expected: "hello world",
		},
		{
			name:     "no quotes",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "single quote",
			input:    `"hello`,
			expected: `"hello`,
		},
		{
			name:     "with spaces",
			input:    `  "hello"  `,
			expected: "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripQuotes(tt.input)
			if got != tt.expected {
				t.Errorf("stripQuotes() = %q, want %q", got, tt.expected)
			}
		})
	}
}
