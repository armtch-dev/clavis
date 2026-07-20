# clavis

An SSH connection manager with an encrypted credential vault, live reachability probes, and guarded encrypted git sync.

Clavis walks you through a step-by-step profile wizard to record SSH hosts. It keeps all passwords and private keys in an age-encrypted vault locked by a master key you generate once and store offline. When you add a profile, it immediately tests the connection so you know it works. Clavis watches your hosts with live TCP reachability probes every 10 seconds—status dots show latency at a glance, colored green for <50ms, yellow for <200ms, red for slower, or a hollow circle if the host is down. Sync to a private GitHub repository is encrypted and guarded: a plaintext secret will never accidentally leak into git. The UI uses the Night Owl palette, the same dark theme as scriptorium, and you can import your existing ~/.ssh/config in one keystroke.

## Install

macOS and Linux (needs git, Go 1.26+, and the OpenSSH client). One line:

```bash
curl -fsSL https://raw.githubusercontent.com/armtch-dev/clavis/main/install.sh | bash
```

Installs to `/usr/local/bin` if writable, otherwise `~/.local/bin`. From a
checkout, `./install.sh` does the same. Or manually:

```bash
go build -o clavis . && mv clavis ~/bin  # or wherever is in your PATH
```

No pre-built releases yet; everything builds from source. The macOS Keychain
unlock source is Mac-only; on Linux use `CLAVIS_KEY_FILE` or the prompt.

## First Run

Just launch it:

```
clavis
```

On first launch the vault is created automatically and your master key is shown once—it looks like `AGE-SECRET-KEY-1…`. Write it down and store it somewhere outside this machine (a password manager, an encrypted note, a piece of paper in a safe). Clavis will never write the master key to disk.

On subsequent runs, clavis prompts you to unlock the vault. It tries three non-interactive sources first:

1. `CLAVIS_KEY` environment variable (for scripts and CI)
2. `CLAVIS_KEY_FILE` environment variable (path to a file holding the master key)
3. macOS Keychain (opt-in via settings; weakens the "offline key" guarantee)

If none of those work, you'll see an interactive prompt.

To cache the key in your login keychain (macOS only), press `k` on the first-run key screen, or unlock the vault once and toggle it in settings (`g`, then `k`). This trades security for convenience; you decide.

## Usage

### The TUI

The main interface is a list of SSH profiles. Keybindings:

| Key | Action |
| --- | --- |
| `enter` | Connect to the selected host |
| `a` | Add a profile (step-by-step wizard) |
| `e` | Edit the selected profile |
| `d` | Delete the selected profile and its vault secrets |
| `t` | Test the connection (dial → handshake → auth → exec) |
| `s` | Sync now (guarded, encrypted git push) |
| `g` | Settings: GitHub token, repo, autosync, keychain |
| `i` | Import hosts from ~/.ssh/config |
| `/` | Filter profiles (case-insensitive substring search) |
| `j/k` or `↑/↓` | Move cursor up/down |
| `?` | Show help overlay |
| `q` or `ctrl+c` | Quit |

### CLI Subcommands

```bash
clavis doctor              # Health check: key, vault, git, ssh
clavis import [path]       # Import hosts from ssh_config (default ~/.ssh/config)
clavis vault rekey         # Rotate the master key (re-encrypts everything)
clavis vault reset         # Wipe all credentials, mint a new key (use if key is lost)
clavis version             # Show version
clavis --dump-frame        # Debug flag: render a single frame and exit
```

## Sync Setup

Press `g` from the main list to enter settings.

1. **Add a GitHub token**: Generate a personal access token with `repo` scope at https://github.com/settings/tokens. Paste it when prompted. This token is stored locally (machine-only, never synced).

2. **Create or link a repository**: Clavis confirms before creating a private repository on your GitHub account. You can also point to an existing private repo.

3. **Enable autosync** (optional): Syncs to git after every change. Manual sync is always available via `s`.

What gets synced: `profiles.json` (host metadata), `config.json` (preferences), `vault.meta` (vault version + recipient), and encrypted vault secrets (`vault/*.age`).

What never syncs: your master key (never stored by clavis), the GitHub token (stored locally), and anything in `local/`.

## Data Layout

Clavis stores everything in `~/.config/clavis`:

```
~/.config/clavis/
├── profiles.json           # Non-secret metadata (host, user, port, auth flags, tags)
├── config.json             # Sync settings, UI preferences
├── vault.meta              # Vault version, age recipient, encrypted canary
├── .gitignore              # Blocks local/ and plaintext key patterns
├── vault/
│   ├── <id>.pass.age       # Encrypted SSH passwords
│   ├── <id>.sshkey.age     # Encrypted SSH private keys
│   └── <id>.passphrase.age # Encrypted key passphrases
└── local/
    └── github-token.age    # Machine-local GitHub PAT (encrypted, gitignored)
```

The `vault/` directory is synced to git (encrypted). The `local/` directory is not.

## Status Indicators

On the profile list, each row shows:

- **Dot**: Connectivity status
  - `●` green: latency <50ms
  - `●` yellow: latency <200ms
  - `●` red: latency ≥200ms
  - `○` red: host is down (TCP connection refused or timeout)
- **Latency**: The most recent round-trip time to the SSH port, or "down"
- **Sparkline**: A mini chart of the last 12 probe results; failures show as `×`

Probes run every 10 seconds to the SSH port (a TCP dial, not ICMP ping) so they work on any network and require no root.

## Environment Variables

- `CLAVIS_KEY` — The master key identity string (AGE-SECRET-KEY-1…)
- `CLAVIS_KEY_FILE` — Path to a file containing the master key (one key per line, comments starting with #)
- `CLAVIS_CONFIG_DIR` — Override the config directory (default `~/.config/clavis`)
