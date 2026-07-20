# Security Model

## Threat Model

Clavis protects against:

- **Vault at rest**: If your laptop or a git clone is stolen, the vault remains encrypted and the thief cannot decrypt passwords or keys without the master key.
- **Plaintext in git**: The sync guard prevents plaintext credentials from accidentally leaking into your git repository.

Clavis does *not* protect against:

- **A compromised running machine**: While clavis is running and the vault is unlocked, any malware on your machine can read secrets from memory.
- **Malicious remote tampering**: Clavis uses trust-on-first-use (TOFU) host-key pinning to detect accidental key changes, but if an attacker controls your GitHub repository and changes `profiles.json` metadata before you sync, clavis has no way to detect it. Treat your git remote as trusted.

## Encryption

### Algorithm

All secrets are encrypted with **age** (filippo.io/age), a modern X25519-based encryption library:

- Encryption scheme: X25519 + ChaCha20-Poly1305 (AEAD)
- Key size: 256-bit
- Files are stored in age v1 binary format

### The Master Key

The **master key** is an X25519 identity (a 32-byte secret), displayed as `AGE-SECRET-KEY-1…` when clavis initializes. This key is:

- Generated once at first run
- Never written to disk by clavis
- Your responsibility to store outside the machine

### Recipients

The **recipient** (public half of the master key) is stored in `vault.meta`. This allows you to:

- Add new secrets to the vault while it's locked (the recipient is public, so encryption works without the secret identity)
- Verify that you're using the correct vault
- Detect a wrong key during unlock (see Canary check below)

### Canary Check

When you unlock the vault, clavis verifies the master key by decrypting an encrypted test value (the canary, the fixed plaintext "clavis-canary-v1"). If decryption fails or produces the wrong plaintext, the unlock fails with "this key does not match the vault (recipient mismatch)". This prevents silent decryption of secrets with the wrong key.

### Host-Key Pinning (TOFU)

When you test a connection or connect to a host, clavis records the SSH server's public key fingerprint in `profiles.json` (SHA256 format). On future connections, it refuses to connect if the fingerprint changes, preventing man-in-the-middle attacks on that specific host. If a mismatch is detected:

```
host-key mismatch: previously seen AAAA…, now BBBB…
refusing to connect
```

The old fingerprint stays in the profile until you manually re-trust the host by editing the profile and running another test.

## Key Loss and Rotation

### `clavis vault reset`

If you lose the master key:

1. Run `clavis vault reset`
2. Confirm deletion (this wipes all encrypted credentials)
3. Clavis generates a new master key
4. Your profile metadata (`profiles.json`) remains; re-enter credentials via the wizard

You keep all your hosts, but you must re-add passwords and keys.

### `clavis vault rekey`

To rotate the master key (generate a new one and re-encrypt all secrets):

1. Run `clavis vault rekey`
2. You will be prompted to unlock the vault with the old key
3. Clavis generates a new master key, displays it once, and re-encrypts everything
4. The next sync pushes the new `vault.meta` and re-encrypted vault files

Everyone syncing from that repository must receive the updated `vault.meta` and re-encrypted files before they can unlock. Out-of-sync vaults are detected at unlock time (canary check).

## The Sync Guard

### Allowlist

Before every git push, clavis verifies that:

1. Only whitelisted files are staged (e.g., `profiles.json`, `config.json`, `vault.meta`, `vault/*.age`)
2. Every file in `vault/` starts with the age magic header (`age-encryption.org/v1`)

If a file fails the check, the push is rejected:

```
sync guard: vault/foo.password is not an age file; refusing to push
```

This prevents a compromised script or misconfiguration from leaking plaintext.

### .gitignore Defense

The repository's `.gitignore` blocks:

- `local/` — Machine-local secrets (GitHub token)
- Plaintext key patterns (`*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.identity`)
- Temporary files (`*.tmp`, `.tmp-*`)

Even if the guard is bypassed, git's index won't stage these files.

### Token Handling

Your GitHub personal access token is never written to `.git/config` or passed on the command line. Instead:

1. It's stored locally (machine-only, encrypted in the vault, in `local/github-token`)
2. During sync, clavis sets the `CLAVIS_GIT_TOKEN` environment variable
3. Git reads it via an inline credential helper: `!f() { echo "username=x-access-token"; echo "password=${CLAVIS_GIT_TOKEN}"; }; f`
4. The token appears in the git credential helper's context only, never in argv or stdout

If someone runs `ps aux` or examines `.git/config`, the token is not visible.

## Host-Key Pinning Coverage

The SHA256 fingerprint pinned at first successful contact is enforced on
every code path clavis controls:

- **Connection tests and password sessions** (in-process SSH): a mismatch
  aborts with a loud "HOST KEY CHANGED" error.
- **Key-auth sessions** (external `ssh`): once a profile is pinned, clavis
  writes the full pinned public key to a private temp `known_hosts` file and
  invokes `ssh -o UserKnownHostsFile=<tmp> -o StrictHostKeyChecking=yes`, so
  the session is locked to the same key. Profiles that have never been pinned
  (no successful test yet) fall back to OpenSSH's own known_hosts prompting
  until the first successful test pins them.

## Known Limitations

- **SIGKILL during a key-auth session**: the decrypted key tempfile is
  shredded when the session ends and on SIGINT/SIGTERM/SIGHUP, but `kill -9`
  cannot be caught; the 0600 tempfile then persists until the OS clears the
  temp dir.
- **A compromised, unlocked machine**: while the vault is unlocked, secrets
  pass through process memory; Go's garbage collector may copy buffers before
  clavis zeroes them. This is inherent to the platform.
- **profiles.json is metadata, not secrets** — but its free-text `notes`
  field syncs in plaintext. Don't put credentials in notes.
- **ProxyJump connection tests** dial the target directly; the jump hop is
  applied only to real sessions.

## Reporting Security Issues

If you find a vulnerability or security concern:

1. Open a private GitHub security advisory: https://github.com/armtch-dev/clavis/security/advisories
2. Or email the maintainer directly (preferred for sensitive issues)
3. Do not open a public GitHub issue for unreported vulnerabilities

Include:

- A description of the issue
- Steps to reproduce (if applicable)
- Potential impact
- Suggested fix (if you have one)
