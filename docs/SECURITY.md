# Security Model

## Threat Model

Clavis protects against:

- **Vault at rest**: Vault credentials require the corresponding master key to decrypt. A stolen clone does not contain Clavis-managed local unlock caches; protection on a stolen machine also depends on any opted-in Keychain/FIDO copy and its gate.
- **Accidental sync exposure**: The sync guard restricts paths, file modes and encrypted-file headers in staged/fetched objects. It reduces accidental exposure; it cannot identify secrets pasted into allowlisted plaintext metadata or scripts, authenticate arbitrary header-bearing bytes, or sanitize historical commits.

Clavis does *not* protect against:

- **A compromised running machine**: While clavis is running and the vault is unlocked, any malware on your machine can read secrets from memory.
- **Malicious remote tampering**: Clavis uses trust-on-first-use (TOFU) host-key pinning to detect accidental key changes, but if an attacker controls your GitHub repository and changes `profiles.json` metadata before you sync, clavis has no way to detect it. Treat your git remote as trusted.

## Encryption

### Algorithm

Vault-owned secrets are encrypted with **age** (filippo.io/age) using X25519 recipients. The optional FIDO envelope uses age-scrypt wrapping instead:

- Encryption scheme: X25519 + ChaCha20-Poly1305 (AEAD)
- Key size: 256-bit
- Files are stored in age v1 binary format

### The Master Key

The **master key** is an X25519 identity (a 32-byte secret), displayed as `AGE-SECRET-KEY-1…` when clavis initializes. This key is:

- Generated once at first run
- Not written as a plaintext master-key file by clavis; opt-in Keychain and FIDO unlock do persist protected local copies (below)
- Your responsibility to store outside the machine

### Recipients

The **recipient** (public half of the master key) is stored in `vault.meta`. This allows you to:

- Add new secrets to the vault while it's locked (the recipient is public, so encryption works without the secret identity)
- Verify that you're using the correct vault
- Detect a wrong key during unlock by comparing the identity's derived recipient

### Canary Check

`Vault.Unlock` parses the identity and checks its derived recipient against the
loaded `vault.meta`; it does **not** decrypt the canary or every secret. Metadata
loading checks the canary's encoding/header. `VerifyAll` (used by doctor and
rekey preparation) decrypts the canary, requires the fixed plaintext
`clavis-canary-v1`, and verifies vault-owned ciphertext, including local secrets
such as the GitHub token. Individual secret reads authenticate their ciphertext.
A matching recipient alone is not proof of a complete, decryptable vault.

### Host-Key Pinning (TOFU)

After a successful saved-profile test/session/script contact, Clavis can persist
the server's SHA256 fingerprint and full public key together in `profiles.json`.
Wizard observations remain draft-only until the matching draft is saved. Failed,
canceled, superseded or retargeted operations cannot silently replace a live pin.
Future connections enforce the pin. If a mismatch is detected:

```
host-key mismatch: previously seen AAAA…, now BBBB…
refusing to connect
```

The old pin stays until explicit review: test (`t`, or wizard `r`), press `h`,
verify the full old/new fingerprints independently, then type `trust` and Enter.
Escape cancels. Saved-profile confirmation revalidates the endpoint, old pin and
metadata revision under the transaction lock; wizard approval must still be saved.
Retest authentication after re-trusting. TOFU does not authenticate first contact
against an independent authority, and trusted-remote metadata can change pins.

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
3. `PrepareRekey` verifies the old generation and prepares the new key/ciphertext in memory while retaining directory ownership; the live generation is unchanged
4. Clavis checks complete key-banner/prompt output and flushes supported writers. Store the new key externally, then type `saved` followed by Enter. EOF, failed output/flush or another response aborts preparation
5. Only acknowledged preparation is committed as one recoverable transaction. Keep both keys and the journals on any storage/commit error; an ambiguous I/O outcome is not proof that nothing changed
6. The next sync publishes the new `vault.meta` and ciphertext. A late status-output failure can occur after commit; the acknowledged new key is still the key to retain

Everyone syncing must receive the coherent new generation and use its new key.
Recipient changes lock the running model and prompt for that key; ordinary unlock
does not prove that every file belongs to the generation. Generation-divergence
checks refuse incompatible credential histories before rebase/push (below).

Successful rekey removes the active FIDO envelope and enrollment metadata in the
same transaction; rollback or explicit restoration restores the old pair. Unlock
with the new key and re-enroll. Keychain refresh occurs only when Keychain supplied
the rekey identity. Update environment/key files and other cached copies yourself.

**Rotation does not revoke historical ciphertext.** The old master key still
decrypts corresponding Git history and retained local before-images. The local
backup is not unlimited history; keep externally stored keys as appropriate.

### Recoverable persistence

`internal/fstxn` coordinates cooperating processes with an exclusive advisory
lock rooted at the config directory. Metadata and related credential changes
publish together; stores reject stale metadata/ciphertext baselines. Runtime
store paths come from the current directory, never a serialized legacy `Path`.

Before replacing live files, a durable journal records complete before/after
images: JSON metadata and age ciphertext, **no plaintext credential or master-key
images**. Metadata callers must keep free-text fields non-secret. Private scratch
files, file sync, atomic rename and parent-directory sync support recovery.
Unsafe paths, symlinks, case-alias collisions and malformed journals fail closed.

- `local/.clavis-transaction.json`: pending transaction. Fresh acquisition/startup
  durably establishes rollback and restores before-images before exposing stores.
- `local/.clavis-committed.json`: retained last committed transaction. Reads/loads
  keep it; the next validated nonempty transaction retires it before staging its
  own journal. Committed transactions are not automatically rolled back.
- `local/.clavis.lock`: persistent ownership inode; do not unlink it to bypass a
  busy owner. Scratch data uses `local/.clavis-write.tmp`.

TUI storage failures retain drafts and block mutations/sync. Ctrl+R obtains a
fresh owner, recovers pending writes and reloads; review then retry explicitly.
Changed edit baselines require reopening; destructive confirmations are renewed.
If recovery fails, preserve the journals and correct the filesystem problem.

Explicit committed-backup restoration is the internal `Lock.RestoreLast()` API:
hold the matching lock, restore before-images as a new transaction, then reload
all stores/vault state. Restoring a rekey requires the old key. There is no
restore-last CLI command; Ctrl+R is pending recovery, not this operation. Preserve
a directory copy before further mutation when assisted restoration is needed.
Repeated I/O failures can leave an uncertain commit outcome. Keep both keys,
reacquire/recover and inspect the recipient rather than guessing success.

The journal stores whole changed images in memory/on disk. Advisory ownership
does not constrain manual Git/filesystem writers. Synthetic fault/process-death
coverage is not physical power-loss or damaged-media validation.

## Hardware-Gated Local Unlock

The master key is the only thing that decrypts the vault, on any machine.
Hardware unlock never replaces it — it gates local copies of it:

- **macOS Keychain (Touch ID)**: opting in to the keychain cache stores the
  key in the login keychain; every read is gated by a device-owner
  authentication prompt (Touch ID, Apple Watch, or account password). This is
  a UI-level gate, not a cryptographic binding — the item still lives in the
  login keychain. In a session with no auth UI (SSH), the gate fails closed
  and clavis falls back to the interactive key prompt.
- **FIDO2 security key (YubiKey etc., macOS and Linux)**: enrolling in
  settings creates a credential with the hmac-secret extension and stores the
  master key in `local/master-key.fido2.age`, encrypted to a secret that only
  an assertion against that physical key (with touch) can re-derive. The
  metadata in `local/fido2.json` (credential ID, salt) is non-secret. Both
  files live in `local/`, which never syncs. Requires the `fido2-tools`
  CLI (`brew install libfido2` / `apt install fido2-tools`).

Settings treats these as alternatives: enabling one replaces the other active
mechanism. Zero active copies is valid, partial replacement errors are reported,
and retained recovery images may still contain a prior encrypted FIDO envelope.
This is not a guarantee of exactly one physical copy on storage.

Losing the enrolled hardware does not lose vault access if you retained the
matching master key; re-enrolling mints a fresh wrapped copy.

FIDO wrapping is an age-scrypt envelope, not vault-owned X25519 ciphertext.
Doctor checks the enrollment pair's safe paths, metadata shape and envelope
header separately; it cannot authenticate that envelope without the physical
ceremony. Enrollment rechecks the current recipient before atomic publication;
unlock rechecks the pair and recipient after the ceremony. Hardware operations
and capability discovery run asynchronously with cancellation/deadlines.

## The Sync Guard

### Allowlist

Clavis-managed sync validates the staged index, the fetched tree before checkout,
and the resulting index after rebase:

1. Root allowlist: `profiles.json`, `identities.json`, `scripts.json`, `config.json`,
   `vault.meta`, `.gitignore`, `README.md`; secrets must be safe single-level
   `vault/*.age` paths
2. Regular Git modes only; reject symlinks, gitlinks, unmerged stages, unsafe paths
   and case-alias collisions
3. Read encrypted blobs by **indexed/tree object ID**, not worktree content, with
   `cat-file --batch`; check object type/size/framing and the complete
   `age-encryption.org/v1\n` header. Staged enumeration plus batch reading takes
   two Git processes, independent of secret count

If a file fails the check, the push is rejected:

```
sync guard: vault/foo.password is not an age file; refusing to push
```

These are format/path checks, not cryptographic verification or content scanning.
Allowlisted metadata/scripts/README remain plaintext. A compromised process can
bypass Clavis or place secrets in allowed fields; the remote remains trusted.

### .gitignore Defense

The repository's `.gitignore` blocks:

- `local/` — Machine-local secrets (GitHub token)
- Plaintext key patterns (`*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.identity`)
- Temporary files (`*.tmp`, `.tmp-*`)

Ignore rules are defense in depth: manual force-add and already-tracked files can
bypass them. Clavis's object allowlist is the enforcement boundary for its sync.

### Ownership, conflicts and key generations

One directory owner spans sync/restore Git mutation and coherent reload of config,
profiles, identities, scripts and vault metadata. TUI requests are single-flight
with one coalesced pending follow-up. Normal action keys pause during sync;
unchanged-recipient reload retains unlock, changed-recipient reload prompts anew.
The configured remote reconciles `origin`, removes obsolete pushurl overrides,
and status exposes Git's resolved push destination, including rewrites.

Git commands have 60-second deadlines; TUI sync/restore has a three-minute budget.
Cancellation terminates command groups/helpers. Conflicts/cancellation attempt a
separate bounded ten-second rebase abort, preserving local commits. Unfinished
Git operations are refused. If abort fails, preserve the directory and follow
the full error's recovery instructions before retrying.

When recipients differ and both histories changed credentials relative to their
common base, sync/pull refuses before rebase/push (`ErrGenerationDivergence`).
Uncommitted credential changes also block generation-crossing pull. A normal
guarded local commit may already exist. One-sided rotation or safe metadata-only
divergence can proceed. Keep both keys and directory copies, migrate conflicting
credentials deliberately into a chosen generation, then retry; there is no
automatic two-key migration or semantic JSON merge resolver. Avoid destructive
reset/force-push as a shortcut. Remote rotation can also require local token
re-entry and FIDO re-enrollment on other machines.

### Token Handling

Your GitHub personal access token is never written to `.git/config` or passed on the command line. Instead:

1. It's stored machine-locally as vault-encrypted `local/github-token.age`
2. During sync, clavis sets the `CLAVIS_GIT_TOKEN` environment variable
3. Git reads it via an inline credential helper: `!f() { echo "username=x-access-token"; echo "password=${CLAVIS_GIT_TOKEN}"; }; f`
4. The helper sends the token over Git's credential protocol; it is not placed in command arguments or ordinary status output

Git receives the token only for fetch/pull/push. Inherited `CLAVIS_*`/`GIT_*`
overrides are filtered; the master-key environment is not passed to Git/helpers.
Git error text is token-scrubbed. Environment/protocol access on a compromised
machine remains outside the threat model; this is not secret isolation from
privileged process inspection.

## Host-Key Pinning Coverage

The SHA256 fingerprint pinned at first successful contact is enforced on
every code path clavis controls:

- **Direct tests, sessions and scripts** (in-process SSH): a mismatch
  aborts with a loud "HOST KEY CHANGED" error.
- **ProxyJump key sessions** (external `ssh`): once a profile is pinned, clavis
  writes the full pinned public key to a private temp `known_hosts` file and
  invokes `ssh -o UserKnownHostsFile=<tmp> -o StrictHostKeyChecking=yes`, so
  the target session is locked to the same key. Unpinned targets use `accept-new`
  into that private file; successful completion returns the observed key before
  cleanup. Alternative host-key sources, trust exceptions and multiplexing are
  disabled for the pinned target. The jump uses trusted native OpenSSH settings.

A full-key-only pin supplies its fingerprint on all controlled authentication
paths; malformed/inconsistent pairs are refused. The context-aware external route
requires a full key for a pinned target and refuses fingerprint-only legacy pins
rather than weakening checking. Tests still dial jump targets directly; scripts
and password-only jump sessions remain unsupported. A stored target key can use
its passphrase and optional password fallback through the one-use FIFO askpass
route described in the [README](../README.md#ssh-authentication-and-import).

## Known Limitations

- **External-session plaintext key handoff**: OpenSSH receives an unlocked key
  in a private 0700 directory/0600 file. Normal completion and context/signal
  cancellation perform idempotent best-effort overwrite/unlink. This is not secure
  erasure on copy-on-write storage; SIGKILL/power loss can leave the file behind.
- **A compromised, unlocked machine**: while the vault is unlocked, secrets
  pass through process memory; Go's garbage collector may copy buffers before
  clavis zeroes them. This is inherent to the platform.
- **Metadata and scripts are plaintext**: notes, names, hosts, usernames, tags,
  identity metadata, preferences and script bodies are not encrypted. Do not put
  credentials in them. Clipboard copies and session-only editor drafts also
  remain within the local-machine trust boundary; drafts do not survive restart.
- **ProxyJump connection tests** dial the target directly; the jump hop is
  applied only to real sessions.
- **Readiness versus reachability**: shared TCP probes (at most 16 active
  exchanges, failure backoff up to five minutes) are not authenticated health
  checks. Jump targets are unprobed. Doctor reports missing required credentials
  and identity references but does not prove SSH login or passphrase sufficiency.
- **Setup versus runtime**: SSH network setup/tests are bounded and cancellable;
  local crypto parsing is synchronous, and interactive/script runtime is not
  limited by the setup deadline. Arbitrary blocking output writers cannot be
  interrupted by socket cancellation.

See [remediation coverage](REMEDIATION_SUMMARY.md) and the
[validation handoff](VALIDATION_HANDOFF.md) for historical evidence, untested
hardware/platform paths and consciously deferred visual/performance checks.

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
