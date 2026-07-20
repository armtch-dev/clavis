# clavis — build plan

Terminal SSH connection manager (sshs-style) with an encrypted credential vault,
live reachability probes, and encrypted git sync. Night Owl palette shared with
scriptorium.

## Stack
- Go + Bubble Tea / Lip Gloss / Bubbles
- Encryption: age (filippo.io/age) — X25519 identity is the master key, generated
  at first run, stored by the user OUTSIDE this machine/repo. Recipient (public
  key) lives in `vault.meta`, so encrypting new secrets never needs the key;
  decrypting (connect/test) does.
- SSH: golang.org/x/crypto/ssh for tests + password sessions; exec system `ssh`
  for key-auth sessions.
- Sync: git CLI (token via GIT_ASKPASS, never in .git/config) + GitHub REST for
  private-repo bootstrap.

## Data layout (~/.config/clavis — this dir IS the sync repo)
- `profiles.json` — non-secret metadata (host, user, port, auth flags, tags,
  proxy_jump, pinned host-key fingerprint)
- `config.json` — sync settings, UI prefs
- `vault.meta` — vault version + age recipient + encrypted canary
- `vault/<id>.<kind>.age` — encrypted secrets (password, key, key passphrase)
- `local/` — GITIGNORED machine-local secrets (GitHub PAT), still age-encrypted
- `.gitignore` — blocks `local/` and any plaintext key patterns

## Security invariants (review against these every phase)
1. The age identity never touches the config dir, the repo, or any log.
2. Every file in `vault/` starts with the age header; pre-push guard verifies an
   allowlist and refuses to push anything else.
3. Secret plaintext lives only in memory or a 0600 tempfile that is removed
   (best-effort overwritten) when the SSH session ends.
4. Lost identity ⇒ `clavis vault reset` (wipe vault, keep profiles, re-enter
   credentials). Rotation ⇒ `clavis vault rekey`.
5. PAT is per-machine (`local/`), never synced.

## Phases
- [x] 0. Scaffold: module, theme port, PLAN, .gitignore
- [x] 1. vault package + tests (adversarial review before moving on)
- [x] 2. profile store + validation + tests
- [x] 3. sshx: typed connection test, TOFU host-key pinning, session launch
- [x] 4. probe monitor: 10s jittered TCP probes, latency history (Sonnet agent)
- [x] 5. gitsync: bootstrap w/ confirmation, plaintext guard — integration-
       tested against a local bare remote (guard blocks plaintext; local/ and
       token never pushed)
- [x] 6. TUI: list w/ live status, step wizard w/ auto-test, settings, unlock,
       help overlay, --dump-frame debug flag
- [x] 7. CLI: doctor, vault rekey/reset, import from ~/.ssh/config
       (Sonnet agent; ssh_config parser by Haiku agent)
- [ ] 8. Docs (README, SECURITY.md), Opus security-review fixes, release
       tooling (goreleaser, install.sh)

## Suggestions folded in
ProxyJump field · host-key pinning w/ loud mismatch warning · TCP probes instead
of ICMP (no root needed) · `doctor` · ssh_config import · per-machine PAT ·
age over hand-rolled AES-GCM.
