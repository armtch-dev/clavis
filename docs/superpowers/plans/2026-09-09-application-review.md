# Application Review Remediation Implementation Plan

> **For agentic workers:** Use subagent-driven-development to implement this plan task-by-task. Each phase needs implementation evidence and independent spec/code-quality review.

**Goal:** Implement all findings and additional recommendations in the application review in six verified phases.

**Architecture:** Preserve Go/Bubble Tea and existing file formats. Add small shared primitives only where required for recoverable disk operations and coordination; keep terminal rendering free of blocking work. Apply regression tests to real persistence, SSH, Git, and model transitions.

**Tech Stack:** Go 1.26.5+, Bubble Tea/Bubbles/Lip Gloss, age, x/crypto/ssh, OpenSSH and Git CLI; macOS and Linux.

**Spec:** `docs/APPLICATION_REVIEW.md` (user explicitly requested implementing everything).

## Global Constraints

- User steering: add regression tests only for high-priority correctness/data-loss risks. Do not add low/medium-priority regression coverage or repeat broad runs per edit. Record untested paths in `docs/VALIDATION_HANDOFF.md` for another agent, keep agent reports brief, and continue execution. This supersedes broader per-task test instructions below.
- No commits, pushes, live credential operations, or modifications to real user configuration.
- Preserve existing profiles/identities/scripts/vault formats or provide backwards-compatible recovery/migration.
- Never persist plaintext master keys; retain encrypted/staged validation on sync.
- Prefer standard library and existing dependencies; avoid framework replacement.
- Implementers must not spawn subagents. Controller assigns implementation and independent review.
- Work sequentially where files/interfaces overlap; use focused regression tests before changing nontrivial behavior.
- Model selection is not exposed by the task tool: use the available general agent for implementation/review with briefs sized to complexity.

## Task 1: Storage and vault recovery (high complexity)

**Files:** `internal/profile/{profile,identity}.go`, `internal/script/script.go`, `internal/vault/`, `internal/cli/cli.go`; small shared filesystem package if needed.

**Deliverables:** findings 1, 2, 8, 14; transaction primitive for task 4, directory-scoped coordination primitive for task 2 if practical.

- [ ] Reproduce restored-path overwrite for all stores with save/copy/load/save fixtures; assert destination path survives legacy JSON `Path`.
- [ ] Exclude runtime paths from JSON and validate loaded metadata/versions/references at appropriate boundaries.
- [ ] Implement recoverable multi-file changes using ciphertext-only staging/backups and startup recovery; reject unsafe paths/symlinks. Preserve old secrets on write failures or interrupted operations.
- [ ] Make CLI key rotation expose the new key successfully before retiring recoverable state. A crash must leave old-generation recovery possible; account for interrupted output and key acknowledgement. Do not save the master key in plaintext.
- [ ] Separate FIDO envelope maintenance from vault-encrypted local secrets. Rotation explicitly invalidates/re-enrolls stale FIDO wrapping while retaining the old enrollment on failed rotation.
- [ ] Doctor checks identity references and required secrets in addition to decrypting existing files.
- [ ] Run focused storage/vault/CLI tests, fault-injection recovery tests, and baseline affected-package tests; report new interfaces precisely.

## Task 2: Dependable and efficient sync (high complexity)

**Files:** `internal/gitsync/`, `internal/tui/{app,welcome,settings}.go`, main startup integration and storage coordination callers as needed.

**Consumes:** transaction/lock primitives and recovery semantics from task 1; preserve those contracts.

- [ ] Add local-bare-remote integration tests for two-machine sync, changed origin, pulled profile persistence, recipient changes, and concurrent requests.
- [ ] Reconcile origin with selected remote; bound Git operations with cancellation and avoid stranded rebase state.
- [ ] Replace per-file `cat-file` subprocesses with staged OID validation through one batch process. Preserve allowlist, symlink/mode, complete age header, and staged-object checks.
- [ ] Serialize sync and metadata/secret mutations across processes; coalesce overlapping UI sync requests. Later edits cannot silently race reload or disappear.
- [ ] Reload complete state after successful pull without unnecessarily locking an unchanged vault; recipient change requests unlock. Preserve selection and update probe targets. Keep local dirty state/last-success/failure details available for task 5.
- [ ] Add benchmark for staged guard at 10/100/1000 encrypted files and verify process count is constant.
- [ ] Run gitsync/TUI regression tests and race checks for coordination paths; report interfaces.

## Task 3: SSH, importer, and probe correctness (high complexity)

**Files:** `internal/sshx/`, `internal/sshconfig/`, `internal/probe/`, narrow integration at `internal/tui/app.go`/CLI import as required.

- [ ] Bound full SSH test lifecycle including session open/exec/output, and password/session handshake setup; cancel abandoned operations.
- [ ] Use full credentials consistently for interactive sessions, including stored protected-key passphrases and password fallback. Preserve ProxyJump behavior and host-key enforcement; never place secrets in argv.
- [ ] Ensure external-session signal watchers exit on normal cleanup and cleanup is idempotent/race-safe.
- [ ] Parse tabs and equals syntax without changing value case; preserve wildcard/default/include semantics and valid quoting. Prefer using installed OpenSSH resolution for trusted config over a growing incomplete parser where appropriate; no live host connections in tests.
- [ ] Share probes by address, bound active network probes, support cancellation on shutdown, and retain correct per-profile statuses/suspension behavior.
- [ ] Test with loopback SSH fixtures, temporary config files, concurrency/cleanup assertions, and affected-package race checks.

## Task 4: Safe TUI state and persistence (high complexity)

**Files:** `internal/tui/{app,wizard,list,identities,scripts,settings,welcome}.go`; shared mutation helper as needed.

**Consumes:** task 1 recoverable mutation/locking and task 2 synchronization/reload contracts.

- [ ] Persist profile/identity/import/delete operations coherently with vault changes; all errors retained and drafts preserved. In-memory rollback on failed persistence must match disk recovery.
- [ ] Preserve exact password/passphrase input; validate at field boundaries and keep errors after transitions.
- [ ] Distinguish wizard test generations/endpoint snapshots from saved-profile tests. Canceled/outdated drafts never change live trust state; cancel work on exit/back/delete.
- [ ] Preserve selected profile by ID over latency updates, category changes, saves, and sync; maintain stable action target.
- [ ] Implement explicit old/new full fingerprint review and deliberate re-trust after test mismatch; reject automatic key replacement.
- [ ] Add state-transition/persistence-failure regression tests, including first-run/unlock and interrupted pending connections; run TUI suite and race checks.

## Task 5: UI, accessibility, and rendering (medium/high complexity)

**Files:** `internal/tui/` views/widgets/theme integration, `internal/theme/`, regression/benchmark tests.

- [x] Fix 40-column panel widths, 80x24 help clipping, long filter/category inputs, large identity pickers, active-textarea resize, and Unicode cell-aware truncation. Use existing viewport/picker patterns.
- [x] Add detail toggle available below 130 columns with full target, identity, jump, auth readiness, fingerprint and copy actions. Prioritize hostname width before trends.
- [x] Complete light palette and selected-row contrast; essential text/hints target 4.5:1. Recompute derived TUI styles when the theme changes. Preserve NO_COLOR/ANSI behavior.
- [x] Add jump-to-field editing with discoverable keys, consistent save hints, Shift+Tab, and unsaved script draft preservation/recovery.
- [x] Add persistent expandable/copyable errors, actual destination/last-sync/dirty state, and probe last-check freshness, chart scale/min/avg/max explanation.
- [x] Move Keychain/capability checks out of View and blocking mutations out of Update; load/cache on settings entry and refresh after relevant commands.
- [x] Cache/reuse visible ordering/group aggregates on relevant changes; default sorting unaffected by probe status. Coalesce probe burst work without stale selection or hidden changes.
- [ ] Verify size matrix (40x8, 40x24, 80x24, 120x30, 160x40), Unicode/NO_COLOR, keyboard flows, and rendering benchmarks. Avoid tests that merely mirror colors or layout implementation.

Phase 5 implementation and scoped checks are complete. Remaining visual/performance
validation is deferred under Global Constraints to `docs/VALIDATION_HANDOFF.md`.

## Task 6: Integration, documentation, and final audit (high complexity)

**Files:** README, SECURITY, review resolution addendum, plan/progress, tests as findings require.

- [ ] Independent broad review of correctness/security/performance across phase boundaries; explicitly check every numbered review finding and every additional UX/scale recommendation.
- [ ] Fix important findings through a dedicated integration agent, then scoped re-review.
- [ ] Update keys, CLI, recovery/FIDO semantics, probe behavior, sync conflict recovery, and measured benchmark documentation; correct overclaims such as old keys being useless for historical Git ciphertext.
- [ ] Run `go test ./...`, `go vet ./...`, `go test -race ./...`, `bash -n install.sh`, `git diff --check`, and targeted post-change benchmarks. Verify Linux build compatibility using a temporary output path if feasible.
- [ ] Record delivered coverage, tests, benchmarks and remaining environment-dependent validation limits.

## Preflight interface review

| Tasks | Shared area | Coordination |
| --- | --- | --- |
| 1 / 2 / 4 | config-dir mutation and recovery | Phase 1 defines primitives; phases 2/4 integrate them sequentially. |
| 2 / 3 / 4 / 5 | TUI app and async messages | Sequential ownership; later tasks preserve earlier regression tests. |
| 3 / 4 | credentials, host-key observation, cancellation | SSH task reports full credential/session API and cancellation semantics. |
| 4 / 5 | wizard/list/details | Correctness state precedes keyboard/view changes. |
| all / 6 | docs and tests | Final review evaluates whole diff, not just the last phase. |

Every task has concrete behavior tests, defined scope, and verification. The review
report is the binding outcome specification; interfaces added by a phase are recorded
in its report before a dependent phase is dispatched.
