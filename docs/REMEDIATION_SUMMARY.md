# Application review remediation

Status: Phases 1–6 implemented and final integrated checks passed, 2026-09-10. The original
[application review](APPLICATION_REVIEW.md), including its reproductions,
measurements and historical line references, is preserved as historical evidence.
This addendum records implementation coverage and verification, not an exhaustive
audit. [Validation handoff](VALIDATION_HANDOFF.md) separates passing checks,
untested implemented paths and unsupported behavior.

Final independent high-risk review approved after correcting the shared retained-script
target guard. Final `go test -race ./... -count=1`, `go vet ./...`,
`bash -n install.sh`, `git diff --check`, and Linux/amd64 cross-build all passed.
The race-enabled run executes the complete retained test suite; a duplicate non-race
run and new lower-priority regressions were omitted per the user's test-budget direction.

## Numbered coverage matrix

All rows below have implementation in the current checkout. Paths are relative
to the repository; braces abbreviate multiple files. “Implemented” does not mean
every UI/device/platform path has been exercised after Phase 5.

| # | Review finding | Implemented files and behavior |
| ---: | --- | --- |
| 1 | Relocated store paths | `internal/profile/{profile,identity}.go`, `internal/script/script.go`: runtime paths excluded from JSON; current-root loading ignores legacy `Path`, validates versions/records and rejects unsafe/colliding IDs. |
| 2 | Rekey data loss | `internal/fstxn/transaction.go`, `internal/vault/{vault,rotation}.go`, `internal/cli/cli.go`, `main.go`: durable ciphertext/metadata before/after journal; recover before loading; prepare, deliver/flush key, require `saved`, then commit; retained last backup and explicit `RestoreLast` API. |
| 3 | Stale application after sync | `internal/tui/coordination.go`, `internal/tui/welcome.go`, `internal/fstxn/revision.go`: coherent all-store reload; preserve ID selection/drafts; reuse identity only for unchanged recipient, prompt on rotation; reject stale metadata/credential edits. |
| 4 | Overlapping sync | `internal/gitsync/gitsync.go`, `internal/tui/{coordination,mutation}.go`: one directory owner through Git/reload; single-flight/coalesced UI requests; cooperative config/FIDO/import writers and mutation/recovery barriers. |
| 5 | Failed credentials reported saved | `internal/tui/{mutation,wizard,list,identities,scripts,settings,welcome}.go`: detached metadata plus credential Changes in one Apply, checked errors, fresh publication only after success; retain input and explicit recovery/retry. |
| 6 | Canceled tests change live trust | `internal/tui/{network,app,coordination,wizard,trust}.go`: originating job/wizard and endpoint/auth/pin checks; cancel obsolete work; draft-only observations until matching save; failed sessions do not pin. |
| 7 | Latency sorting redirects selection | `internal/tui/{list,app,coordination}.go`: selected profile ID drives actions across sorting/filter/category/reload; stable destructive targets; safe fallback after removal. |
| 8 | FIDO maintenance/rotation | `internal/vault/{vault,rotation}.go`, `internal/fido2/fido2.go`, `internal/cli/cli.go`: distinguish scrypt hardware envelope; atomic enrollment/removal with recipient recheck; rotation invalidates active enrollment, rollback restores pair; doctor checks structure separately. |
| 9 | Wrong sync destination | `internal/gitsync/gitsync.go`, `internal/tui/{coordination,settings,presentation}.go`: reconcile origin/remove stale pushurl, resolve actual push URL including rewrites, display configured/attempted destination and session status. |
| 10 | Secret whitespace trimmed | `internal/tui/wizard.go`: exact password/passphrase bytes, empty-edit keep semantics, explicit stored-key choice, protected-key validation and obsolete-passphrase deletion in the save transaction. |
| 11 | SSH import semantics | `internal/sshconfig/sshconfig.go`, `internal/cli/cli.go`, `internal/tui/list.go`: case-preserved values, case-sensitive Host patterns, first-value/default/include/quote/equals semantics; explicit unsupported forms; one atomic import publication. |
| 12 | SSH timeout coverage | `internal/sshx/{sshx,session,script}.go`, `internal/tui/network.go`: one test budget through auth/channel/exec/output, capped test output and bounded banner; cancellable transport/setup; runtime deadline clears only after setup acknowledgement. |
| 13 | Stored auth ignored in sessions | `internal/sshx/{sshx,session,askpass}.go`: shared direct credentials/passphrase/password fallback; native key-based ProxyJump with target fallback via guarded one-use FIFO; preserve jump provider/policy separately. |
| 14 | Doctor misses required secrets | `internal/cli/cli.go`, `internal/vault/vault.go`: missing profile/identity credentials and references diagnosed under one owner; canary/vault-owned ciphertext verification; FIDO structural diagnostics without claiming hardware authentication. |
| 15 | Disappearing validation errors | `internal/tui/{wizard,scripts,settings,app,presentation}.go`: field/editor errors retained across failure transitions; persistent last error; Ctrl+E full details/copy/dismiss; explicit save-recovery feedback. |
| 16 | Compact layouts hide controls | `internal/tui/{presentation,list,wizard,identities,scripts,settings,welcome,trust}.go`: cell-budgeted/paged panels, scrollable help/review, bounded identity selection, input tails and active textarea resize. Full size/Unicode matrix remains untested. |
| 17 | Light-theme contrast | `internal/theme/nightowl.go`, TUI views: rebase semantic/derived colors against canvas/selection toward 4.5:1; retain ANSI/colorless paths. Real-terminal contrast/screenshot audit remains unperformed. |
| 18 | Per-secret Git process overhead | `internal/gitsync/gitsync.go`: enumerate staged entries once, stream indexed OIDs through one framed batch reader; preserve mode/path/age-header validation and check fetched trees. Two-process staged-guard evidence below. |
| 19 | External-session watcher leak | `internal/sshx/session.go`, `internal/tui/app.go`: remove per-session signal watchers, application-owned cancellation, idempotent cleanup, join direct-session input/resize workers. |
| 20 | Settings render I/O | `internal/tui/{local_state,settings,welcome,coordination}.go`, `internal/vault/unlock.go`, `internal/fido2/fido2.go`: command-loaded capability/credential snapshots, entry/explicit/publication refresh, async hardware/Keychain/clipboard work with context bounds. |
| 21 | Repeated list sorting/copying | `internal/tui/{list,app}.go`: cache visible ordering/entries/group totals; invalidate on relevant changes; default probe updates avoid sorting; 16ms event batches reconcile overflow snapshots. Post-change render/allocation benchmarks deferred. |

## Additional UX and scale recommendations

| Recommendation | Delivered coverage / boundary |
| --- | --- |
| Explicit re-trust | `internal/tui/trust.go`: full old/new fingerprints, literal `trust` confirmation, stale endpoint/pin refusal, draft-only wizard approval until save; `t`/`r` then `h`. |
| Details below 130 columns and copy | `internal/tui/{presentation,app,list}.go`: `v` overlay, full target/identity/jump/fingerprint, `c` target and `f` fingerprint copy, paging/Escape. |
| Hostname before trends | `internal/tui/list.go`: target width prioritized; compact layouts reduce trend columns. Real-terminal visual assessment deferred. |
| Reachable versus auth-ready | `internal/tui/{local_state,presentation,list,detail}.go`: cached credential readiness and endpoint-scoped auth result; textual `via jump`, distinct from TCP status. |
| Jump-to-field | `internal/tui/wizard.go`: editing Ctrl+F selector, navigation/Enter jump; Ctrl+S commits current field and attempts save; Tab/Shift+Tab traversal, with key-paste Tab reserved for its textarea. |
| Script consistency/recovery | `internal/tui/scripts.go`: Ctrl+S/legacy Ctrl+D save, reverse traversal, one session-only draft; list `D` resume/`X` discard, Ctrl+N new-copy recovery, Ctrl+R unsaved run with original-target validation. No crash-persistent drafts. |
| Error and sync recovery details | `internal/tui/{app,presentation,mutation,settings}.go`: Ctrl+E copyable error; barrier Ctrl+R recover/reload before explicit retry; settings `v` destination/last-success/pending/dirty. Local save success does not imply remote sync success. |
| Freshness and chart interpretation | `internal/tui/{presentation,detail}.go`: check age, min/avg/max and numeric chart scale; columns are samples, not equal time; failures excluded from latency aggregate and back off up to five minutes. |
| Shared bounded probes/cancellation | `internal/probe/probe.go`, `internal/tui/{app,network}.go`: one worker per distinct direct address, at most 16 active dial/banner exchanges, per-profile history/generation, shared suspension owners, cancellable Stop and stale-message refusal. Large-fleet production load testing deferred. |

## Existing benchmark evidence (no Phase 6 measurement)

Phase 2's retained `BenchmarkGuardStaged`, Apple M5 Pro / darwin-arm64 /
Go 1.27.1, five timed iterations per size:

| Encrypted files | Guard time/op | Git processes/op |
| ---: | ---: | ---: |
| 10 | 49.63 ms | 2 |
| 100 | 61.92 ms | 2 |
| 1,000 | 198.24 ms | 2 |

The original review measured **22.23 seconds at 1,000 files** with per-file
processes. Absolute timing comparisons are illustrative: the later fixture
reuses genuine age ciphertext of 136 KiB synthetic binary input under distinct
filenames (repeated OIDs), excludes setup/encryption/staging/cleanup, and includes
index enumeration, process starts, framed body draining and process-counter
overhead. The baseline used different fixture/iteration sizes. The constant
process count is directly asserted; these are guard-only measurements, not full
sync/network throughput. Later generation checks were not rebenchmarked.

## Operational boundaries

- [README](../README.md) documents current keys, recovery, supported SSH/import
  routes and shared probe behavior. [Security](SECURITY.md) documents ciphertext-
  only secret staging, retained backup lifetime, acknowledged rekey, FIDO
  re-enrollment, old-key access to Git history, and the trusted-remote model.
- Mixed-generation credential divergence is intentionally refused; automatic
  two-key migration and semantic JSON conflict resolution are not implemented.
  `RestoreLast` is an internal API, not a CLI/TUI committed-backup restore action.
- Password-only ProxyJump, jump scripts and jump-aware in-process tests are not
  implemented. Supported key-based jump fallback and import subsets are documented
  explicitly; omitted OpenSSH features are not described as merely untested.
- Short local CRUD/recovery and crypto parsing remain synchronous. Capability/
  hardware/network work is asynchronous; a hard UI latency bound is not claimed.
- Phase 6 completed documentation, final high-risk review, the retained-script
  target fix, and integrated verification. Physical hardware/terminal/Linux runtime
  and lower-priority UI performance validation remain assigned in the handoff.
