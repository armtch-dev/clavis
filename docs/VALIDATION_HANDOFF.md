# Validation handoff

The user requested limiting new regression tests to high-priority correctness/data-loss risks and handing other validation to a subsequent agent. Implementation coverage is in [REMEDIATION_SUMMARY.md](REMEDIATION_SUMMARY.md); the original [application review](APPLICATION_REVIEW.md) remains historical evidence.

## Final verification — completed

On the final implementation (after the retained script-picker target fix), the
controller ran this sequence successfully:

```sh
go test -race ./... -count=1
go vet ./...
bash -n install.sh
git diff --check
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /var/folders/_w/ngpq09gn4j11hks8kynh6wt40000gq/T/opencode/clavis-final-linux .
```

All package tests passed under the race detector. Final high-risk review approved.
No duplicate non-race suite or new low/medium-priority regressions were run. The
remaining items below are follow-up coverage, not observed failing checks. Re-run
only what subsequent changes or specific unresolved concerns warrant.

## Environment-dependent checks

- Real macOS Keychain Touch ID/Apple Watch/password operations, cancellation, and error UI.
- Physical FIDO2 enrollment/unlock/re-enrollment after rekey, disconnects, and multiple hardware models.
- Authenticated interactive PTY sessions, terminal resize/control keys, and remote-shell behavior in actual terminal emulators.
- Live GitHub authentication, repository creation, rate limits, remote network interruptions, and token expiry.
- Linux runtime execution (cross-compilation has passed, but is not runtime validation).
- Physical power-loss/media failure durability (synthetic I/O faults/process death have regression coverage).

## Historical phase verification ledger

These are **prior-phase reports**, not fresh verification of the final checkout:

- Phases 1–3 reported full non-race tests, applicable race suites, vet and Linux
  cross-builds passing after their fixes. Fixtures exercised synthetic storage
  faults/process death, local bare Git remotes, loopback SSH/OpenSSH, import
  reference output and bounded/shared probes; they did not use live credentials.
- Phase 4's final remediation reported `go test ./... -count=1`,
  `go test -race ./... -count=1`, `go vet ./...` and `git diff --check` passing.
  Its earlier full-race FIDO timeout is **superseded**: the synthetic enrollment
  completion budget was raised from 3 to 15 seconds after correct rejection was
  measured at about 3.43 seconds under race instrumentation. Both rejection and
  non-publication assertions remain. A loaded parallel run also hit an SSH
  fixture deadline; separate subsequent full runs passed. Avoid overlapping
  expensive suites when interpreting timing failures.
- Phase 5 changed UI, hardware Context APIs and fixtures afterward. Its focused
  follow-up passed as recorded below; full TUI, full integration/race and broader
  FIDO/vault package checks were not repeated on that final state.
- Phase 2's existing staged-guard benchmark was approximately **198.24 ms and two
  Git processes for 1,000 files**, versus the historical 22.23-second baseline.
  Fixture sizes/iteration counts differ; see the summary for the exact caveat.
  This is not a new measurement or a full-sync speed claim. No post-Phase-5 UI
  benchmark, allocation measurement, contrast measurement or screenshot audit
  is available.

The final verification above supersedes the earlier integration-pending status.
Use synthetic credentials/temp repositories and fake hardware tools for automated
follow-up. No new benchmark is required merely to restate the existing guard result;
rerun it only if implementation changes or an unresolved concern warrants it.

## Phase 5 — evidence

`go test ./internal/tui ./internal/theme` ran once. Theme passed; TUI had one
failure because the restore fixture discarded the new async capability command.
The fixture now delivers a synthetic result. The affected follow-up passed (7.585s):

```sh
go test ./internal/tui -run 'Test(WelcomeRestoreFlow|WelcomeEnrollOffer|LaunchAutoFidoUnlock|ViewListResponsive|Phase5|SyncTwoMachinesReloadAndRecipient|SyncReconcilesChangedOrigin|StatusExpiry|SpinnerActive)'
```

Three new high-priority tests cover retained script content/original target,
stale-copy recovery without overwriting concurrent edits, and hardware cancellation
before enrollment publication. Fake FIDO fixtures also stub `security` to prevent
real Keychain access. `git diff --check` passed. No new medium/low UI tests,
benchmarks, full-suite or race runs; the complete TUI suite was not repeated.

## Phase 5 — untested UI paths and precise follow-up

- **Size matrix:** render/interact at 40×8, 40×24, 80×24, 120×30, 160×40.
  Cover welcome/restore, unlock, master-key banner, every wizard choice/test/paste
  step, script picker/editor, settings and deletion prompts. Check frame dimensions,
  focused input/selected row visibility and bottom actions via PgUp/PgDn.
  Existing responsive tests cover only a subset.
- **Scrolling:** page through all help at 80×24/40×8, including repeated boundary
  keys. Test 30+ identities, first/last rows and missing/reordered IDs after reload.
  Inspect compact hints and selector navigation.
- **Inputs/Unicode:** enter 100+ cells into matching/no-match filters and category
  prompts, then backspace to empty. Exercise CJK, emoji/ZWJ and combining accents
  in names/tags/targets. Resize active key/script textareas with the cursor on the
  final line; verify horizontal viewport, visible cursor and exact retained content.
- **Details/copy:** use `v` below/above 130 columns. Read full IPv6 target, identity,
  jump and fingerprint; check `c`/`f` clipboard success/failure, unpinned targets,
  selection changes and target deletion/retarget while the overlay is open.
- **Editing/recovery:** keyboard-walk Ctrl+F, Enter/Tab/Shift+Tab, Ctrl+S and legacy
  Ctrl+D, including invalid/incomplete fields and auth changes. Escape/run → `D`
  must retain the original draft; `X` discards it. Check Ctrl+N copy-name conflicts
  and failed-write barrier precedence over Ctrl+R. Retention is one session-only
  in-memory draft, not crash/restart recovery.
- **Errors/sync:** generate multiline validation, Git conflict and host-key errors;
  check Ctrl+E, paging, copying, dismissal and successful retry. Compare configured
  versus resolved push URL, including Git rewrites, before/after first sync and
  failures. Check dirty/pending/in-flight state and last-success time.
- **Readiness/charts:** exercise locked/missing credentials, deleted identities,
  failed/successful auth tests, secret-only reload, via-jump rows, old/missing
  probes, backoff and failed samples. Inspect min/avg/max and numeric chart scale;
  ensure sample columns are not described as uniformly spaced time.
- **Themes:** inspect native navy, white/mid-tone `CLAVIS_BG`, ANSI-16/256, tmux
  fallback and `NO_COLOR` in real terminals. Measure essential text/hints/chips/
  statuses against canvas and selection (target ≥4.5:1); check for frozen navy
  styles. Palette/transparency may differ from declared RGB. No new contrast
  measurement or screenshot audit was performed.

## Phase 5 — untested async/performance paths and precise follow-up

**Lower-priority UI performance testing was consciously deferred** to preserve
the requested token/test budget. Caches and batching are implemented, but their
large-fleet performance improvement has not been measured. The checks below are
handoff work, not a condition silently recorded as already passing.

- With delayed fake Keychain/FIDO tools, inspect responsive entry/refresh, copy,
  enrollment/removal, restore offers and unlock refresh. Exercise timeouts,
  cancellation, partial replacement errors and concurrent recipient changes.
  Verify obsolete snapshots cannot consume token/repository request ownership.
  Additive Context APIs in `internal/fido2` and `internal/vault/unlock.go` have
   fixture coverage; their existing package suites passed in final integration,
   but the hardware/interaction combinations listed above remain unexercised.
- Benchmark 100/1,000/10,000 profiles and 20 categories: default/latency sort,
  filtering, category mutation, selection, empty lists and sync reload. Compare
  allocations/sort count; default probe bursts must retain the ordering cache.
- Stress bursts beyond the 64-message channel while retargeting/deleting profiles.
  Verify overflow snapshot reconciliation, group totals, stable-ID actions and
   shutdown; measure update latency. The final race suite passed; additional stress
   workloads listed here were not run.

## Cross-phase recovery and supported-route follow-up

Existing retained regressions cover core boundaries; final integration should
exercise them together with Phase 5 state/command publication, not infer coverage
from the presence of a test file alone:

- **Storage/rekey:** prepare → failed output/flush/EOF/ack → abort; acknowledged
  commit → late output failure; pending recovery and retained committed backup
  across reload; explicit `RestoreLast` plus complete reload with the old key.
  Ensure Ctrl+R only recovers pending writes, preserves drafts and does not replay
  actions or automatically restore committed images. Persistent faults must keep
  the barrier/journals. Physical disk durability remains unvalidated.
- **Sync:** two synthetic machines, local edits plus remote rotation, safe
  one-sided rotation, mixed-generation refusal preserving both histories,
  conflict/cancellation/abort failure, stale editor/ciphertext, origin pushurl
  and URL rewrites. Check last-success retention, explicit new-key unlock and
  local PAT/FIDO mismatch handling after a remote rotation. Manual/noncooperating
  filesystem writers are outside advisory-lock guarantees.
- **Async trust/settings:** cancel or retarget saved/wizard tests, remove a
  selected identity during picker reload, arrive at a save barrier with pending
  token/repository results, and retry after recovery. Old/duplicate results must
  not consume a newer request or publish trust/configuration. Keep full old/new
  fingerprints readable and confirmation deliberate at compact sizes.
- **SSH/import:** retain real loopback encrypted-key and rejected-key/password
  fallback checks for direct and key-based jump routes, target/jump prompt
  separation (including identical prompts), original jump auto/force/never
  provider policy, pin mismatch, setup deadline and cleanup cancellation. Run
  actual terminal typing/resize/logout and Linux FIFO/askpass helper runtime;
  cross-build and macOS headless fixtures do not cover those paths. Compare
  supported import fields with `ssh -G` using synthetic config only; check Include
  context, case/first-value precedence and explicit unsupported-form rejection.
- **Probe integration:** verify 16 active exchanges includes banner waits, shared
  address suspension survives owner retarget/removal, backoff/freshness labels
  remain honest, stale queued status is rejected, and Stop drains work while UI
  batching/overflow reconciliation is active. Loopback concurrency assertions
  are not production fleet throughput measurements.
- **Responsiveness ceiling:** local CRUD remains synchronous under nonwaiting
  ownership. Large metadata, slow storage/recovery and protected-key parsing can
  still pause the UI; no hard bound was established. Defer lower-priority timing/
  allocation tests as above; move captured mutations to commands only if evidence
  warrants that additional implementation.

## Unsupported versus untested

Unimplemented by design: automatic two-key credential migration, semantic JSON
conflict merging, user-facing committed-backup restoration, crash-persistent
script drafts, password-only ProxyJump, ProxyJump scripts, and jump-aware
in-process tests. Import represents a documented OpenSSH subset, not every option.
These are explicit product boundaries, not pending verification claims. Physical
hardware, terminal/Linux runtime, broad post-Phase-5 integration and the visual/
performance checks above are **implemented paths awaiting validation**. Any newly
observed missing behavior required by the approved scope must go to the controller
as an actionable implementation gap rather than being marked tested or resolved.
