# Clavis application review

Date: 2026-09-09

## Review brief

Review this application end to end for correctness, inefficient code, performance
bottlenecks, and UI/UX quality. Trace the main user journeys and data flows; examine
error handling, state management, persistence, accessibility, terminal-size
adaptation, and visual consistency. Validate findings with existing checks or
focused reproductions where practical. For each actionable finding, provide
severity, file/line evidence, user impact, and the simplest effective improvement.
Prioritize confirmed bugs and high-value fixes, distinguish measured results from
hypotheses, and finish with a practical improvement roadmap.

## Summary

The package boundaries are clear, and the application already has useful features:
encrypted credential storage, reusable identities, background probes with backoff,
asynchronous preflight checks, script targeting, and a consistent terminal visual
language. The existing tests and race checks pass.

The most important weaknesses are at boundaries between individually working
components: moving stores between machines, synchronizing disk and UI state,
persisting metadata alongside credentials, handling asynchronous wizard results,
and rotating differently encrypted local files. Address these before visual polish.

Severity convention:

- **High:** potential credential/data loss, wrong-host actions, or broken core persistence.
- **Medium:** broken supported workflows, misleading feedback, or significant usability problems.
- **Low:** bounded resource leaks or lower-impact improvements.

Evidence labels:

- **Reproduced:** exercised with synthetic fixtures and focused Go tests.
- **Measured:** a local benchmark or computed color contrast, with scope stated.
- **Code-traced:** follows directly from the implementation; full runtime behavior was not exercised.

## Correctness and reliability

### 1. High — restored stores write to the original machine's path

**Evidence: reproduced.** `internal/profile/profile.go:75-93`,
`internal/profile/identity.go:42-60`, `internal/script/script.go:68-85`.

Each store exports `Path` without `json:"-"`. Save serializes that absolute path;
Load initializes the destination path, then JSON unmarshalling overwrites it with
the source machine's path. Copying all three JSON stores to another directory and
loading them reproduced the defect for profiles, identities, and scripts.

**Impact:** restore appears successful, but edits subsequently fail with permission
errors or write into the wrong directory. A second configuration on the same
machine can accidentally update the first configuration. Local path information
also travels through Git unnecessarily.

**Smallest fix:** exclude `Path` from JSON in all three stores and derive it solely
from the caller's configuration directory. Ensure existing JSON containing `Path`
is ignored. Add a save → copy to different directory → load → save regression test.

### 2. High — a failed rekey can make existing secrets unrecoverable

**Evidence: reproduced with a metadata-write fault.**
`internal/vault/vault.go:299-352`, especially `337-348`.

Rekey decrypts everything first, but then replaces ciphertext files individually
before writing the new metadata. If a later write fails, it returns an empty new
key. Some or all secrets are already encrypted to that unreturned key. Injecting
a metadata-write failure reproduced an existing secret becoming undecryptable by
the old key after `Rekey` returned an error.

**Impact:** disk-full, permission errors, or interruption during rotation can cause
credential loss. Per-file atomic rename does not make the whole rotation atomic.

**Fix:** stage a complete replacement generation while retaining the old one;
make the generation switch recoverable, and ensure the replacement key is safely
available before retiring the old generation. Test failures at every write/switch
boundary and recovery after interruption.

### 3. High — sync pulls data but leaves the running application stale

**Evidence: reproduced at the sync-completion boundary.**
`internal/gitsync/gitsync.go:270-283`, `internal/tui/app.go:306-313`.

Sync performs `pull --rebase`, which changes files on disk. `syncDoneMsg` only
updates the status message. It does not reload profiles, identities, scripts,
configuration, vault metadata, or probe targets. A fixture representing a pulled
profile remained absent from the model and was deleted from disk by the next
`saveAll` call.

**Impact:** another machine's changes are invisible and may be overwritten. If
the remote rotated the vault, the old in-memory recipient/identity also becomes
inconsistent with the ciphertext on disk.

**Fix:** serialize mutation and sync, then reconcile/reload the complete state after
a successful pull, preserving selection by ID. Detect recipient changes and request
the appropriate unlock. Do not reuse `reloadFetched` blindly: it creates a locked
vault and is currently designed for first-run restore.

### 4. High — overlapping sync operations share one Git index and worktree

**Evidence: reproduced command scheduling; code-traced Git overlap.**
`internal/tui/app.go:592-615,632-640`, `internal/tui/list.go:221-222`,
`internal/tui/scripts.go:557-563`, `internal/tui/identities.go:155-161`.

`syncing` is a display flag, not a guard. A second manual sync or autosync schedules
another transaction while the first is still running. UI saves can also change
files during add, validation, commit, or rebase.

**Impact:** index-lock errors, inconsistent completion messages, worktree conflicts,
and a broken assumption that the index validated is the index committed.

**Smallest fix:** one in-flight sync plus a dirty/pending flag that coalesces later
requests into one follow-up sync. Coordinate file mutations with the Git operation;
multiple processes using the same config directory need a directory-scoped lock.

### 5. High — credential-write failures are reported as successful saves

**Evidence: reproduced.** `internal/tui/wizard.go:648-711,716-761`;
similar ignored errors at `internal/tui/list.go:291-295,318-327`.

The wizard mutates the profile/identity before saving secrets. Key/passphrase
writes and deletions ignore errors. A password-write error sets an error status,
but the final `saved ...` status immediately replaces it and the draft is discarded.
A failed vault-directory write reproduced a green success message with no saved
credential. Deletion can also remove secrets before metadata persistence succeeds.

**Impact:** users lose their input and believe credentials were stored; metadata
can refer to missing secrets, or retained profiles can lose deleted credentials.

**Fix:** check every persistence error, retain drafts on failure, and coordinate
metadata and secret updates with recoverable ordering/rollback. Report success only
once the complete operation succeeds. Apply the same policy to import and deletion.

### 6. High — canceled wizard tests can pin another server's key on a live profile

**Evidence: reproduced.** `internal/tui/app.go:297-303,381-417`,
`internal/tui/wizard.go:312-324,624-628`.

Wizard tests and saved-profile tests share `testDoneMsg` with only a profile ID.
The global handler applies every result to the live store before considering the
wizard. Editing an unpinned profile to target a different host, starting a test,
canceling, then receiving a successful result pins the draft host's key onto the
unchanged original profile.

**Impact:** canceling an edit still changes persisted trust state, and subsequent
connections to the original host fail against the wrong pin.

**Smallest fix:** distinguish draft test results from live tests and attach a
request generation/endpoint snapshot. Keep draft pins in the draft until save;
ignore stale/canceled results.

### 7. High — live latency sorting silently changes the selected host

**Evidence: reproduced.** `internal/tui/list.go:60-94,237-250`,
`internal/tui/app.go:293-295`.

Selection is a numeric cursor into a list that is re-sorted whenever latency
changes. In a two-host fixture, one probe update changed the selected ID from
`a` to `b` without any navigation input.

**Impact:** Enter or a script action can target a different machine from the one
the user selected. This is more serious than a cosmetic jumping-row issue.

**Smallest fix:** track selected profile ID, and derive its cursor index after
sorting/filtering/mutation. Keep it stable as probe results arrive.

### 8. Medium — FIDO2 enrollment breaks vault verification and rotation

**Evidence: reproduced with the same age envelope type, without hardware.**
`internal/vault/vault.go:272-290,314-333`,
`internal/fido2/fido2.go:46-47,216-220,235-249`.

The FIDO2-wrapped master key is `local/master-key.fido2.age`, encrypted using an
age scrypt recipient derived from the hardware secret. Vault maintenance treats
every `local/*.age` file as encrypted to the vault's X25519 identity. Consequently,
valid FIDO2 enrollment makes `VerifyAll` and `Rekey` fail to decrypt that file.

**Fix:** explicitly distinguish vault-owned local secrets from the hardware
envelope. Verify the latter through its own mechanism. During rotation, rewrap or
invalidate/re-enroll the hardware copy so it cannot silently retain the old key.

### 9. Medium — changing the sync URL does not change the actual destination

**Evidence: reproduced using local temporary destinations.**
`internal/tui/settings.go:415-420`, `internal/tui/app.go:603-614`.

Settings updates `cfg.Sync.Remote`, but sync calls `SetRemote` only when origin is
absent. An existing origin remains unchanged. The success message uses the new
configured URL even though Git uses the old URL.

**Impact:** backups continue going to the previous repository while the UI suggests
otherwise. Creating a replacement repository has the same issue.

**Smallest fix:** reconcile origin with the configured destination before sync,
not merely when origin is missing; report the destination actually used.

### 10. Medium — passwords and key passphrases are modified by whitespace trimming

**Evidence: password reproduced; passphrase uses the same code path.**
`internal/tui/wizard.go:465-466,501-505,517-521`.

`commitStep` trims every input, including secrets. A password containing leading
or trailing spaces was changed before storage. Protected keys with such a
passphrase cannot be unlocked through this form.

**Smallest fix:** use the exact input bytes for passwords/passphrases; trim only
metadata fields. Keep the intended empty-input behavior explicit when editing.

### 11. Medium — SSH config import misparses valid OpenSSH syntax

**Evidence: reproduced.** `internal/sshconfig/sshconfig.go:70-100,103-127`.

Three common forms fail:

- `User<TAB>Deploy`: splitting only on literal spaces drops the directive.
- `User=Deploy` / `IdentityFile=/Tmp/MyKey`: lowercasing the combined token changes
  the value, including case-sensitive usernames and paths.
- `Host *` defaults: ignored instead of inherited by concrete hosts.

**Impact:** imported profiles have wrong users or missing keys even though the
original OpenSSH configuration works.

**Fix:** tokenize the directive independently from its value and preserve value
case. Resolve inherited settings with OpenSSH semantics. Since OpenSSH is already
a prerequisite, evaluating discovered aliases with `ssh -G -F <config> <alias>`
is worth considering instead of expanding a partial parser; account for the
behavior of trusted SSH configuration, including `Match exec`.

### 12. Medium — SSH timeout coverage ends too early

**Evidence: session-open hang reproduced; password-handshake path code-traced.**
`internal/sshx/sshx.go:145-154`, `internal/sshx/session.go:145-158`.

Connection tests clear the deadline after the handshake, before opening a session
and running `echo`. A local SSH server that authenticated but did not answer channel
requests kept a 50 ms test blocked beyond 300 ms. In the password-session path,
`ssh.ClientConfig.Timeout` used by `ssh.Dial` bounds TCP dialing, not the subsequent
SSH handshake, so a banner-speaking service can suspend the UI indefinitely.

**Fix:** bound the full test operation and cap its output; apply explicit deadlines
through password handshake/session setup, clearing them for the interactive shell.
Use cancellation to stop abandoned work. Git commands likewise need a bounded,
cancelable execution path (`internal/gitsync/gitsync.go:47-59`).

### 13. Medium — interactive key sessions ignore stored passphrases/password fallback

**Evidence: code-traced.** `internal/tui/app.go:549-568`,
`internal/sshx/session.go:36-91`.

Test and script paths consume the complete `Credentials` object. Interactive key
sessions pass only `PrivateKey` to `ExternalCommand`. A stored key passphrase is
never supplied to OpenSSH; a profile with both key and password also does not
receive its stored password fallback.

**Impact:** a profile can pass the connection test but ask users to re-enter secrets
when connecting, undermining reusable credentials and vault convenience.

**Fix:** use a supported credential handoff for interactive sessions, or reuse an
in-process session path that supports the same auth methods. Never put secrets in
command arguments or general environment variables.

### 14. Medium — doctor misses absent required credentials

**Evidence: reproduced.** `internal/cli/cli.go:59-88`,
`internal/vault/vault.go:272-290`.

Doctor decrypts files that exist, but never checks profiles/identities for required
secret references. A profile needing an absent password received “all checks
passed.” The importer explicitly promises that doctor will flag missing keys.

**Smallest fix:** load metadata and check referenced identities and each required
password/key before ciphertext verification. Include missing-reference diagnostics.

## UI functionality and aesthetics

### 15. Medium — validation errors disappear before they can be read

**Evidence: reproduced.** `internal/tui/wizard.go:149-151,669-672,732-735`,
`internal/tui/settings.go:236-240,268-272`.

Both flows set an error then call a transition helper that clears it. Invalid
profile names/duplicates return to the name step without an explanation; a rejected
GitHub token resets its prompt with no visible rejection reason.

**Smallest fix:** transition first, then assign the error, or explicitly preserve
errors across transitions. Keep actionable errors available until dismissal or
successful retry rather than relying only on a disappearing footer.

### 16. Medium — compact terminals hide controls and selected items

**Evidence: reproduced by rendering model frames.**
`internal/tui/app.go:662-664,691-701`, `internal/tui/scripts.go:280-282`,
`internal/tui/list.go:429-488,989-1053`,
`internal/tui/wizard.go:867-891`.

- At 40 columns, the script manager renders 46 columns, despite the root accepting
  a 40-column terminal.
- At 80×24, the help overlay loses its bottom content, including the closing hint.
- With 30 identities, the selected last identity is outside the visible wizard
  area because the identity picker has no scrolling window.
- A 100-character filter expanded an 80-column frame to 130 columns. Dropping the
  header's right-hand metadata cannot constrain the left-hand input.

**Fix:** budget every panel against available cells, reuse the existing scrolling
picker pattern, give help a viewport, and make filter/category inputs horizontally
scroll within a fixed budget. Terminal-size changes should resize active textareas
as well as their surrounding panels.

### 17. Medium — light-theme adaptation leaves primary text nearly invisible

**Evidence: code-traced and contrast measured.**
`internal/theme/nightowl.go:170-194,205-216`.

`rebase` adapts neutral tiers but leaves primary text, labels, and accent/status
colors using light-on-dark defaults. With a declared white background:

- Primary text `#d6deeb` on white: **1.35:1**.
- Accent `#7fdbca` on white: **1.63:1**.

Even in the native dark palette, the selected host text is **3.05:1** against the
selection background, selected auth chips **2.47:1**, and wizard hints **2.95:1**
against the navy background. These are useful contrast heuristics for terminal
readability, not a claim of browser WCAG conformance testing.

**Fix:** adapt the complete semantic palette for light backgrounds, and choose
selected-row foregrounds against the selection background. Essential host data,
auth labels, and navigation hints should meet a 4.5:1 readability target. Keep
lower contrast for genuinely decorative separators.

### Additional high-value UX improvements

These recommendations combine source review with the supplied `docs/tui.png` and
`docs/wizard.png` screenshots. They are proposals rather than implemented designs.

| Priority | Improvement | Specific rationale |
| --- | --- | --- |
| High | Provide an explicit host-key review/re-trust workflow | Documentation says editing/retesting re-trusts a changed server, but the wizard preserves the old pin and the test rejects it. Show the full old/new fingerprints and allow a deliberate trust update after verification. See `wizard.go:95-101,703-705` and `app.go:410-420`. |
| High | Make full connection details available below 130 columns | The detail pane exists only at `list.go:381-387`; smaller terminals truncate the target and hide identity, jump, and fingerprint information. A detail toggle using the same content is enough. Include copy-target and copy-fingerprint actions. |
| Medium | Keep the full hostname more prominent than the trend | The screenshot's target column is subdued while trend columns consume substantial width. Prioritize name, full target, auth readiness, and status; hide/narrow trends earlier on smaller terminals. |
| Medium | Distinguish reachable from ready to authenticate | A green TCP probe does not imply stored credentials exist or auth works. Show separate missing-credential/auth-test state and a textual `via jump` indicator in compact rows. |
| Medium | Add jump-to-field editing | The existing Ctrl+S shortcut helps save early, but users still traverse earlier questions to reach a late field. A compact field selector can coexist with the novice-friendly wizard. |
| Medium | Improve script-editor recovery and consistency | Retain unsaved drafts on accidental back navigation, add Shift+Tab reverse traversal, and use consistent save hints across profile and script editors. See `scripts.go:200-220`. |
| Medium | Preserve error details and recovery actions | Errors are truncated and expire; Git conflicts or host-key failures deserve an expandable/copyable detail view. Distinguish local save success from remote sync failure and show last successful sync/pending changes. |
| Low | Explain chart freshness and scaling | Sparklines auto-scale separately per host, and failed probes back off to five minutes. Indicate last-check age, min/avg/max labels, and that chart columns are samples rather than uniformly spaced time. |

Keep the existing restrained visual direction: typography through terminal weight,
consistent selection marker, teal identity accent, and quiet section dividers.
Improving contrast and information hierarchy offers more value than adding colors,
animations, decorative panels, or another UI dependency.

## Performance and inefficiencies

### 18. High at larger vault sizes — sync guard launches Git once per secret

**Evidence: measured.** `internal/gitsync/gitsync.go:153-185`.

The staged guard enumerates the whole index, then invokes `git cat-file` separately
for each encrypted file, including unchanged ones. Local measurements of just
`guardStaged`, excluding setup, encryption, pull, and push:

| Encrypted files | Guard time |
| ---: | ---: |
| 10 | 224 ms |
| 100 | 2.10 s |
| 1,000 | 22.23 s |

Environment: Apple M5 Pro, darwin/arm64, Go 1.27.1. Single-iteration synthetic
benchmarks; absolute subprocess times vary across installations.

**Smallest fix:** use one `git cat-file --batch` process to validate indexed object
IDs, retaining staged-content and symlink checks. Add coalesced sync scheduling
from finding 4. Do not trade away index validation for speed.

### 19. Low — every external SSH session leaks a signal-watcher goroutine

**Evidence: reproduced.** `internal/sshx/session.go:47-61`.

The watcher waits on `<-sig`. Cleanup calls `signal.Stop(sig)`, which does not close
that channel, so normal completion never releases the watcher. Ten create/cleanup
cycles left ten watcher goroutines blocked. Captured cleanup state remains reachable.

**Smallest fix:** a done channel plus a select, with idempotent cleanup such as
`sync.Once`. Make normal exit and signal exit use the same cleanup path.

### 20. Medium — settings renders perform external process and filesystem I/O

**Evidence: code-traced; whole-screen cost not benchmarked.**
`internal/tui/settings.go:466-485`, `internal/vault/unlock.go:85-90`.

Every settings-menu render runs `security find-generic-password` on macOS and
stats FIDO enrollment files. Probe events and spinner ticks trigger rerenders,
placing subprocess latency on the UI path. Keychain save/delete operations also
run synchronously in update handlers.

**Smallest fix:** load local-unlock status when opening settings and refresh it
after relevant operations. Move potentially blocking operations to commands and
keep rendering a function of already-loaded state.

### 21. Low for normal fleets — unnecessary sorting/copying on every list render

**Evidence: measured.** `internal/tui/list.go:39-94,599-608,664-677`.

Every `visible()` call copies and sorts the profiles. Group headings scan the full
visible list again. A synthetic benchmark of `visible()` plus the row region,
120×30 terminal, 20 categories, 26 available rows, no filesystem/network I/O:

| Profiles | Time per render | Allocated per render |
| ---: | ---: | ---: |
| 100 | 0.119 ms | 94.5 KB |
| 1,000 | 0.397 ms | 395 KB |
| 10,000 | 4.124 ms | 3.14 MB |

This is not a full application frame or a production traffic measurement. At
ordinary fleet sizes it is less important than Git process overhead.

**Fix when scale warrants it:** compute visible ordering and group counts once per
relevant state change; reuse them in rendering/selection. In default ordering,
probe updates should not require sorting metadata. Coalesce bursts of probe events
before expensive recomputation. Avoid speculative caches for individual strings.

### Further scale considerations

`internal/probe/probe.go:78-112,225-235` creates a goroutine/connection loop per
profile, even when multiple profiles share one address. Large fleets should share
address-level probes and bound concurrent dials. Cancellation-aware dialing would
also make exit responsive instead of waiting for current probe timeouts. This was
code-traced, not load-tested; prioritize only for actual fleet sizes or measured
connection-rate problems. Existing jitter and exponential backoff are useful.

## Verification performed

Baseline checks completed successfully:

```text
go test ./...
go vet ./...
go test -race ./...
bash -n install.sh
```

Focused audit checks were injected with Go's `-overlay` mechanism from temporary
files outside the repository. They used synthetic credentials, temporary config
directories, and a loopback SSH fixture. Reproduction tests intentionally assert
the desired behavior and fail on the current implementation; they do not indicate
that the existing suite regressed.

Reproduced issues cover relocated store paths, failed rekey recovery, FIDO envelope
maintenance, sync/model reconciliation, overlapping sync scheduling, changing
origin, failed credential writes, password whitespace, hidden validation errors,
selection stability, canceled draft test pinning, compact layouts, SSH config
syntax, missing-credential doctor checks, SSH test timeout, and watcher cleanup.

The two microbenchmarks and contrast calculations are reported above. Source
inspection covered entry points, CLI/import/install flow, stores, vault/unlock,
FIDO2 integration, SSH test/session/script paths, probes, Git sync, and TUI screens.

Limits: no live GitHub account/repository operations, physical security-key
ceremonies, authenticated interactive SSH sessions, or terminal-emulator visual
automation were exercised. Screenshot observations are based on supplied images;
layout defects were verified through rendered model frames. No claims of an
exhaustive security audit or measured production throughput are made.

## Recommended order of work

1. **Protect data and trust:** fix store paths, recoverable rekey, coordinated
   credential persistence, canceled test results, and selected-host stability.
2. **Make sync dependable:** single-flight/coalesced transactions, correct origin,
   safe reload/reconciliation, recipient-change handling, and batch staged reads.
3. **Repair supported workflows:** FIDO maintenance, exact secret input, SSH config
   semantics, bounded SSH setup/tests, consistent auth handoff, and doctor references.
4. **Restore UI clarity:** visible validation errors, scrollable help/identity
   picking, fixed-width inputs, complete light/selected palettes, accessible details,
   and explicit host-key recovery.
5. **Polish with evidence:** cache settings capabilities, stop watcher leaks, improve
   script drafts and field navigation, then optimize list/probe scale as needed.

The highest-value next implementation is the persistence/sync correctness work,
with fault-injection and two-machine workflow tests. A wholesale rewrite or new UI
framework is unnecessary.
