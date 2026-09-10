# SDD ledger — plan: docs/superpowers/plans/2026-09-09-application-review.md

## Execution decisions

- User approved all recommendations and requested phased subagent implementation.
- Branch: `fix/application-review`; base: `f61e5a3`. Original review is preserved.
- Work remains in the current checkout on a task branch; no commits/pushes or live configuration changes are authorized. Review gates inspect working-tree diffs instead of commit ranges.
- Task tool has no model parameter. All implementers/reviewers use the available general agent, with role and scope adapted to complexity; no unsupported model-selection claim.
- Subagents are sequential for overlapping source ownership. Each receives its phase scope and writes a report under the pre-approved temporary directory.
- Preflight checked the shared interfaces listed in the implementation plan. No contradictory ownership: stages consume prior reports and run existing regressions.
- Baseline `go test ./...`: PASS.

## Status

User steering: reduce token/test overhead; only new high-priority regressions, avoid repeated broad runs, concise subagent reports, hand off remaining validation in docs/VALIDATION_HANDOFF.md. Continue all implementation phases.

Task 1: complete — storage/vault recovery; independent spec and quality APPROVED after one fix round (durable rollback ordering, case-alias safety, write/load validation). Affected tests/race/vet, full suite, and Linux build passed. API report: temporary clavis-phase1-report.md. Shared package internal/fstxn provides exclusive single-owner Lock, Apply([]Change), safe reads, recovery; Locked loaders avoid nested locking. Rotation is PrepareRekey/Key/Commit/Close, with CLI key delivery and explicit saved acknowledgement before commit.
Task 2: complete — spec/quality independently APPROVED after fixing stale-save reentry, mixed-generation sync refusal, welcome lock nesting, and stable identity deletion/references. Full tests/vet and affected race checks pass. Batch guard now two Git processes at all sizes; 1000-file measurement ~198ms (different larger ciphertext fixture vs review baseline). APIs/conventions in temporary clavis-phase2-report.md: uiLock is non-reentrant UI-thread owner; Locked methods only under lock, Change+Apply requires reload for new revisions, sync pauses actions and coalesces requests, complete applyDisk preserves recipient identity/selection/drafts; new async SSH messages carry endpoint snapshots.
Task 3: complete — independent spec/quality APPROVED, 7 review findings addressed over two fix rounds (pin-only enforcement, ProxyJump fallback/jump askpass isolation, async result separation/coordination, exact import semantics). Whole suite, affected races, Linux build/vet pass. Context/cancellation SSH APIs and task tokens now present; importer resolution/atomic integration and 16-concurrent deduplicated address probes implemented. Exact contracts in temporary clavis-phase3-report.md.
Task 4: complete — spec/quality APPROVED after retained-picker and settings-recovery completion fixes. Atomic CRUD/draft recovery, exact secrets, stable selection, scoped tests, explicit h/type trust/enter host-key recovery delivered. Full tests/race/vet passed by implementer; scoped final review code-only per user. FIDO completion fixture given 15s bound without weakened assertions. API report temporary phase4-report.md.
Task 5: complete — final spec/quality review approved after shared retained-script target guard correction (one high-priority red/green regression). Compact views, palettes, details/copy, field selector/script drafts, error/sync/readiness/freshness, async hardware/capability state, cached/coalesced list updates implemented. Lower-priority tests deferred per user in docs/VALIDATION_HANDOFF.md.
Task 6: complete — concise high-risk final review approved; documentation/1–21 plus extra UX/scale coverage matrix complete in docs/REMEDIATION_SUMMARY.md. Final go test -race ./... -count=1, go vet ./..., bash -n install.sh, git diff --check, Linux/amd64 cross-build all PASS. No duplicate non-race run or new lower-priority regressions. Untested UI/performance and real environment paths documented in docs/VALIDATION_HANDOFF.md. Changes remain on fix/application-review without commits/pushes.
