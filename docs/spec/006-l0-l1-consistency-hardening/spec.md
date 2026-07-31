# Feature Specification: L0/L1 Consistency Hardening

**Feature Branch**: `docs/1707-l0-l1-closeout`

**Created**: 2026-07-08

**Completed**: 2026-07-14

**Status**: Complete

**Tracking**: Epic #1685, closeout #1707, supply-chain repair #1770

## Outcome

The L0 LocalOnly and L1 LocalTx proof chains are implemented and connected to the existing typed verification registry. The closeout does not add a `GateId`, CLI, CI job, workflow, generated artifact, public API, wire schema, runtime path, or migration.

The original C-00 restriction was a historical constraint for #1708: that PR created a docs-only baseline while #1686–#1707 remained open. It is not a current scope restriction. This closeout updates the rule documents and verification tests after #1686–#1706 landed, and repairs the yanked transitive `spin` versions tracked by #1770.

## User Scenarios & Testing

### User Story 1 - LocalOnly is effect-proven (Priority: P1)

As a reviewer, I can determine from generated evidence and machine checks whether a `LocalOnly` route has only permitted local effects, uses an unambiguous production mount, and preserves tenant and privilege boundaries.

**Independent test**: Run `consistency local-only-effects`; a missing, duplicate, unknown, stray, ambiguous, or forbidden effect fails with the affected contract or mount.

**Acceptance scenarios**:

1. A strict LocalOnly handler that captures `business-write`, `business-transaction`, outbox, publish, workflow, saga, reconcile, worker, or cross-tenant audit effects is rejected; provider-owned read-path transactions remain allowed.
2. Cross-tenant reads require `CrossTenantPrivilege`, which makes the capability ineligible for LocalOnly; classifying it as an ordinary read cannot bypass that boundary.
3. Generated effect and route evidence is checked against source manifests, so hand-written documentation cannot attest compliance.

### User Story 2 - LocalTx is executable and observable (Priority: P1)

As a domain developer or operator, I can trace every active `LocalTx` contract through generated evidence, route ownership, tests, adapter behavior, and bounded metrics; contracts admitted by the status board additionally close through the live Postgres validation journey.

**Independent test**: Run `localtx-coverage` for static closure and `cargo xtask ci run --job integration/postgres-domain` for real Postgres matrices and the #1706 journey.

**Acceptance scenarios**:

1. Every active LocalTx contract closes its manifest, generated registry, owner, route, test, backend profile, and provider probes.
2. Status-board admitted contracts additionally close board, fixture, runner, and `postgres-domain` lane evidence; #1706 does not claim global journey coverage.
3. Validation and authorization failures prove rollback or no-write behavior, while `commit_unknown` and `rollback_failed` remain terminal and non-replayable.

### User Story 3 - Verification membership cannot silently drift (Priority: P1)

As a maintainer, I can rely on typed gate metadata to derive full, affected local `meta`, and remote typed plans without duplicating command inventories in documentation or workflows.

**Independent test**: Table-driven policy regressions check the L0/L1 gates' `OnImpact(Consistency)` membership and their full/remote ownership without equating compile behavior with local cost.

**Acceptance scenarios**:

1. Static L0/L1 proofs remain in full/remote plans and are selected by affected local CI when the Consistency domain is impacted.
2. The same gates do not migrate into Core, Security, or Coverage lanes as duplicate execution paths.
3. Contract checks precede codegen consumers; `localtx-coverage` and `local-only-effects` remain immediately after codegen in that order.

### User Story 4 - Operators have an honest validation ladder (Priority: P1)

As a contributor, I can select fast, full, or live validation without confusing compile-only coverage, artifact reporting, and real backend execution.

**Independent test**: Follow `quickstart.md` and confirm each command provides the documented evidence and failure behavior.

**Acceptance scenarios**:

1. The fixed repository-fast plan runs only its nine always-on repository contracts; L0/L1 proof is selected by affected `make ci` or an explicit direct gate invocation.
2. Full verification adds workspace/default behavior checks and integration compilation, but does not claim to run real backend matrices.
3. The Postgres-domain shard runs without `--allow-missing-tools` and fails closed if its required environment or compiled test inventory is unavailable.

## Requirements

### Functional Requirements

- **FR-001**: `gate_catalog` and typed plan derivation MUST remain the sole machine source for verification membership.
- **FR-002**: L0/L1 static gates MUST use the typed `OnImpact(Consistency)` local policy and remain included in their full and remote typed owners; `CompileKind` MUST describe compilation only, not local cost or membership.
- **FR-003**: Contract validation and breaking review MUST precede codegen; LocalTx coverage and LocalOnly effect proof MUST follow codegen in that order.
- **FR-004**: LocalOnly enforcement MUST fail closed for incomplete or ambiguous effect, mount, state, provenance, tenant, and privilege evidence.
- **FR-005**: Every active LocalTx contract MUST fail closed when its manifest, generated, owner, route, test, backend profile, or provider-probe evidence is missing, duplicated, unknown, or empty.
- **FR-006**: Live Postgres matrices and the scoped #1706 journey MUST remain in `postgres-domain`; only status-board admitted contracts require journey board, fixture, and runner closure, and fast or compile-only validation MUST NOT represent that evidence as completed.
- **FR-007**: Consistency reports MUST expose their verdict in `status`; callers MUST NOT treat the report process exit code as the gate verdict.
- **FR-008**: Documentation MUST explain machine truth and diagnostics without maintaining a second gate inventory or claiming that SpecKit completion is continuous enforcement.
- **FR-009**: The supply-chain repair MUST update only `spin 0.9.8` to `0.9.9` and `spin 0.10.0` to `0.10.1`, without changing parent dependency declarations.
- **FR-010**: The closeout MUST NOT add compatibility aliases, parallel workflows, deny allowlists, public API changes, or runtime migrations.

### Key Entities

- **Typed gate catalog**: Closed `GateId` metadata registry that derives verification plans.
- **LocalOnly effect proof**: Generated and checked evidence that a local route has no forbidden business effects and respects tenant/privilege boundaries; business persistence/outbox/publish are zero, provider reads may execute transactions, and operational state remains governed by its dedicated controls.
- **LocalTx closure**: Contract-to-route-to-test-to-adapter evidence required for every active LocalTx contract.
- **Scoped LocalTx journey**: Additional board/fixture/runner/lane closure for status-board admitted contracts only.
- **Consistency report**: Diagnostic evidence artifact whose JSON `status` carries its verdict.
- **Postgres-domain shard**: Live acceptance boundary for real Postgres matrices and the active L1 journey.

## Success Criteria

- **SC-001**: `cargo deny check` passes and the all-features dependency tree contains `spin 0.9.9` and `0.10.1`, with neither yanked version present.
- **SC-002**: Focused typed-plan tests prove metadata, membership, exclusions, and order without a copied full label snapshot.
- **SC-003**: Direct contract, LocalTx, LocalOnly, report-status, affected local CI, workspace, clippy, and live Postgres validations pass.
- **SC-004**: Active documentation contains no hard-coded gate count, stale blocker instruction, incomplete T001–T023 task, or unresolved SpecKit marker.
- **SC-005**: The PR closes #1707 and #1770 and cites the rust-analyzer typed dispatch/check-only benchmark.

## Assumptions

- #1686–#1706 are complete and their existing machine gates are the implementation truth.
- CI activation, forge, Shadow, and required-check state are maintained only in the CI operations status document.
- Periodic yank preflight, parent dependency major-version refresh, adaptive-CI activation, and forge-state synchronization remain out of scope.
