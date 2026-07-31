# Requirements Checklist: L0/L1 Consistency Hardening

**Feature**: `docs/spec/006-l0-l1-consistency-hardening`

**Reviewed**: 2026-07-14

**Status**: Complete

## Machine Truth

- [x] Typed `GateId` policy remains the single source for full/remote ownership and affected-local membership.
- [x] No new gate, CLI, workflow, CI job, generated output, runtime path, public interface, wire schema, or migration was introduced.
- [x] Contract review and codegen-adjacent LocalTx/LocalOnly ordering has table-driven regression coverage.
- [x] Static proof, full/default conformance, integration compilation, and live Postgres execution are described as distinct boundaries.
- [x] SpecKit completion is documentation state, not a new continuous-enforcement mechanism.

## L0/L1 Semantics

- [x] LocalOnly failure semantics cover effect closure, production mounts, state/provenance, tenant isolation, and local privilege.
- [x] Every active LocalTx contract has contract-to-route-to-test-to-backend closure; only status-board admitted contracts require journey closure.
- [x] `commit_unknown` and `rollback_failed` are terminal and non-replayable.
- [x] The #1706 journey is described by its admitted contract scope and does not overclaim global coverage.
- [x] Report JSON `status`, not the process exit code alone, is documented as the evidence verdict.

## Documentation Closeout

- [x] T001–T023 are all recorded complete.
- [x] Historical C-00 restrictions are identified as historical rather than active instructions.
- [x] Root, architecture, CI operations, L0/L1 rules, and the full SpecKit pack describe current behavior.
- [x] Hard-coded gate counts, obsolete ship ordering, and the stale #1707 blocker instruction are removed.
- [x] Documentation remains a thin explanation of executable sources and does not duplicate the complete gate inventory.

## Supply Chain and Acceptance

- [x] `spin 0.9.8` and `0.10.0` yanked failures were reproduced before the update.
- [x] `Cargo.lock` resolves the existing transitive chains to `spin 0.9.9` and `0.10.1` without parent declaration or deny-policy changes.
- [x] Deny, dependency-tree, adapter, focused gate, fast, workspace, clippy, and live Postgres validation are in the acceptance plan.
- [x] The PR closes #1707 and #1770 and includes the required rust-analyzer benchmark reference.
