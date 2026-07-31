# Tasks: L0/L1 Consistency Hardening

**Status**: Complete

**Tracking**: Epic #1685, #1686–#1708

This checklist records delivered work. Issue ordering is historical context, not an instruction to recreate the implementation sequence.

## Baseline and Shared Carriers

- [x] T001 [C-00] #1708 Add the repository-local SpecKit baseline and feature pointer.
- [x] T002 [C-01] #1686 Implement HTTP consistency metadata carrier.
- [x] T003 [C-02] #1687 Implement the unified LocalTx/effect evidence schema.
- [x] T004 [C-03] #1688 Generate `EffectProfile` and `LOCAL_TX_SPECS` registries.

## L0 Effect-Proven LocalOnly

- [x] T005 [L0-01] #1689 Implement LocalOnly effect lint.
- [x] T006 [L0-02] #1690 Bind consistency and effects into route metadata.
- [x] T007 [L0-03] #1691 Add port effect classification markers.
- [x] T008 [L0-04] #1692 Separate or reclassify `audit.list-entries` semantics.
- [x] T009 [L0-05] #1693 Implement the forbidden side-effect guard.
- [x] T010 [L0-06] #1694 Add the LocalOnly conformance testkit.
- [x] T011 [L0-07] #1695 Add deterministic consistency/effect reports.
- [x] T012 [L0-08] #1696 Add consistency/effect breaking review.

## L1 Executable LocalTx

- [x] T013 [L1-01] #1697 Implement the `localtx-coverage` gate.
- [x] T014 [L1-02] #1698 Add LocalTx boundary vocabulary and closed labels.
- [x] T015 [L1-03] #1699 Close the Postgres LocalTx runner over `PgTenantPool`.
- [x] T016 [L1-04] #1700 Add Settings repo-atomic CAS proof.
- [x] T017 [L1-05] #1701 Add the historical Identity logout/password-change proof. #1842 later moved
  password-change to L2 OutboxFact, so it is no longer part of the active LocalTx inventory.
- [x] T018 [L1-06] #1702 Add the LocalTx conformance suite.
- [x] T019 [L1-07] #1703 Add the SecretRepo live Postgres matrix.
- [x] T020 [L1-08] #1704 Add the Identity live Postgres matrix.
- [x] T021 [L1-09] #1705 Close LocalTx metrics and traces.
- [x] T022 [L1-10] #1706 Add active L1 validation journeys.

## Final Closeout

- [x] T023 [C-04] #1707 Close typed verification regression coverage and active documentation; #1770 repairs the yanked transitive patches in the same PR.

## Completion Evidence

- Typed gate policy derives full/remote ownership and affected-local `OnImpact(Consistency)` membership.
- Contract review, codegen, LocalTx closure, and LocalOnly proof retain their required order.
- Full/default conformance and integration compile coverage remain distinct from live Postgres matrices and the #1706 journey.
- `Cargo.lock` resolves `spin` to non-yanked semver-compatible patches; parent dependency declarations and deny policy remain unchanged.
- Root, architecture, operations, rule, and SpecKit documentation describes current machine truth without carrying a second gate inventory.
