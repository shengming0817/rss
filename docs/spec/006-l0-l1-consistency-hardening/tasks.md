# Tasks: L0/L1 Consistency Hardening SpecKit Baseline

**Input**: Design documents from `docs/spec/006-l0-l1-consistency-hardening/`

**Prerequisites**: Epic #1685 and PBI #1708 exist; implementation PBIs #1686..#1707 remain open.

**Tests**: This baseline PR uses a placeholder-marker scan, `cargo xtask verify --fast`, and a diff allowlist check. Runtime tests belong to later implementation PBIs.

**Organization**: Tasks are PR/PBI-level only. Each row maps to a real issue and is suitable for a later `/ship` invocation.

## Phase 0: Baseline PR

**Purpose**: Create the repo-local SpecKit truth source and update the default feature pointer.

- [ ] T001 [C-00] #1708 Add `docs/spec/006-l0-l1-consistency-hardening/` and update `.specify/feature.json`; close only #1708.

**Checkpoint**: Future `/ship` work can consume this directory, while all implementation PBIs remain open.

---

## Phase 1: Shared Carrier Chain

**Purpose**: Establish the generated metadata and evidence foundations needed by both L0 and L1.

- [ ] T002 [C-01] #1686 Implement HTTP consistency metadata carrier.
- [ ] T003 [C-02] #1687 Implement unified evidence schema for LocalTx fields and effect profile shape.
- [ ] T004 [C-03] #1688 Implement codegen registries for `EffectProfile` and `LOCAL_TX_SPECS`.

**Checkpoint**: L0 and L1 branches can start in parallel after #1688.

---

## Phase 2: L0 Effect-Proven LocalOnly Track

**Purpose**: Mature LocalOnly from contract declaration to route/handler effect proof.

- [ ] T005 [L0-01] #1689 Implement local-only effect lint.
- [ ] T006 [L0-02] #1690 Bind consistency and effects into route metadata.
- [ ] T007 [L0-03] #1691 Add port effect classification markers.
- [ ] T008 [L0-04] #1692 Split or reclassify `audit.list-entries`.
- [ ] T009 [L0-05] #1693 Implement forbidden side-effect guard.
- [ ] T010 [L0-06] #1694 Add LocalOnly conformance testkit.
- [ ] T011 [L0-07] #1695 Add consistency/effect report output.
- [ ] T012 [L0-08] #1696 Add consistency/effect breaking review.

**Checkpoint**: L0 has generated visibility, effect declarations, handler/port evidence, conformance, reports, and review governance.

---

## Phase 3: L1 Executable LocalTx Track

**Purpose**: Mature LocalTx from declaration plus partial implementation to executable validation across contracts, routes, adapters, metrics, and journeys.

- [ ] T013 [L1-01] #1697 Implement `localtx-coverage` gate.
- [ ] T014 [L1-02] #1698 Add LocalTx boundary vocabulary and closed labels.
- [ ] T015 [L1-03] #1699 Implement Postgres LocalTx runner closure over `PgTenantPool`.
- [ ] T016 [L1-04] #1700 Add Settings L1 repo-atomic CAS tests.
- [ ] T017 [L1-05] #1701 Add Identity L1 logout/password-change tests.
- [ ] T018 [L1-06] #1702 Add LocalTx conformance suite.
- [ ] T019 [L1-07] #1703 Add SecretRepo LocalTx matrix.
- [ ] T020 [L1-08] #1704 Add Identity LocalTx matrix.
- [ ] T021 [L1-09] #1705 Add LocalTx metrics and trace closure.
- [ ] T022 [L1-10] #1706 Add active L1 validation journeys.

**Checkpoint**: L1 has capability evidence, generated visibility, transaction boundary proof, conformance, adapter matrices, observability, and journeys.

---

## Phase 4: Final Implementation Closeout

**Purpose**: Integrate the completed L0/L1 implementation set into verify/docs after all earlier PBIs are done.

- [ ] T023 [C-04] #1707 Complete verify integration and docs closeout for L0/L1 gates.

**Checkpoint**: #1707 is blocked until #1686..#1706 are complete.

---

## Dependencies & Execution Order

### Natural DAG Stages

| Stage | PBIs That Can Run Together | Required Before Stage Starts |
|-------|----------------------------|------------------------------|
| 0 | #1708 | None |
| 1 | #1686 | #1708 |
| 2 | #1687 | #1686 |
| 3 | #1688 | #1687 |
| 4 | #1689, #1690, #1691, #1692, #1697, #1698 | #1688 |
| 5 | #1693, #1699, #1700, #1701 | Each issue's blockers from the table below |
| 6 | #1694, #1695, #1702, #1705 | Each issue's blockers from the table below |
| 7 | #1696, #1703, #1704 | Each issue's blockers from the table below |
| 8 | #1706 | #1700, #1701, #1703, #1704, #1705 |
| 9 | #1707 | #1686..#1706 |

Maximum natural fan-out is Stage 4 with six PBIs. No wave-size cap is applied.

### Direct Dependency Table

| PBI | Direct Blockers |
|-----|-----------------|
| #1708 | None |
| #1686 | #1708 |
| #1687 | #1686 |
| #1688 | #1687 |
| #1689 | #1688 |
| #1690 | #1688 |
| #1691 | #1688 |
| #1692 | #1688 |
| #1693 | #1689, #1690, #1691 |
| #1694 | #1692, #1693 |
| #1695 | #1693 |
| #1696 | #1695 |
| #1697 | #1688 |
| #1698 | #1688 |
| #1699 | #1698 |
| #1700 | #1697 |
| #1701 | #1697 |
| #1702 | #1698, #1699 |
| #1703 | #1700, #1702 |
| #1704 | #1701, #1702 |
| #1705 | #1698, #1699 |
| #1706 | #1700, #1701, #1703, #1704, #1705 |
| #1707 | #1686, #1687, #1688, #1689, #1690, #1691, #1692, #1693, #1694, #1695, #1696, #1697, #1698, #1699, #1700, #1701, #1702, #1703, #1704, #1705, #1706 |

## Follow-Up Ship Order

Use `/ship --level=L2 #<issue>` for each implementation PBI unless a later issue is reclassified by triage.

1. #1686
2. #1687
3. #1688
4. #1689, #1690, #1691, #1692, #1697, #1698 in parallel
5. #1693, #1699, #1700, #1701 as blockers clear
6. #1694, #1695, #1702, #1705 as blockers clear
7. #1696, #1703, #1704 as blockers clear
8. #1706
9. #1707

## Docs-Only Guardrail

The C-00 PR closes only #1708. Any change outside `.specify/feature.json` and `docs/spec/006-l0-l1-consistency-hardening/**` belongs to a later implementation PBI.
