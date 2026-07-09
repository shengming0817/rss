# Implementation Plan: L0/L1 Consistency Hardening SpecKit Baseline

**Branch**: `docs/1708-l0-l1-spec-baseline` | **Date**: 2026-07-08 | **Spec**: [spec.md](./spec.md)

**Tracking**: Epic #1685, docs-only PBI #1708

**Input**: Feature specification from `docs/spec/006-l0-l1-consistency-hardening/spec.md`

## Summary

Create the repo-local SpecKit baseline for the L0/L1 consistency hardening epic. This PR records the shared carrier PBIs, L0 effect-proof track, L1 LocalTx validation track, maximum natural parallelism, and future `/ship` sequence. It is a docs-only baseline and intentionally leaves all implementation PBIs #1686..#1707 open.

## Source Inputs

- L0 planning package: imported SpecKit source for effect-proven LocalOnly; relevant planning content is folded into this feature directory.
- L1 planning package: imported SpecKit source for executable LocalTx hardening; relevant planning content is folded into this feature directory.
- Epic issue: #1685
- Docs-only baseline PBI: #1708
- Implementation PBIs: #1686..#1707

## Technical Context

**Language/Version**: Markdown documentation in the RSS Rust workspace.

**Primary Dependencies**: Existing SpecKit templates under `.specify/templates/`; existing issue tracker PBIs; existing rule sources under `docs/rules/**`.

**Storage**: No runtime storage. Documents live under `docs/spec/006-l0-l1-consistency-hardening/`.

**Testing**: Placeholder scan, `cargo xtask verify --fast`, and diff allowlist check.

**Target Platform**: RSS repository documentation and future Codex `/ship` workflows.

**Project Type**: Docs-only SpecKit planning baseline.

**Performance Goals**: Not applicable; this PR changes no runtime path.

**Constraints**:

- Do not modify Rust code, contract schema, generated files, migrations, or `docs/rules/**` rule bodies.
- Keep this PR limited to `.specify/feature.json` and `docs/spec/006-l0-l1-consistency-hardening/**`.
- Do not close any implementation PBI.
- Ignore previous wave-size limits; use the natural dependency DAG.

## Constitution Check

RSS has no separate constitution file. `CLAUDE.md`, `AGENTS.md`, `docs/rules/**`, and executable xtask/Cargo gates are the applicable governance sources.

- **Docs-only blast radius**: PASS. The planned diff is limited to SpecKit docs and the feature pointer.
- **Issue truth**: PASS. The plan uses real Azure Boards issue numbers instead of generated placeholders.
- **Runtime isolation**: PASS. No runtime, adapter, codegen, contract schema, generated, migration, or rule-body file is in scope.
- **L0/L1 parallelism**: PASS. Shared carrier dependencies are explicit; L0 and L1 branches can proceed in parallel after #1688.
- **SpecKit pointer**: PASS. `.specify/feature.json` intentionally points future default SpecKit commands to this feature. Older feature work must isolate and restore pointer changes because `SPECIFY_FEATURE_DIRECTORY` can be persisted by the SpecKit helper.

## Project Structure

```text
.specify/
└── feature.json

docs/spec/006-l0-l1-consistency-hardening/
├── spec.md
├── plan.md
├── tasks.md
├── quickstart.md
└── checklists/
    └── requirements.md
```

No source code, generated output, migrations, contracts, or rule bodies are part of this PR.

## Issue Map

| Planning ID | Issue | Track | Title | Primary Purpose |
|-------------|-------|-------|-------|-----------------|
| C-00 | #1708 | Baseline | SpecKit baseline for L0/L1 consistency hardening | Repo-local docs-only source for #1685 |
| C-01 | #1686 | Shared | HTTP consistency metadata carrier | Make L0-L4 runtime-visible in generated HTTP metadata |
| C-02 | #1687 | Shared | Unified evidence schema: LocalTx fields + effect profile shape | Define LocalTx/effect evidence carriers |
| C-03 | #1688 | Shared | Codegen registries: EffectProfile + LOCAL_TX_SPECS | Generate shared registries for L0 and L1 gates |
| L0-01 | #1689 | L0 | local-only effect lint | Static LocalOnly effect check entry |
| L0-02 | #1690 | L0 | route metadata binding for consistency/effects | Carry generated metadata through route registration |
| L0-03 | #1691 | L0 | port effect classification markers | Classify DI/domain ports for effect checks |
| L0-04 | #1692 | L0 | audit.list-entries split or reclassification | Remove mixed strict L0 and cross-tenant audited write semantics |
| L0-05 | #1693 | L0 | forbidden side-effect guard | Fail LocalOnly routes with forbidden side effects |
| L0-06 | #1694 | L0 | LocalOnly conformance testkit | Reusable side-effect probes and conformance harness |
| L0-07 | #1695 | L0 | consistency/effect report | Deterministic JSON/Markdown posture report |
| L0-08 | #1696 | L0 | consistency/effect breaking review | Governance review for consistency/effect changes |
| L1-01 | #1697 | L1 | localtx-coverage gate | Active LocalTx closure and evidence gate |
| L1-02 | #1698 | L1 | LocalTx boundary vocabulary and closed labels | Low-cardinality LocalTx model for code and metrics |
| L1-03 | #1699 | L1 | Postgres LocalTx runner closure over PgTenantPool | Adapter-local transaction runner without leaking raw PG types |
| L1-04 | #1700 | L1 | Settings L1 repo-atomic CAS tests | Settings LocalTx proof and conflict coverage |
| L1-05 | #1701 | L1 | Identity L1 logout/password-change tests | Identity LocalTx proof and no-write paths |
| L1-06 | #1702 | L1 | LocalTx conformance suite | Reusable LocalTx conformance harness |
| L1-07 | #1703 | L1 | SecretRepo LocalTx matrix | Real Postgres matrix for settings secrets |
| L1-08 | #1704 | L1 | Identity LocalTx matrix | Real Postgres matrix for identity L1 paths |
| L1-09 | #1705 | L1 | LocalTx metrics and trace closure | Operator-visible LocalTx status and closed labels |
| L1-10 | #1706 | L1 | active L1 validation journeys | End-to-end journey coverage and status-board entries |
| C-04 | #1707 | Closeout | verify integration and docs closeout for L0/L1 gates | Final verify/docs integration after implementation PBIs |

## Dependency DAG

The baseline ignores wave-size limits and uses the maximum natural parallelism implied by dependencies.

| Stage | Parallel PBIs | Dependency Gate | Notes |
|-------|---------------|-----------------|-------|
| 0 | #1708 | None | This docs-only PR closes only C-00. |
| 1 | #1686 | #1708 merged | Shared generated consistency metadata carrier. |
| 2 | #1687 | #1686 | Shared evidence schema and effect profile shape. |
| 3 | #1688 | #1687 | Shared generated registries. |
| 4 | #1689, #1690, #1691, #1692, #1697, #1698 | #1688 | Maximum parallel fan-out: four L0 PBIs and two L1 PBIs. |
| 5 | #1693, #1699, #1700, #1701 | Stage 4 prerequisites by issue | L0 guard and L1 adapter/domain proof begin in parallel. |
| 6 | #1694, #1695, #1702, #1705 | Stage 5 prerequisites by issue | Testkits, reports, and observability can progress together. |
| 7 | #1696, #1703, #1704 | Stage 6 prerequisites by issue | Governance review and adapter matrices. |
| 8 | #1706 | #1700, #1701, #1703, #1704, #1705 | L1 journeys after concrete proofs and observability. |
| 9 | #1707 | #1686..#1706 complete | Final docs/verify closeout for the implementation set. |

### PBI-Level Dependencies

| Issue | Depends On | Parallel After Dependencies |
|-------|------------|-----------------------------|
| #1708 | None | Yes, docs-only baseline |
| #1686 | #1708 | No, first shared carrier |
| #1687 | #1686 | No, consumes metadata carrier |
| #1688 | #1687 | No, consumes evidence schema |
| #1689 | #1688 | Yes, L0 lint |
| #1690 | #1688 | Yes, L0 route binding |
| #1691 | #1688 | Yes, L0 port markers |
| #1692 | #1688 | Yes, L0 audit contract correction |
| #1693 | #1689, #1690, #1691 | Yes, L0 guard |
| #1694 | #1692, #1693 | Yes, L0 conformance after audit and guard |
| #1695 | #1693 | Yes, L0 report after guard data exists |
| #1696 | #1695 | Yes, L0 breaking review after report shape |
| #1697 | #1688 | Yes, L1 coverage gate |
| #1698 | #1688 | Yes, L1 vocabulary |
| #1699 | #1698 | Yes, Postgres runner after boundary vocabulary |
| #1700 | #1697 | Yes, settings proof after LocalTx coverage gate |
| #1701 | #1697 | Yes, identity proof after LocalTx coverage gate |
| #1702 | #1698, #1699 | Yes, conformance after model and runner |
| #1703 | #1700, #1702 | Yes, settings matrix after domain proof and suite |
| #1704 | #1701, #1702 | Yes, identity matrix after domain proof and suite |
| #1705 | #1698, #1699 | Yes, observability after model and runner |
| #1706 | #1700, #1701, #1703, #1704, #1705 | No, journey close after proofs |
| #1707 | #1686..#1706 | No, final closeout |

## SpecKit Artifact Decision

Generate the artifacts requested for C-00:

- `spec.md`
- `plan.md`
- `tasks.md`
- `quickstart.md`
- `checklists/requirements.md`

Do not import the L0 package's optional JSON schemas or the L1 package's spreadsheet/JSON planning exports into this PR. Future implementation PBIs may add or modify runtime contracts, generated outputs, rule docs, or test artifacts in their own scoped PRs.

## Verification Plan

1. Run a placeholder-marker scan against `docs/spec/006-l0-l1-consistency-hardening` and `.specify/feature.json`.
2. Run `cargo xtask verify --fast` from the docs worktree.
3. Confirm the final diff contains only `.specify/feature.json` and `docs/spec/006-l0-l1-consistency-hardening/**`.

## Complexity Tracking

No governance complexity violations are introduced by this docs-only baseline.
