# Implementation Plan: Runtime Deployment SpecKit v2

**Branch**: `docs/1779-runtime-deployment-speckit-v2` | **Date**: 2026-07-14 | **Spec**: [spec.md](./spec.md)

## 当前事实

The brownfield repository has static assembly intent and generated domain closure, but no complete assembly-lock → executable-plan → deployment → inventory → release-evidence chain. Tracker review found one missing dependency (#1794 → #1802), two unowned subset config schemas, and an incorrect required-forge-check assumption in #1809.

## 目标能力

#1779 freezes the smallest interfaces and implementation program needed for #1780–#1809 and lands a repository-owned specification carrier in the typed fast aggregate. Later owner PBIs implement runtime/deployment carriers and may refine internals without weakening the frozen identities.

## Delivery batches

1. Identity protocol: research/data model, four Draft-07 schemas, RFC-8785 fingerprint vectors/schema cases, target architecture, and rule.
2. Machine closure: spec/plan/quickstart/tasks, exact task baseline, focused xtask command, typed fast-aggregate membership, mutation selftests, and feature pointer.

The old 001 tree is read-only. 007 replaces it as the active pointer without reader negotiation, aliases, shims, fallback, or dual write.

## Design choices

- Four schemas only: AssemblyLock, RuntimePlan, DeploymentPlan, RuntimeInventory.
- AssemblyLock, RuntimePlan, and DeploymentPlan have separate domain-tagged fingerprints; every downstream artifact carries its immediate upstream identity.
- Fingerprint bytes are `ASCII(stageTag) || NUL || RFC8785(unsignedObject)`; input aggregates close membership, path, order, and child digest semantics before hashing.
- RuntimeInventory is a design boundary; #1806 must add the authorized production HTTP contract.
- Typed secret references are the only stable secret representation.
- Domain/lifecycle order remains semantic; set-like facts sort canonically.
- Carrier choice prefers type/visibility/schema/codegen/golden Hard proof, then fail-closed Medium proof with red and anti-vacuity evidence.
- Skills invoke repository gates; #1809 extends the existing local `ci-gate` and does not activate a forge required check.

## Four-principle review

- **Thorough**: tracker bodies, exact fingerprint bytes/input universes, three-stage identity chain, subset schema ownership, 31-node/52-edge task baseline, artifacts, contracts, and validation are aligned before downstream implementation.
- **No backward compatibility**: 007 is the single active plan; 001 is immutable lineage and no old reader or dual path is introduced.
- **Elegant and simple**: four target schemas remain; one shared byte protocol and one exact task baseline replace parallel prose interpretations.
- **AI-HARD**: the repository command checks meta-schemas, instances, fingerprint vectors, exact tasks/edges, and synthetic mutations; typed registry membership makes the selftest part of `verify --fast`, while later targets still require their named Hard/Medium carriers.

## Verification plan

1. Resolve the active feature and require the core documents, four schemas, schema cases, fingerprint vectors, and task baseline.
2. Run `cargo xtask runtime-deployment-spec --selftest --against origin/develop`, then `cargo xtask verify --fast`; require Draft-07 meta-schema/instance checks, exact 31-node/52-edge adjacency, carrier parity, RFC-8785 vectors, registry-membership mutants, and content synthetic mutations.
3. Check 001 immutability, diff scope, template markers, and zero generated churn; this approved Cx3 revision has no LOC cap.
4. Run doc contracts, archrules, fast verification, Make fast verification, and workspace all-targets check.
5. Confirm future owner commands in `tasks.md` exactly match tracker validation sequences.

## 缺口与 owner

The implementation matrix is in `tasks.md` and its machine mirror is `fixtures/task-baseline.json`. Dynamic ordering comes only from the latest #1778 `pm:epic-wave`; this document does not duplicate a mutable scheduler. #1779 supplies the specification carrier and registers its selftest in the typed fast aggregate. Same-head receipt aggregation and active-PR scheduling remain #1809, so this PR claims neither receipt closure nor forge activation.

## Rollback

Revert the target documents, schemas/fixtures, xtask command and aggregate registration, and feature pointer together. No runtime data, API, generated deployment artifact, or migration rollback is required, and no compatibility reader remains after rollback.
