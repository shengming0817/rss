# Implementation Plan: Runtime Deployment SpecKit v2

**Branch**: `docs/1779-runtime-deployment-speckit-v2` | **Date**: 2026-07-14 | **Spec**: [spec.md](./spec.md)

## 当前事实

The brownfield repository has static assembly intent and generated domain closure, but no complete assembly-lock → executable-plan → deployment → inventory → release-evidence chain. Tracker review found one missing dependency (#1794 → #1802), two unowned subset config schemas, and an incorrect required-forge-check assumption in #1809.

## 目标能力

#1779 freezes the smallest interfaces and implementation program needed for #1780–#1809 and lands a repository-owned specification carrier in the typed fast aggregate. Later owner PBIs implement runtime/deployment carriers and may refine internals without weakening the frozen identities.

## Delivery batches

1. Identity protocol: research/data model, four Draft-07 schemas, RFC-8785 fingerprint vectors/schema cases, target architecture, and rule.
2. Machine closure: spec/plan/quickstart/tasks, exact task baseline, repository xtask machine-input command, typed fast-aggregate membership, mutation selftests, and feature pointer.

The old 001 tree is read-only. 007 replaces it as the active pointer without reader negotiation, aliases, shims, fallback, or dual write.

## Design choices

- Four schemas only: AssemblyLock, RuntimePlan, DeploymentPlan, RuntimeInventory.
- AssemblyLock, RuntimePlan, and DeploymentPlan have separate domain-tagged fingerprints; every downstream artifact carries its immediate upstream identity.
- Fingerprint bytes are `ASCII(stageTag) || NUL || RFC8785(unsignedObject)`; input aggregates close membership, path, order, and child digest semantics before hashing.
- RuntimeInventory is a design boundary; #1806 must add the authorized production HTTP contract.
- Purpose/consumer-bound Vault file bindings are the only stable DeploymentPlan secret representation; Kubernetes Secret and raw environment-value paths are removed rather than negotiated.
- Domain/lifecycle order remains semantic; set-like facts sort canonically.
- Carrier choice prefers type/visibility/schema/codegen/golden Hard proof, then fail-closed Medium proof with red and anti-vacuity evidence.
- Skills invoke repository gates; #1809 extends the existing local `ci-gate` and does not activate a forge required check.

## Four-principle review

- **Thorough**: tracker bodies, exact fingerprint bytes/input universes, three-stage identity chain, subset schema ownership, 31-node/52-edge task baseline, artifacts, contracts, and validation are aligned before downstream implementation.
- **No backward compatibility**: 007 is the single active plan; 001 is immutable lineage and no old reader or dual path is introduced.
- **Elegant and simple**: four target schemas remain; one shared byte protocol and one exact task baseline replace parallel prose interpretations.
- **AI-HARD**: the repository command checks meta-schemas, instances, fingerprint vectors, exact tasks/edges, and synthetic mutations; typed registry membership makes the selftest part of `verify --fast`, while later targets still require their named Hard/Medium carriers.

## Verification plan

1. Resolve the active feature and validate the four schemas, schema cases, and fingerprint vectors.
2. Run `cargo xtask runtime-deployment-spec --selftest`, then `cargo xtask verify --fast`; require Draft-07 schema/instance checks, RFC-8785 vectors, and semantic mutations.
3. Run archrules, fast verification, Make fast verification, and workspace all-targets check.

## 缺口与 owner

The implementation matrix in `tasks.md` is planning prose, not a CI enforcement carrier. Dynamic ordering comes only from the latest #1778 `pm:epic-wave`. #1779 supplies the machine schema/fingerprint validator and registers its selftest in the typed fast aggregate. Same-head receipt aggregation and active-PR scheduling remain #1809, so this PR claims neither receipt closure nor forge activation.

## Rollback

Revert the target documents, schemas/fixtures, xtask command and aggregate registration, and feature pointer together. No runtime data, API, generated deployment artifact, or migration rollback is required, and no compatibility reader remains after rollback.
