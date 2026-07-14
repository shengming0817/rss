# Implementation Plan: L0/L1 Verification Closeout

**Branch**: `docs/1707-l0-l1-closeout` | **Date**: 2026-07-14 | **Spec**: [spec.md](./spec.md)

**Tracking**: Epic #1685, closeout #1707, supply-chain repair #1770

## Summary

Close the completed L0/L1 hardening work through the existing typed verification architecture, repair the two yanked transitive `spin` patches, strengthen regression tests, and replace historical planning language with the current proof and validation model.

No new gate, command, workflow, generated output, runtime behavior, public interface, wire schema, or migration is introduced.

## Historical Context

C-00 #1708 created this SpecKit directory before implementation started. Its docs-only diff allowlist and “do not start #1707” instruction applied only to that baseline PR. PBIs #1686–#1706 subsequently delivered the shared carriers, LocalOnly effect proof, LocalTx closure, adapter matrices, observability, and active journey. This plan records the resulting topology rather than preserving the old future-work DAG as an active instruction.

## Implemented Proof Topology

```text
contract manifests and evidence schemas
  -> generated consistency/effect/LocalTx registries
  -> route ownership, production mounts, and port classifications
  -> typed Meta gates (contract review -> codegen -> LocalTx -> LocalOnly)
  -> full conformance and integration-target compilation
  -> live postgres-domain matrices and #1706 journey
  -> bounded metrics, traces, reports, and operator diagnostics
```

The executable sources remain:

- `xtask/src/ci_lanes.rs` for closed gate metadata and plan membership.
- `xtask/src/verify.rs` for derived full/fast/lane plans and typed dispatch.
- `xtask/src/consistency_effects.rs` and `xtask/src/localtx_coverage.rs` for fail-closed static proof.
- The integration shard and nextest registries for live Postgres execution.
- `cargo-deny` and `Cargo.lock` for supply-chain resolution policy.

Rule and SpecKit documents explain those sources; they do not replace them.

## Implementation Changes

### Supply chain

- Reproduce the yanked `spin 0.9.8` and `0.10.0` failure with `cargo deny check`.
- Update only the lockfile resolutions to `0.9.9` and `0.10.1`.
- Verify the existing `flume` and `crc-fast` semver constraints accept the patches and that AMQP, MQTT, and S3 backend surfaces still build or test.

### Typed verification

- Replace duplicated label-oriented L0/L1 tests with one table-driven contract over `GateId` metadata.
- Check full, fast, real Meta-lane, and compatibility membership plus Core/Security/Coverage exclusion.
- Check the codegen-adjacent order without copying the complete plan label list.

### Documentation

- Remove hard-coded gate counts and outdated required-check claims from root, architecture, and CI operations entrypoints.
- Describe the Azure active forge, GitHub Shadow evidence, and current non-required `ci-gate` status.
- Rewrite L0/L1 rules as implemented proof chains with adoption order, failure semantics, tenant/privilege boundaries, and the live validation boundary.
- Mark this full SpecKit pack complete and replace baseline-only instructions with current diagnostics and acceptance commands.

## Four-Principle Review

- **Thorough**: fixes the actual dependency blocker and closes code, rules, operations, architecture, and SpecKit drift with focused through live validation.
- **No backward compatibility**: deletes obsolete versions, counts, ordering instructions, and blocker language without aliases, dual paths, or policy exceptions.
- **Elegant and simple**: keeps the typed registry and existing commands as the only machinery; two semver-compatible lockfile patches are the only dependency changes.
- **AI-HARD**: closed `GateId` metadata, derived plans, codegen, static gates, live shards, and cargo-deny remain machine-enforced. Documents carry no independent inventory or completion guard.

## Verification Plan

1. Supply chain: deny check, all-features inverse dependency tree, AMQP/MQTT/S3 targets.
2. Static proof: focused verify-plan tests, contract breaking, LocalTx coverage, LocalOnly effects, and JSON report `status` parsing.
3. Drift scan: unresolved markers, unchecked T001–T023 tasks, stale blocker text, and hard-coded gate counts.
4. Ship funnel: `make verify-fast`, workspace/all-target check, xtask clippy, and live `postgres-domain` without missing-tool relaxation.
5. Review and delivery: diff-sized built-in review, in-scope Cx1/Cx2 fixes, required disposition for Cx3/Cx4, PR metadata, and delayed monitoring.

## External Benchmark

`ref: rust-lang/rust-analyzer xtask/src/flags.rs@63a6f0d4bcfd3bbcf36383fcbcbcd93456ed1653`

The benchmark supports closed typed dispatch and check-only verification. RSS intentionally keeps plan membership registry-derived instead of duplicating task commands in workflow YAML.

## Out of Scope

- New `GateId`, CLI, CI job, workflow, or branch-protection change.
- Runtime, public API, wire schema, generated output, or migration changes.
- `.specify/feature.json` changes or a SpecKit completion-state governance gate.
- Parent dependency major-version refresh, periodic yank automation, adaptive activation, or forge-state synchronization.
