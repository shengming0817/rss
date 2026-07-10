# Implementation Plan: Runtime Assembly Optimization Plan

**Branch**: `docs/1655-runtime-assembly-plan` | **Date**: 2026-07-08 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `docs/spec/001-runtime-assembly-plan/spec.md`

## Summary

Create the SpecKit planning foundation for the runtime assembly optimization series. This PR records the target capabilities, hard architectural constraints, PR sequence, validation commands, and project-specific execution rules. It is documentation and planning only; runtime behavior remains unchanged.

## Technical Context

**Language/Version**: Markdown documentation in a Rust workspace pinned to Rust 1.96.0.

**Primary Dependencies**: Cargo workspace, `xtask`, `deny.toml`, dylint registry, SpecKit templates, and RSS rule documents.

**Storage**: Documentation under `docs/spec/001-runtime-assembly-plan/` and `docs/rules/runtime-assembly-plan.md`.

**Testing**: `cargo xtask verify --fast`.

**Target Platform**: RSS repository governance and future runtime assembly PRs.

**Project Type**: Rust workspace documentation and governance planning.

**Constraints**: Docs-only foundation; no runtime behavior change; no new assembly schema; no generated runtime module output; no Soft-only governance claims.

**Scale/Scope**: One SpecKit feature directory, one `.specify/feature.json` pointer update, and one runtime assembly rule document.

## Constitution Check

RSS uses `CLAUDE.md`, `docs/rules/**`, Cargo metadata, `deny.toml`, clippy configuration, dylint, and `xtask` as its active governance sources.

- **Layering / crate graph**: PASS. This PR does not change dependencies. Future work must keep domains isolated and communicate cross-domain only through contracts and generated code.
- **Assembly fact ownership**: PASS. This PR records that `assembly.toml` owns deployment provider facts and does not replace `contracts/**` as the wire contract source.
- **AI-HARD governance**: PASS. This PR names future Hard/Medium expectations but does not declare a current `INVARIANT:` without a carrier.
- **No behavior change**: PASS. This PR does not edit runtime Rust code, adapter code, migrations, generated code, or assembly schema.
- **Open-source reference**: PASS. This series uses existing Rust workspace and xtask patterns, especially rust-analyzer xtask and Omicron workspace/context patterns.

## Benchmark References

- `ref: rust-lang/rust-analyzer xtask/src/main.rs@master` - compact `cargo xtask` command entrypoint for repository-specific automation.
- `ref: oxidecomputer/omicron Cargo.toml@main` - large Rust workspace using Cargo metadata and repository tooling as governance carriers.
- `ref: oxidecomputer/omicron nexus/src/context.rs@main` - server context and shared state construction pattern used as contrast for RSS explicit runtime wiring.

RSS adopts the idea of repository-owned tooling and explicit shared runtime state, but keeps domain-native crate boundaries, provider declarations, and manual constructor injection rather than adding a runtime DI container.

## Project Structure

### Documentation

```text
docs/spec/001-runtime-assembly-plan/
├── spec.md
├── plan.md
└── tasks.md

docs/rules/
└── runtime-assembly-plan.md
```

`specs/001-runtime-assembly-plan/**` resolves to the same files through the existing `specs -> docs/spec` symlink.

### Source Code

```text
.specify/
└── feature.json
```

No Rust source, migrations, generated code, or assembly schema files are in scope for PR-001.

## Runtime Assembly Boundary Map

| Area | Current Source | This Series Target | Carrier |
|------|----------------|-------------------|---------|
| Runtime root | `assemblies/runtime/src/lib.rs` | Phase skeleton, move-only splits, no-behavior-change harness | Rust tests + future baseline gate |
| Shared dependencies | `SharedRuntimeDeps` in `assemblies/runtime/src/module.rs` | Keep infra/provider inputs from becoming a service locator | `cargo xtask runtime-deps guard` |
| Module output | `DomainModuleResult` in `crates/bootstrap/src/module.rs` | Standard probes/resources/workers merge and drain | Type system + tests |
| Provider facts | `assemblies/runtime/assembly.toml` | Expand to domains/topology/listeners and capability closure | `cargo xtask assembly validate` |
| Domain list | Hand-edited runtime wiring | Generated module list from assembly declaration | Future codegen drift gate |
| Visibility | Manual source reading | Runtime graph/baseline output | Future xtask graph/baseline gates |

## PR Path Summary

| PR | Issue | Phase | Summary | Depends | Validation |
|----|-------|-------|---------|---------|------------|
| PR-001 | #1655 | Phase 0 | SpecKit foundation and runtime assembly rule document | none | `cargo xtask verify --fast` |
| PR-002 | #1656 | Phase 0 | Runtime assembly baseline inventory and xtask baseline gate | #1655 | `cargo xtask runtime-baseline verify`; `cargo xtask archrules verify`; `cargo xtask verify --fast` |
| PR-003 | future | Phase 1 | Runtime phase skeleton; `run()` remains behavior-preserving | #1656 | focused runtime phase tests |
| PR-004 | future | Phase 1 | Move infra/env config builders to `runtime::infra` | PR-003 | runtime tests + verify fast |
| PR-005 | future | Phase 1 | Move listener/auth/health finalization to route modules | PR-003 | route/auth/listener tests |
| PR-006 | future | Phase 1 | Extract launch plan and shutdown registration order | PR-005 | launch order tests |
| PR-007 | future | Phase 1 | No-behavior-change runtime harness | PR-004, PR-005, PR-006 | runtime harness snapshot |
| PR-008 | #1663 | Phase 2 | SharedRuntimeDeps infra-only guard | PR-007 | `cargo xtask runtime-deps guard`; `cargo xtask verify --fast` |
| PR-009 | future | Phase 2 | Configure allowed dependency prefixes and rules | PR-008 | runtime deps guard + archrules |
| PR-010 | future | Phase 3 | Add domains/topology/listeners to assembly manifest | PR-009 | assembly manifest tests |
| PR-011 | future | Phase 3 | Validate domain closure against Cargo dependencies | PR-010 | assembly closure tests |
| PR-012 | future | Phase 3 | Validate domain required capabilities and providers | PR-011 | assembly capability tests |
| PR-013 | future | Phase 3 | Introduce AssemblyPlan/RuntimePlan builder | PR-012 | runtime plan tests |
| PR-014 | #1669 | Phase 4 | Define domain binding/output shape | PR-013 | bootstrap/runtime module tests |
| PR-015 | #1670 | Phase 4 | Move `wire_settings`, `wire_identity`, `wire_audit` | PR-014 | wire function tests |
| PR-016 | future | Phase 4 | Generate runtime modules file | PR-015 | codegen check |
| PR-017 | future | Phase 4 | Use generated modules in runtime run path | PR-016 | runtime tests |
| PR-018 | future | Phase 4 | Add settings-only assembly | PR-017 | assembly validate + smoke test |
| PR-019 | future | Phase 4 | Add identity-audit assembly | PR-018 | assembly validate + smoke test |
| PR-020 | future | Phase 5 | Introduce ProviderBundle standardization | PR-019 | provider bundle tests |
| PR-021 | future | Phase 5 | Standardize PG runtime deps outputs | PR-020 | postgres/runtime tests |
| PR-022 | future | Phase 5 | Standardize event transport outputs | PR-021 | event transport tests |
| PR-023 | future | Phase 6 | Export runtime graph | PR-022 | graph baseline verify |
| PR-024 | future | Phase 6 | L2 crash matrix first scenario | PR-017 | crash matrix tests |
| PR-025 | future | Phase 6 | Security production closeout gates | #1655 | closeout guard |
| PR-026 | future | Phase 6 | PR size/spec drift CI governance | PR-023 | CI gate tests |

## AI-HARD Carrier Map

| Constraint | Current Carrier | Future Carrier |
|------------|-----------------|----------------|
| Domains cannot depend on sibling domains | Cargo crate graph + `deny.toml` + `cargo xtask layer-deps` | unchanged |
| Provider declarations match active dependency graph | `assembly.toml` + `cargo xtask assembly validate` | expanded assembly validation |
| Runtime wiring facts do not drift silently | none for full wiring baseline | `cargo xtask runtime-baseline verify` in #1656 |
| `SharedRuntimeDeps` stays infra/provider-only | `cargo xtask runtime-deps guard` | configurable allowlist + rules in PR-009 |
| Generated domain module list is current | none before generator lands | codegen drift gate in PR-016/017 |
| PR size and spec drift are visible | review discipline | CI gate in PR-026 |

## Complexity Tracking

No Constitution Check violations. The planned series is intentionally split because combining baseline, refactor, manifest schema, generated modules, provider bundles, graph output, and CI policy would exceed the reviewable PR budget and hide behavior drift.
