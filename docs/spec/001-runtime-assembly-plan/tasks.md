# Tasks: Runtime Assembly Optimization Plan

**Input**: Design documents from `docs/spec/001-runtime-assembly-plan/`

**Prerequisites**: `spec.md`, `plan.md`, `docs/rules/runtime-assembly-plan.md`

**Tests**: PR-001 is docs-only. Validation is `cargo xtask verify --fast` plus marker scan for unresolved placeholders.

**Organization**: Tasks are grouped by logical PR so future work can be executed as issue-sized slices.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel because the file set is disjoint.
- **[Story]**: User story from `spec.md`.
- Every implementation task names exact paths.

## Phase 0: SpecKit Foundation

### PR-001 / Issue #1655

- [ ] T001 [US1] Add runtime assembly feature specification in `docs/spec/001-runtime-assembly-plan/spec.md`.
- [ ] T002 [US1] Add implementation plan with technical context, constitution check, PR path summary, and AI-HARD carrier map in `docs/spec/001-runtime-assembly-plan/plan.md`.
- [ ] T003 [US3] Add dependency-ordered task index in `docs/spec/001-runtime-assembly-plan/tasks.md`.
- [ ] T004 [US2] Add runtime assembly execution rules in `docs/rules/runtime-assembly-plan.md`.
- [ ] T005 [US1] Update `.specify/feature.json` to point to `docs/spec/001-runtime-assembly-plan`.

Validation: `cargo xtask verify --fast`; marker scan over `docs/spec/001-runtime-assembly-plan` and `docs/rules/runtime-assembly-plan.md`.

### PR-002 / Issue #1656

- [ ] T006 [US1] Add current runtime assembly baseline document in `docs/architecture/runtime-assembly-baseline.md`.
- [ ] T007 [US2] Add committed generated baseline at `runtime-baseline/runtime.txt`.
- [ ] T008 [US2] Add `cargo xtask runtime-baseline list|verify` in `xtask/src/runtime_baseline.rs`, `xtask/src/main.rs`, and `xtask/src/verify.rs`.
- [ ] T009 [US2] Add red/green tests for command parsing, rendering, drift, missing baseline, empty inputs, and missing anchors.

Validation: `cargo test -p xtask runtime_baseline`; `cargo test -p xtask parse_command_runtime_baseline`; `cargo xtask runtime-baseline verify`; `cargo xtask archrules verify`; `cargo xtask verify --fast`.

## Phase 1: Decompose Runtime Root

- [ ] T010 [US1] Add runtime phase skeleton in `assemblies/runtime/src/phase.rs` and wire phase names from `assemblies/runtime/src/lib.rs`.
- [ ] T011 [US1] Mark `run()` phase boundaries without moving business logic.
- [ ] T012 [US1] Add closed phase-name tests.
- [ ] T013 [P] [US1] Move provider/env builders into `assemblies/runtime/src/infra/` in a move-only PR.
- [ ] T014 [P] [US1] Move listener/auth/health finalization into route/listener modules in a move-only PR.
- [ ] T015 [US1] Extract launch plan and `ShutdownStack` registration order into `assemblies/runtime/src/launch.rs`.
- [ ] T016 [US1] Add no-behavior-change runtime harness and phase order golden.

Validation for T016: `cargo test -p runtime runtime_phase_harness`; `cargo test -p runtime runtime_module_output_harness`; `cargo test -p runtime launch_plan`; `cargo test -p runtime`; `cargo xtask runtime-baseline verify`; `cargo xtask verify --fast`. The harness is pure in-memory and must not call `runtime::run()`, require Docker, or depend on live PG/Vault/Redis/S3/AMQP/SPIFFE state.

## Phase 2: Guard Shared Runtime Dependencies

- [x] T017 [US2] Add `xtask/src/runtime_deps_guard.rs` to parse `SharedRuntimeDeps` fields.
- [x] T018 [US2] Define allowed infra/provider crate and type prefixes.
- [x] T019 [US2] Add synthetic red fixture rejecting domain service fields.
- [x] T020 [US2] Add runtime deps guard to `cargo xtask verify --fast`.
- [x] T021 [US2] Document `WIRING-DEPS-INFRA-ONLY-01` only after the Medium carrier exists.

## Phase 3: Assembly Plan Manifest

- [ ] T022 [US2] Extend assembly manifest parsing with domains, topology, and listeners.
- [ ] T023 [US2] Update `assemblies/runtime/assembly.toml` with explicit domains and listeners.
- [ ] T024 [US2] Add parse red tests for unknown domain, empty domains, unknown topology, and duplicate listeners.
- [ ] T025 [US2] Add domain closure validation against assembly Cargo dependencies.
- [ ] T026 [US2] Add required capability and provider binding validation.
- [ ] T027 [US1] Add `AssemblyPlan` and `RuntimePlan` builder in runtime.

## Phase 4: Domain Composition

- [x] T028 [US1] Define domain binding/output shape without introducing a runtime DI container.
- [x] T029 [US1] Add merge/extend helpers while preserving probes/resources/workers semantics.
- [ ] T030 [US1] Move `wire_settings`, `wire_identity`, and `wire_audit` into runtime domain modules.
- [ ] T031 [US1] Add `cargo xtask assembly generate-modules` and commit generated module output.
- [ ] T032 [US1] Switch runtime assembly to generated module list.
- [ ] T033 [US1] Add settings-only assembly.
- [ ] T034 [US1] Add identity-audit assembly.

## Phase 5: Provider Bundle Standardization

- [ ] T035 [US2] Introduce provider bundle standardization for shared resources.
- [ ] T036 [US2] Standardize PG runtime deps outputs.
- [ ] T037 [US2] Standardize event transport outputs.

## Phase 6: Governance And Visibility

- [ ] T038 [US2] Add assembly graph export for domain/provider/listener/runtime visibility.
- [ ] T039 [US2] Add first L2 OutboxFact crash matrix scenario.
- [ ] T040 [US2] Add security production closeout spec gates for JWKS, Vault, and SPIFFE.
- [ ] T041 [US3] Add PR-size and spec-drift governance to CI.

## Dependencies

- PR-002 depends on PR-001.
- Phase 1 depends on the baseline from PR-002.
- Phase 2 depends on the no-behavior-change harness from Phase 1.
- Phase 3 depends on SharedRuntimeDeps guard completion.
- Phase 4 depends on AssemblyPlan manifest and validation.
- Phase 5 depends on generated domain composition.
- Phase 6 graph gate depends on provider bundle standardization; crash matrix can start after generated runtime modules.

## Parallel Opportunities

- PR-004 and PR-005 can run after PR-003 because their file families are disjoint.
- PR-024 can run after PR-017 without waiting for provider bundle standardization.
- PR-025 can run after PR-001 because it is a security closeout planning lane.

## Implementation Strategy

1. Ship PR-001 as documentation foundation only.
2. Ship PR-002 as baseline inventory plus Medium xtask gate.
3. Make runtime root decomposition no-behavior-change until the harness proves equivalence.
4. Add manifest and generated-module capabilities only after baseline drift is guarded.
5. Keep each normal PR within the documented size budget unless it matches an explicit exception.
