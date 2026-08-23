# Feature Specification: Runtime Assembly Optimization Plan

**Feature Branch**: `docs/1655-runtime-assembly-plan`

**Created**: 2026-07-08

**Status**: Draft

**Input**: User description: "Establish the SpecKit foundation for the RSS runtime assembly optimization series and record the non-negotiable RSS architecture constraints for future runtime assembly work."

## User Scenarios & Testing

### User Story 1 - Runtime assembly work has a single planning entry (Priority: P1)

Runtime maintainers, AI implementers, and reviewers can open `docs/spec/001-runtime-assembly-plan/` and understand the objective, safety constraints, PR sequence, and validation commands for the runtime assembly optimization series.

**Why this priority**: The planned work spans runtime wiring, assembly manifests, generated modules, provider bundles, graph visibility, and CI gates. Without a single planning entry, later PRs can accidentally bypass RSS domain-native rules or mix behavior changes into move-only PRs.

**Independent Test**: Read `spec.md`, `plan.md`, `tasks.md`, and `assembly manifest / AssemblyLock / RuntimePlan / cargo xtask assembly validate`; the reader can determine which PR owns a change, what must remain behavior-preserving, and which validation command applies.

**Acceptance Scenarios**:

1. **Given** a future PR proposes to split `runtime::run()`, **When** the reviewer checks this feature entry, **Then** they can identify the phase boundary, the PR budget, and the no-behavior-change requirement.
2. **Given** a future PR proposes new assembly manifest fields, **When** the implementer checks this feature entry, **Then** they can see that `assembly.toml` is a deployment fact source and must not replace `contracts/**` as the wire contract source.
3. **Given** a future PR proposes a new runtime governance rule, **When** the reviewer checks this feature entry, **Then** the rule must name a Hard or Medium carrier instead of relying on manual convention.

---

### User Story 2 - Runtime wiring cannot bypass domain-native boundaries (Priority: P1)

Architecture reviewers can use this entry to prevent runtime assembly optimization from weakening RSS crate graph boundaries, contract-only cross-domain communication, or the assembly/provider fact model.

**Why this priority**: Runtime assembly is the highest-power composition layer. It can name adapters, domains, generated contracts, and service crates, so this series needs explicit boundaries before code movement begins.

**Independent Test**: For any planned task, map it to the crate graph rules in `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps` and to a validation carrier such as Cargo, deny wrappers, `cargo xtask layer-deps`, `cargo xtask assembly validate`, or a future xtask gate.

**Acceptance Scenarios**:

1. **Given** a domain wants data from another domain, **When** implementing runtime assembly changes, **Then** the path remains `contracts/**` to `generated` to runtime wiring, not a sibling domain dependency.
2. **Given** a provider is activated by an assembly, **When** reviewing the change, **Then** the provider crate, features, lifecycle, durability, and consumer remain machine-readable through `assembly.toml` plus assembly validation.
3. **Given** `SharedRuntimeDeps` gains fields in a future PR, **When** reviewing the change, **Then** domain service objects are not accepted without a Medium or Hard guard.

---

### User Story 3 - Follow-up PRs are bounded and reviewable (Priority: P2)

Project maintainers can split runtime assembly optimization into small PRs with explicit dependencies, special-case rules, and validation commands.

**Why this priority**: The source plan has 26 logical PRs. The series must stay reviewable and avoid combining docs, move-only changes, schema expansion, runtime behavior changes, generated code, and CI policy changes in one oversized change.

**Independent Test**: `tasks.md` lists the PR sequence, dependency order, file ownership, and validation command for each issue-sized slice.

**Acceptance Scenarios**:

1. **Given** a PR claims to be move-only, **When** the reviewer checks the plan, **Then** behavior changes, new rules, and schema changes are rejected from that PR.
2. **Given** a PR exceeds the normal size budget, **When** the reviewer checks the plan, **Then** the PR must match one of the documented special exceptions.
3. **Given** two PRs touch the same file family, **When** planning work, **Then** the dependency order prevents overlapping writes from racing.

## Edge Cases

- `specs/001-runtime-assembly-plan/**` resolves through the existing `specs -> docs/spec` symlink; the canonical repository path remains `docs/spec/001-runtime-assembly-plan/**`.
- The current `assembly.toml` schema has `name`, `profile`, and `diportProviders`; `domains`, `topology`, and `listeners` are future targets and must not be described as current schema.
- `SharedRuntimeDeps` infra-only wiring is now a present `INVARIANT:` carrier via `cargo xtask runtime-deps guard`; future field additions must satisfy that Medium gate.
- Move-only PRs may re-export existing public symbols only when required to keep tests compiling during file movement; they must not create long-lived compatibility aliases.
- Generated module output must be committed and drift-checked when the relevant future PR lands; this foundation PR does not generate runtime modules.

## Requirements

### Functional Requirements

- **FR-001**: System MUST provide a SpecKit feature directory at `docs/spec/001-runtime-assembly-plan/` with `spec.md`, `plan.md`, and `tasks.md`.
- **FR-002**: System MUST update `.specify/feature.json` so SpecKit commands resolve `docs/spec/001-runtime-assembly-plan`.
- **FR-003**: The plan MUST record RSS domain-native constraints: crate graph layering, contract-only cross-domain communication, assembly provider facts, and Hard/Medium governance carriers.
- **FR-004**: The plan MUST separate current repository facts from future target capabilities.
- **FR-005**: The tasks document MUST include the PR-001 through PR-026 sequence from the source implementation plan, including dependencies and validation commands.
- **FR-006**: The runtime assembly rule document MUST define normal PR size budget, special exception classes, and no-behavior-change requirements.
- **FR-007**: This feature MUST NOT modify runtime Rust code, adapter code, migrations, generated code, or assembly schema.
- **FR-008**: This feature MUST pass `cargo xtask verify --fast` in a clean worktree.
- **FR-009**: The three SpecKit files and runtime assembly rule document MUST contain no unresolved clarification markers or template placeholders.

### Key Entities

- **Runtime Assembly Plan**: The ordered series of PR-sized changes that reduces runtime wiring complexity while preserving RSS architecture boundaries.
- **Assembly Fact Source**: `assemblies/{name}/assembly.toml`, the deployment-level DI provider declaration source for provider crate, features, lifecycle, durability, and consumer.
- **Runtime Wiring Anchor**: A stable callsite or type boundary in `runtime::run()` used by later baseline and refactor PRs.
- **SharedRuntimeDeps**: The runtime parameter object that carries shared infrastructure into wiring functions; infra-only intent is enforced by `cargo xtask runtime-deps guard`.
- **Generated Modules**: Future code generated from assembly declarations to select domain modules without hand-editing `runtime::run()`.

## Success Criteria

### Measurable Outcomes

- **SC-001**: `docs/spec/001-runtime-assembly-plan/spec.md`, `plan.md`, and `tasks.md` exist and contain no template placeholders.
- **SC-002**: `.specify/feature.json` points to `docs/spec/001-runtime-assembly-plan`.
- **SC-003**: `assembly manifest / AssemblyLock / RuntimePlan / cargo xtask assembly validate` exists and records Phase 0/1/2 boundaries, PR budget rules, and AI-HARD policy.
- **SC-004**: `tasks.md` lists PR-001 through PR-026 and makes #1656 dependent on #1655.
- **SC-005**: The final diff contains no runtime source, adapter source, migration, generated contract, or assembly schema changes.
- **SC-006**: `cargo xtask verify --fast` succeeds in the worktree.

## Assumptions

- Issue #1655 is the authoritative tracking item for this foundation PR.
- Issue #1656 remains a separate dependent PR and owns baseline inventory plus xtask enforcement.
- Future runtime behavior changes are delivered only after baseline and no-behavior-change harness PRs land.
