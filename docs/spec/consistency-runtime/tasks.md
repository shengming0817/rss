# Tasks: Consistency Runtime SpecKit Entry

**Input**: Design documents from `docs/spec/consistency-runtime/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), checklists/requirements.md

**Tests**: This is a docs-only feature. Verification is `cargo xtask verify --fast`; runtime, integration, coverage, and Docker-backed tests are intentionally out of scope.

**Organization**: Tasks are grouped by user story to enable independent review of the documentation slices.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3, US4)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the explicit SpecKit feature directory and command pointer.

- [ ] T001 Create `docs/spec/consistency-runtime/` and `docs/spec/consistency-runtime/checklists/`
- [ ] T002 Update `.specify/feature.json` to point at `docs/spec/consistency-runtime`
- [ ] T003 [P] Confirm `specs/consistency-runtime/**` resolves through the existing `specs -> docs/spec` symlink

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Replace SpecKit template placeholders with concrete docs-only content before user-story-specific sections are reviewed.

**Critical**: No user story phase is complete until all generated files contain no template placeholder text and no unresolved clarification markers.

- [ ] T004 Populate SpecKit metadata headers in `docs/spec/consistency-runtime/spec.md`
- [ ] T005 Populate SpecKit metadata headers in `docs/spec/consistency-runtime/plan.md`
- [ ] T006 Create quality checklist in `docs/spec/consistency-runtime/checklists/requirements.md`
- [ ] T007 Record docs-only artifact scope in `docs/spec/consistency-runtime/plan.md`

**Checkpoint**: The feature directory is ready for story-level documentation review.

---

## Phase 3: User Story 1 - 一致性目标有单一阅读入口 (Priority: P1) MVP

**Goal**: A reader can understand RSS consistency runtime goals and acceptance criteria from the feature entry.

**Independent Test**: Read `spec.md`, `plan.md`, and `tasks.md`; each named mechanism from #1614 has a level, boundary, and acceptance path.

### Implementation for User Story 1

- [ ] T008 [US1] Document L0-L4 user story, edge cases, requirements, and success criteria in `docs/spec/consistency-runtime/spec.md`
- [ ] T009 [P] [US1] Link architecture, eventbus, saga, reconcile, tenancy, and observability rule sources from `docs/spec/consistency-runtime/plan.md`
- [ ] T010 [US1] Add mechanism coverage checks for L0-L4, outbox, inbox, saga, projection, reconcile, and tenant-aware consistency in `docs/spec/consistency-runtime/checklists/requirements.md`

**Checkpoint**: User Story 1 is independently reviewable as the docs MVP.

---

## Phase 4: User Story 2 - 分层和运行时归属不倒置 (Priority: P1)

**Goal**: The entry prevents layer ownership confusion for future runtime implementation.

**Independent Test**: For each mechanism, the plan maps ownership to existing crate layers and rule carriers without changing code.

### Implementation for User Story 2

- [ ] T011 [US2] Add layer ownership acceptance scenarios in `docs/spec/consistency-runtime/spec.md`
- [ ] T012 [P] [US2] Add Constitution Check results for layering, contract-only communication, and docs-only scope in `docs/spec/consistency-runtime/plan.md`
- [ ] T013 [US2] Add mechanism boundary map for `consistency`, `eventexec`, `diport`, `adapters`, `bootstrap`, domains, contracts, and generated code in `docs/spec/consistency-runtime/plan.md`

**Checkpoint**: Future implementation tasks have a clear layer map.

---

## Phase 5: User Story 3 - Tenant-aware failure modes 可审计 (Priority: P1)

**Goal**: Security-relevant consistency failure modes are visible and tied to Hard/Medium carriers or explicit future acceptance.

**Independent Test**: The feature entry names partition key scope, tenant authority, DLX payload boundaries, consumer leaseLost, and reconcile fencing without relying on Soft-only rules.

### Implementation for User Story 3

- [ ] T014 [US3] Document tenant-aware acceptance scenarios and edge cases in `docs/spec/consistency-runtime/spec.md`
- [ ] T015 [P] [US3] Add AI-HARD carrier summary for tenant authority, partition ordering, DLX, lease CAS, projection witness, and fencing in `docs/spec/consistency-runtime/plan.md`
- [ ] T016 [US3] Ensure tasks and checklist do not claim tenant hardening is complete beyond existing rule sources in `docs/spec/consistency-runtime/tasks.md`

**Checkpoint**: Security reviewer can audit the planning entry without consulting historical spreadsheets.

---

## Phase 6: User Story 4 - 后续任务可从 SpecKit 入口派生 (Priority: P2)

**Goal**: The task list itself is SpecKit-formatted, dependency ordered, and safe for follow-up PBI/PR generation.

**Independent Test**: Every task row starts with `- [ ] T###`, has `[USx]` in user-story phases, and contains an exact file path.

### Implementation for User Story 4

- [ ] T017 [US4] Generate the dependency-ordered task list in `docs/spec/consistency-runtime/tasks.md`
- [ ] T018 [US4] Add dependency and parallel execution sections to `docs/spec/consistency-runtime/tasks.md`
- [ ] T019 [US4] Add implementation strategy and docs-only verification instructions to `docs/spec/consistency-runtime/tasks.md`

**Checkpoint**: Follow-up planning can consume `tasks.md` without additional interpretation.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Verify the generated docs and avoid governance regressions.

- [ ] T020 Scan `docs/spec/consistency-runtime/` for template placeholders and unresolved clarification markers
- [ ] T021 Run `cargo xtask verify --fast` for `.specify/feature.json` and `docs/spec/consistency-runtime/`
- [ ] T022 Confirm the final diff includes only `.specify/feature.json` and `docs/spec/consistency-runtime/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies
- **Foundational (Phase 2)**: Depends on Setup completion
- **US1 / US2 / US3**: Depend on Foundational completion; can be reviewed in parallel because they touch separate sections
- **US4**: Depends on US1-US3 content because tasks summarize the completed documentation slices
- **Polish**: Depends on all documentation phases

### User Story Dependencies

- **User Story 1 (P1)**: Starts after Foundational
- **User Story 2 (P1)**: Starts after Foundational
- **User Story 3 (P1)**: Starts after Foundational
- **User Story 4 (P2)**: Starts after US1-US3 content is drafted

### Parallel Opportunities

- T003 can run in parallel with T001-T002.
- T009 and T010 can run in parallel with T008.
- T012 can run in parallel with T011.
- T015 can run in parallel with T014.
- T017-T019 are serial because they all write `docs/spec/consistency-runtime/tasks.md`.

---

## Parallel Example: User Story 2

```text
Task: "Add Constitution Check results for layering, contract-only communication, and docs-only scope in docs/spec/consistency-runtime/plan.md"
Task: "Add layer ownership acceptance scenarios in docs/spec/consistency-runtime/spec.md"
```

---

## Implementation Strategy

### MVP First

1. Complete Phase 1 and Phase 2.
2. Complete User Story 1.
3. Validate that the feature entry covers all named mechanisms from #1614.

### Incremental Delivery

1. Add layer ownership through User Story 2.
2. Add tenant-aware safety coverage through User Story 3.
3. Generate the final SpecKit task list through User Story 4.
4. Run `cargo xtask verify --fast`.

### Docs-Only Guardrail

Keep the PR limited to `docs/spec/consistency-runtime/**` and `.specify/feature.json`. Any runtime implementation belongs in a separate issue/PR generated from this entry.
