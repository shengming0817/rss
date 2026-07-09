# Feature Specification: L0/L1 Consistency Hardening SpecKit Baseline

**Feature Branch**: `docs/1708-l0-l1-spec-baseline`

**Created**: 2026-07-08

**Status**: Draft

**Tracking**: Epic #1685, docs-only PBI #1708

**Input**: User request to create a docs-only SpecKit baseline for the L0/L1 consistency hardening DAG, closing only C-00 and leaving #1686..#1707 for later implementation PRs.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Repo has a single SpecKit source for #1685 (Priority: P1)

As an implementer or reviewer, I can open `docs/spec/006-l0-l1-consistency-hardening/` and see the scope, issue map, dependencies, verification rules, and follow-up ship order for epic #1685 without relying on local downloads or historical chat context.

**Why this priority**: The L0 and L1 packages were generated separately, while the real delivery plan now uses one epic with common carrier PBIs and two implementation tracks. A repo-local SpecKit source prevents drift between the issue tracker, downloaded planning files, and future `/ship` work.

**Independent Test**: Read `spec.md`, `plan.md`, `tasks.md`, `quickstart.md`, and `checklists/requirements.md`; confirm they identify C-00 #1708 as docs-only, list #1686..#1707 as follow-up PBIs, and state that this PR does not modify runtime, codegen, interface, migration, generated, or `docs/rules/**` rule bodies.

**Acceptance Scenarios**:

1. **Given** a reviewer opens the feature directory, **When** they inspect the documents, **Then** the epic, C-00 PBI, and implementation PBIs are all visible with real issue numbers.
2. **Given** a future implementer starts `/ship #1686`, **When** they consult this feature, **Then** they can see that #1686 is the first shared carrier and not a L0-only or L1-only task.
3. **Given** this docs-only PR is reviewed, **When** the diff is checked, **Then** only `.specify/feature.json` and `docs/spec/006-l0-l1-consistency-hardening/**` changed.

---

### User Story 2 - Shared carriers unblock L0 and L1 without artificial serialization (Priority: P1)

As a planning maintainer, I need the common PBIs to be explicit so L0 and L1 implementation can branch in parallel after their shared generated metadata and evidence carriers exist.

**Why this priority**: L0 effect proof and L1 LocalTx validation both depend on generated consistency metadata and evidence schema work. Treating the tracks as simple copy-paste or fully serialized work would hide the real coupling and reduce safe parallelism.

**Independent Test**: `plan.md` and `tasks.md` show #1686 -> #1687 -> #1688 as the shared carrier chain, then list L0 and L1 PBIs in natural DAG stages without applying a wave-size cap.

**Acceptance Scenarios**:

1. **Given** #1688 is complete, **When** work is assigned, **Then** L0 #1689/#1690/#1691/#1692 and L1 #1697/#1698 can start in parallel if their file ownership is kept scoped.
2. **Given** #1697 and #1698 are complete, **When** L1 implementation continues, **Then** settings, identity, Postgres runner, and observability work can advance according to their own dependencies.
3. **Given** #1693 is not complete, **When** L0 conformance or reporting is considered, **Then** only the PBIs that depend on the forbidden side-effect guard wait.

---

### User Story 3 - L0 LocalOnly track is effect-proven (Priority: P1)

As a reviewer of LocalOnly routes, I need the L0 follow-up PBIs to mature LocalOnly from contract declaration to machine-checkable handler effect proof.

**Why this priority**: `LocalOnly` currently exists as contract metadata, but strict L0 requires proof that handlers do not carry write, transaction, outbox, publish, workflow, saga, reconcile, worker, or cross-tenant audit side effects.

**Independent Test**: The L0 PBIs in `tasks.md` cover generated consistency/effect carriers, route metadata binding, port classification, ambiguous `audit.list-entries` correction, local-only lint, forbidden side-effect guard, conformance, report output, and breaking review.

**Acceptance Scenarios**:

1. **Given** a LocalOnly HTTP contract, **When** codegen and the L0 gates run after implementation PBIs land, **Then** the route has runtime-visible consistency and an effect profile.
2. **Given** a LocalOnly route captures a forbidden side-effect port, **When** the L0 guard runs, **Then** it fails with the contract id and forbidden effect.
3. **Given** `audit.list-entries` mixes scoped read and cross-tenant audited write behavior, **When** #1692 is implemented, **Then** the strict L0 path is separated or the audited path is explicitly non-L0.

---

### User Story 4 - L1 LocalTx track is executable and verifiable (Priority: P1)

As a domain developer or operator, I need the L1 follow-up PBIs to prove LocalTx semantics through contract evidence, route coverage, adapter behavior, conformance, metrics, and journeys.

**Why this priority**: RSS has active L1 contracts and transaction primitives, but the validation chain is not yet unavoidable across generated metadata, route binding, rollback/concurrency tests, and operational evidence.

**Independent Test**: The L1 PBIs in `tasks.md` cover LocalTx coverage, boundary vocabulary, Postgres runner closure, settings and identity tests, conformance suites, adapter matrices, metrics/traces, journeys, and final verify integration.

**Acceptance Scenarios**:

1. **Given** an active `LocalTx` contract, **When** L1 gates run after implementation PBIs land, **Then** generated metadata, route binding, evidence, and test coverage are all checked.
2. **Given** a LocalTx write fails validation or authorization, **When** its conformance test runs, **Then** rollback/no-write behavior is proven.
3. **Given** a LocalTx commit has an unknown outcome, **When** metrics and retry classification are inspected, **Then** the status is visible and not retried as a normal transient failure.

---

### User Story 5 - Follow-up ship work can be scheduled from the DAG (Priority: P2)

As the person driving delivery, I can start each implementation PR from its PBI and know which work is blocked, which work is parallel, and which PBI is reserved for final closeout.

**Why this priority**: The implementation spans generated metadata, xtask gates, runtime route binding, adapters, testkit, docs, and journeys. A maximum-parallel DAG is needed to keep work moving without conflating this docs-only PR with runtime changes.

**Independent Test**: `quickstart.md` gives the C-00 PR validation flow and the follow-up `/ship` order; `tasks.md` includes a maximum natural parallelism table and states that C-04 #1707 is only for final implementation closeout.

**Acceptance Scenarios**:

1. **Given** this baseline PR merges, **When** work resumes, **Then** `/ship --level=L2 #1686` is the first implementation PR.
2. **Given** any PBI is selected out of order, **When** its dependencies are checked, **Then** the blocking issue numbers are available in `tasks.md`.
3. **Given** #1707 is considered, **When** any earlier implementation PBI is still open, **Then** #1707 remains blocked.

## Edge Cases

- `.specify/feature.json` becomes the default feature pointer. Older SpecKit work must use a separate branch or worktree if it needs another feature pointer, because the SpecKit helper can persist `SPECIFY_FEATURE_DIRECTORY` back into `.specify/feature.json`.
- Generated code may create large future diffs, but this baseline PR does not regenerate or commit generated files.
- The L0 and L1 packages use different original feature directories; this repo baseline intentionally consolidates them under one issue DAG.
- `#1707 C-04` is not a substitute for this baseline PR. It is the final closeout after implementation PBIs land.
- Existing rule documents remain rule sources. This feature references them and does not alter `docs/rules/**` bodies.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide `docs/spec/006-l0-l1-consistency-hardening/` with `spec.md`, `plan.md`, `tasks.md`, `quickstart.md`, and `checklists/requirements.md`.
- **FR-002**: System MUST update `.specify/feature.json` to point at `docs/spec/006-l0-l1-consistency-hardening`.
- **FR-003**: `tasks.md` MUST list C-00 #1708 and follow-up PBIs #1686..#1707 using real issue numbers.
- **FR-004**: `tasks.md` MUST describe natural DAG maximum parallelism and MUST NOT apply a wave-size cap.
- **FR-005**: The baseline PR MUST close only #1708 and MUST NOT close #1686..#1707.
- **FR-006**: The baseline MUST keep #1707 C-04 as final implementation docs/verify closeout after earlier PBIs are done.
- **FR-007**: The baseline MUST identify #1686, #1687, and #1688 as shared carriers that unblock both L0 and L1.
- **FR-008**: The baseline MUST distinguish L0 effect-proof work from L1 LocalTx validation work.
- **FR-009**: The baseline MUST keep the diff limited to `.specify/feature.json` and `docs/spec/006-l0-l1-consistency-hardening/**`.
- **FR-010**: The baseline MUST NOT modify Rust code, contract schemas, generated files, migrations, or `docs/rules/**` rule bodies.
- **FR-011**: The baseline MUST include verification instructions for the placeholder scan and `cargo xtask verify --fast`.
- **FR-012**: The baseline MUST preserve external source attribution to the L0 and L1 SpecKit packages without copying their optional schema artifacts into this PR.

### Key Entities

- **Epic #1685**: Parent work item for L0/L1 consistency hardening.
- **C-00 #1708**: Docs-only baseline PBI closed by this PR.
- **Shared Carrier PBIs**: #1686, #1687, and #1688; common generated metadata and evidence foundations.
- **L0 Track PBIs**: #1689..#1696; effect-proven LocalOnly work.
- **L1 Track PBIs**: #1697..#1706; executable LocalTx validation work.
- **C-04 #1707**: Final implementation docs/verify closeout after L0 and L1 tracks land.
- **Natural DAG Stage**: A dependency level that can run in parallel once all previous blockers are complete.
- **SpecKit Baseline**: The repo-local documents that future `/ship` work uses as planning truth.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The new feature directory contains all five required documents.
- **SC-002**: `.specify/feature.json` resolves to `docs/spec/006-l0-l1-consistency-hardening`.
- **SC-003**: A scan for unresolved template markers returns no matches in the new feature directory and `.specify/feature.json`.
- **SC-004**: `cargo xtask verify --fast` is attempted from the docs worktree and the result is recorded in the PR.
- **SC-005**: The final PR diff contains only `.specify/feature.json` and files under `docs/spec/006-l0-l1-consistency-hardening/`.
- **SC-006**: `tasks.md` gives each follow-up PBI a dependency set and a maximum-parallel DAG stage.
- **SC-007**: The PR body includes `本 PR 无需对标：docs-only SpecKit baseline，未改 runtime/codegen/interface`.
- **SC-008**: No implementation PBI #1686..#1707 is closed by this PR.

## Assumptions

- This PR is intentionally docs-only and does not implement any runtime, codegen, interface, migration, generated, or rule-body change.
- The existing issue tracker entries #1685..#1708 are the authoritative work item numbers.
- The imported L0 and L1 SpecKit packages are planning inputs whose relevant content has been folded into this directory; no local download path is an execution dependency.
- If an older SpecKit feature still needs to run, callers will isolate the pointer change in a branch or worktree and explicitly restore `.specify/feature.json` before leaving that context.
