# Tasks: Tenancy / ABAC / Data Permission Closeout

**Input**: Design documents from `docs/spec/005-tenancy-abac-dataperm-closeout/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, quickstart.md

**Tests**: Security-critical tasks use TDD or red/green governance selftests.

**Organization**: Each user story maps to one or more PR-sized PBI work items. Every PBI is independently trackable in Azure Boards.

**Tracking**: Feature #1576; child PBI #1577, #1579, #1580, #1581, #1582, #1583, #1584, #1585, #1586.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the feature artifact and tracking baseline.

- [ ] T001 Record this feature scope in docs/spec/005-tenancy-abac-dataperm-closeout/spec.md
- [ ] T002 Record implementation sequencing in docs/spec/005-tenancy-abac-dataperm-closeout/plan.md
- [ ] T003 Create Azure Boards Feature work item and link child PBI work items for this task list

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Finish tenant source and durable runtime gates that block all downstream data-permission work.

**Critical**: No RowScope/ABAC/FieldMask expansion should proceed before PR1-PR4 are complete or explicitly accounted for.

- [x] T004 [US1] Implement service-token MAC binding for `X-Tenant-ID` in crates/authn and crates/httpserve
- [x] T005 [US1] Add contract/header governance tests for authenticated tenant header sources in xtask
- [ ] T006 [US1] Wire durable bootstrap to use non-superuser NOBYPASSRLS `rss_app` serving pool in adapters/postgres and runtime composition
- [ ] T007 [US1] Add readyz/current-role probe coverage for non-bypass serving role in crates/syshealth or adapters/postgres
- [x] T008 [US1] Add raw-pool/TxManager bypass guard for tenant-scoped Postgres code in adapters/postgres and xtask

---

## Phase 3: User Story 1 - Tenant Runtime Isolation Gate (Priority: P1)

**Goal**: Tenant-scoped runtime paths run through typed tenant APIs, cotx SET LOCAL funnel, RLS capability gate, and non-bypass serving role.

**Independent Test**: Durable startup rejects bypass roles; tenant A/B read-write isolation passes with `rss_app`.

- [ ] T009 [P] [US1] Add red integration tests for `rss_app` tenant A/B read/write isolation in adapters/postgres/src/integration_tests.rs
- [ ] T010 [US1] Finish serving pool bootstrap wiring for tenant-scoped repositories in adapters/postgres/src/pool.rs
- [ ] T011 [US1] Enforce startup failure on skipped RLS setup path through PgRuntimeDeps setup in adapters/postgres and runtime composition
- [ ] T012 [P] [US1] Add anti-vacuity tests for TENANCY-SETLOCAL-FUNNEL-01 in xtask/src/setlocal_funnel.rs
- [ ] T013 [US1] Update docs/rules/tenancy.md to remove stale dual-pool follow-up text after PR2 lands

---

## Phase 4: User Story 2 - Global Event Tables Tenant Scope (Priority: P1)

**Goal**: Ordered outbox delivery cannot couple tenants through unscoped partition keys.

**Independent Test**: Tenant A dead-lettered ordered event does not block tenant B ordered event with same business key.

- [ ] T014 [P] [US2] Add failing cross-tenant partition blocking test in adapters/postgres/src/integration_tests.rs
- [ ] T015 [US2] Add tenant-aware PartitionKey constructor or tenant_id outbox storage in crates/consistency and adapters/postgres, including Debug/log redaction tests for tenant-aware PartitionKey and OutboxEnvelopeParts
- [ ] T016 [US2] Update diport::OutboxEnvelopeParts to require tenant-aware ordered delivery inputs in crates/diport/src/outbox_emitter.rs
- [ ] T017 [US2] Add codegen/doc-contract drift checks for tenant-aware outbox signatures in xtask
- [ ] T018 [US2] Update docs/rules/eventbus.md and docs/rules/tenancy.md with final outbox tenant-scope invariant

---

## Phase 5: User Story 3 - RowScope And Cross-Tenant Audit (Priority: P2)

**Goal**: Row visibility is sealed and cross-tenant all-scope is only issued through durable audited capability.

**Independent Test**: super-admin all-scope issuance fails closed when audit append fails.

- [ ] T019 [P] [US3] Add RowVisibility derivation tests for user/device/admin/super-admin in crates/authn
- [ ] T020 [US3] Wire durable audit sink into audited cross-tenant visibility issuance in crates/authn and adapters/postgres
- [ ] T021 [US3] Add failure-path tests proving audit append failure denies RowScopeAll in crates/authn
- [ ] T022 [P] [US3] Add governance guard for cross-tenant visibility call sites in lints/rss_crosstenant_callsite or xtask
- [ ] T023 [US3] Update docs/rules/tenancy.md with live audited issuance references

---

## Phase 6: User Story 4 - Contract-Derived ABAC Wiring (Priority: P2)

**Goal**: Production route gates use contract-derived permissions/resources and primary Authorizer/PDP wiring.

**Independent Test**: modeless active route is rejected; owner/self route authorization sends canonical resource context to PDP.

- [ ] T024 [P] [US4] Add route modeless rejection tests in xtask contract/codegen validation
- [ ] T025 [US4] Wire primary Authorizer into HTTP route context before serving in crates/httpserve and runtime composition
- [ ] T026 [US4] Replace handler-local role/self authorization branches with contract-derived permission funnels in crates/authn and crates/httpserve
- [ ] T027 [P] [US4] Add governance search/lint for handler-local Principal role checks in xtask or dylint
- [ ] T028 [US4] Add owner/self scoped PDP resource canonicalization tests in crates/authn or crates/httpserve

---

## Phase 7: User Story 5 - FieldMask / Projection Data Protection (Priority: P3)

**Goal**: Sensitive read fields are masked by default through sealed projection/resource view types.

**Independent Test**: Missing FieldMask obligation yields masked sensitive fields.

- [ ] T029 [P] [US5] Define sealed FieldMask/ResourceProjection model in crates/vocab or the selected domain read-model module
- [ ] T030 [US5] Apply ResourceProjection to audit/query read responses in crates/audit
- [ ] T031 [US5] Add default-mask and explicit-unmask tests for sensitive fields in crates/audit
- [ ] T032 [P] [US5] Add projection obligation consumption documentation in docs/rules/tenancy.md

---

## Phase 8: User Story 6 - Governance Closeout (Priority: P3)

**Goal**: Final docs, ADR references, and verify gates describe and enforce the completed model.

**Independent Test**: `cargo xtask verify` passes and no completed tenant/ABAC/data-permission item remains documented as future work.

- [ ] T033 [P] [US6] Update docs/architecture ADR references for tenant/RLS/AuthZ/data-permission closeout
- [ ] T034 [US6] Add final reverse self-check to xtask verify for tenant/AuthZ/RLS/masking invariants
- [ ] T035 [P] [US6] Update docs/spec/005-tenancy-abac-dataperm-closeout/quickstart.md with final verification commands
- [ ] T036 [US6] Run cargo fmt, cargo xtask verify, and cargo test --workspace for the feature closeout PR

## Dependencies

```text
US1 -> US2 -> US3 -> US4 -> US5 -> US6
US1 -> US3
US1 -> US4
US2 -> US6
```

## Parallel Execution Examples

- After PR1 starts: T009 and T012 can run in parallel with T010 because they touch integration tests and xtask separately.
- After PR4 settles: T019 can start while T024/T027 prepare contract and governance red tests; final route closeout still waits for PR6 RowScope wiring.
- T024 and T027 can run in parallel during ABAC route hardening.
- T029 and T033 can run in parallel after the route model stabilizes.

## Implementation Strategy

1. MVP: complete PR1-PR4 to close tenant runtime isolation and outbox tenant ordering risk.
2. Data-permission upgrade: complete PR5-PR8 for RowScope, ABAC route wiring, and FieldMask projection.
3. Closeout: complete PR9 with documentation, ADR references, and reverse self-checks.
