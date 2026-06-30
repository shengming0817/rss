# Feature Specification: Tenancy / ABAC / Data Permission Closeout

**Feature Branch**: `005-tenancy-abac-dataperm-closeout`

**Created**: 2026-06-28

**Status**: Draft

**Input**: User description: "分析 gocell #1337 多租户实施过程，使用 speckit 进行任务拆解，登记 feature issue 和子 PBI，分析最大并行度并进行 feature 评论。"

## User Scenarios & Testing

### User Story 1 - Tenant Runtime Isolation Gate (Priority: P1)

Platform runtime can run tenant-scoped HTTP/service/repo paths on a non-bypass Postgres serving role, with tenant scope injected only through the typed transaction funnel and verified at startup/readiness.

**Why this priority**: This is the minimum production safety gate for multi-tenancy. ABAC and data masking cannot compensate for a broken tenant boundary.

**Independent Test**: Durable startup fails on superuser/BYPASSRLS or missing RLS policy; with `rss_app` serving role, tenant A can read/write its own rows and cannot see/write tenant B rows.

**Acceptance Scenarios**:

1. **Given** a tenant-scoped table and a non-bypass serving connection, **When** no `SET LOCAL rss.tenant_id` is injected, **Then** reads return zero rows and writes are rejected.
2. **Given** durable bootstrap, **When** RLS capability verification fails, **Then** startup fails and readyz reports unhealthy.
3. **Given** service/repo code, **When** it needs tenant scope, **Then** it receives `TenantId` through typed parameters rather than `String` or request body values.

---

### User Story 2 - Global Event Tables Tenant Scope (Priority: P1)

Outbox and event routing cannot create cross-tenant liveness coupling or unscoped payload access.

**Why this priority**: Outbox ordering must not depend on caller discipline around key uniqueness; tenant scope belongs in the persisted boundary that enforces partition gating.

**Independent Test**: Two tenants using the same aggregate key cannot block each other in outbox partition ordering; all tenant-scoped emit paths either persist tenant scope or use a typed tenant-aware partition key.

**Acceptance Scenarios**:

1. **Given** tenant A and tenant B events with the same business key, **When** tenant A's event is dead-lettered, **Then** tenant B's later events are not blocked by the same `(domain, partition_key)`.
2. **Given** an emitter call site, **When** it requests ordered delivery, **Then** the outbox row persists the typed tenant scope and gates ordering by tenant as well as domain and partition key.

---

### User Story 3 - RowScope And Cross-Tenant Audit (Priority: P2)

User/device/admin data visibility is derived through sealed `RowVisibility`, and cross-tenant super-admin visibility is available only through audited capability issuance.

**Why this priority**: This turns row-level data permission into a typed obligation instead of handler-local filters.

**Independent Test**: Normal user/device/admin queries receive self/device/tenant visibility, while super-admin all-scope is denied unless the audited issuance funnel writes durable audit first.

**Acceptance Scenarios**:

1. **Given** a normal user, **When** row visibility is derived, **Then** it is self-scoped and includes the subject.
2. **Given** a device principal, **When** row visibility is derived, **Then** it is device-scoped and includes the device subject.
3. **Given** a super-admin principal, **When** durable audit append fails, **Then** cross-tenant visibility is not issued.

---

### User Story 4 - Contract-Derived ABAC Wiring (Priority: P2)

HTTP/gRPC route authorization uses contract-derived permission/resource/self-scoped metadata and the primary PDP/Authorizer path. Handler-local role checks and permission strings are eliminated from production routes.

**Why this priority**: Tenant isolation must be followed by consistent authorization; route gates cannot drift from contracts.

**Independent Test**: A generated or registered route without an AuthZ mode is rejected; owner/self scoped routes call the PDP with canonical resource/subject context; handler-local role checks are caught by governance tests.

**Acceptance Scenarios**:

1. **Given** an active HTTP contract, **When** it lacks permission or explicit opt-out, **Then** codegen/governance rejects it.
2. **Given** an owner-scoped route, **When** path resource parsing fails, **Then** authorization denies without falling back to coarse route allow.
3. **Given** production handler code, **When** it hand-checks `Principal.roles`, **Then** governance fails.

---

### User Story 5 - FieldMask / Projection Data Protection (Priority: P3)

Read endpoints consume PDP obligations through sealed projection/resource views so sensitive fields default to masked unless explicitly allowed.

**Why this priority**: Column-level data permission is separate from tenant and row scope; it completes user/device-level data protection.

**Independent Test**: Sensitive fields in audit/query responses are masked by default; unmasked projections require explicit sealed field access.

**Acceptance Scenarios**:

1. **Given** a PDP decision with no field obligation, **When** a read endpoint renders a resource, **Then** sensitive fields are masked.
2. **Given** a sealed projection allowing a field, **When** the response is rendered, **Then** only that field is unmasked.

---

### User Story 6 - Governance Closeout (Priority: P3)

The feature is complete only when documentation, ADR links, xtask/governance checks, and reverse self-checks describe and enforce the final tenant/ABAC/data-permission model.

**Why this priority**: The project is AI-operated; undocumented or Soft-only security rules will drift.

**Independent Test**: `cargo xtask verify` includes tenancy/codegen/RLS/AuthZ checks, and docs reference the final implementation without stale follow-up statements.

**Acceptance Scenarios**:

1. **Given** the feature is implemented, **When** `cargo xtask verify` runs, **Then** all tenancy/AuthZ/RLS governance checks pass.
2. **Given** a reviewer reads `docs/rules/tenancy.md`, **When** they follow the implementation references, **Then** no completed item remains described as follow-up.

## Edge Cases

- Internal `X-Tenant-ID` without service-token MAC must not be treated as cryptographically authentic.
- Superuser and BYPASSRLS roles must fail startup capability gates.
- `RowScope::All` must not be constructible through ordinary row visibility.
- Outbox partition keys may contain credential-like identifiers and must remain redacted in `Debug`.
- Public/bootstrap/service-owned routes must use explicit opt-out reasons, not missing AuthZ metadata.

## Requirements

### Functional Requirements

- **FR-001**: Tenant scope MUST come only from JWT tenant claim or authenticated/internal header path; request body `tenantId` MUST be rejected.
- **FR-002**: Repo/service and Postgres tenant scope APIs MUST use typed `TenantId`, never bare `String`.
- **FR-003**: Durable startup MUST fail when tenant tables lack FORCE RLS, tenant isolation policy, GUC round-trip, or non-bypass serving role.
- **FR-004**: Production Postgres serving paths MUST use non-superuser/NOBYPASSRLS role wiring.
- **FR-005**: Direct raw pool/connection bypass of tenant-scoped transaction helpers MUST be caught by governance or startup fail-fast.
- **FR-006**: Outbox ordered delivery MUST persist tenant scope and gate ordered partitions by `(tenant_id, domain, partition_key)`.
- **FR-007**: `RowVisibility` MUST be sealed and prevent ordinary construction of cross-tenant all-scope.
- **FR-008**: Cross-tenant super-admin visibility MUST be issued only after durable audit append succeeds.
- **FR-009**: Route authorization MUST be contract-derived and must reject missing AuthZ mode for active generated routes.
- **FR-010**: Handler-local role-name authorization branches MUST be removed or guarded fail-closed by governance.
- **FR-011**: Field-level projection MUST mask sensitive fields by default and unmask only through sealed projection access.
- **FR-012**: The feature MUST include focused conformance tests and reverse self-checks for tenant, RLS, RowScope, ABAC, and projection behavior.

### Key Entities

- **TenantId**: Canonical UUID boundary value for tenant isolation.
- **RequestCtx**: Sealed runtime authorization context carrying tenant and principal facets.
- **RowVisibility**: Sealed row-level data visibility obligation.
- **CrossTenantVisibility**: Audited capability for super-admin cross-tenant reads.
- **PartitionKey**: Outbox ordering key scoped by persisted outbox `tenant_id`; the key may remain a business aggregate key without cross-tenant liveness coupling.
- **Permission / Policy / Decision**: ABAC route authorization inputs and outcomes.
- **ResourceProjection / FieldMask**: Column-level projection and masking boundary.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Cross-tenant tenant-table read/write leakage is blocked by both typed parameters and RLS tests.
- **SC-002**: Missing tenant scope results in zero rows or write rejection, not fallback to anonymous/default tenant.
- **SC-003**: Durable startup fails for superuser/BYPASSRLS serving roles.
- **SC-004**: Outbox ordered delivery cannot couple two tenants via the same unscoped partition key.
- **SC-005**: user/device/admin/super-admin row visibility scenarios have independent tests.
- **SC-006**: Active HTTP/gRPC routes have exactly one AuthZ mode or explicit opt-out.
- **SC-007**: Sensitive read projections are masked by default.
- **SC-008**: `cargo xtask verify` passes with the added governance checks.

## Assumptions

- Existing RSS architecture rules in `CLAUDE.md` and `docs/rules/` remain authoritative.
- Azure Boards is the active forge; Feature/PBI tracking uses `hack/automation/forge.sh`.
- This feature is a closeout/hardening feature over existing work, not a from-zero rewrite.
