# Research: Tenancy / ABAC / Data Permission Closeout

## Decision 1: Keep tenant isolation separate from ABAC

**Decision**: Tenant isolation remains typed repo/service parameter + PG RLS. ABAC is an additional route/resource decision layer and cannot be the sole tenant boundary.

**Rationale**: GoCell #1337 explicitly separates L1 tenant boundary from L2 ABAC and L3 row scope. RSS already encodes this in `TenantId`、`RowScope`、`pg_tenant_tx_guard` 与 PostgreSQL RLS/ACL.

**Alternatives considered**:

- Model tenant as an ABAC rule only. Rejected because policy/store failures could widen data access.
- Keep only RLS. Rejected because application-level API signatures would still permit missing tenant call sites until runtime.

## Decision 2: Harden runtime serving role before expanding data permissions

**Decision**: Finish `rss_app` dual-pool/bootstrap serving role and raw-pool bypass protection before RowScope/FieldMask expansion.

**Rationale**: `FORCE RLS` is ineffective against superuser/BYPASSRLS. Startup capability gates exist, but production serving wiring must use non-bypass credentials.

## Decision 3: Outbox tenant scope is part of multi-tenancy

**Decision**: Treat outbox partition tenant scope as part of this feature, not an eventing-only optimization.

**Rationale**: Ordered delivery by `(domain, partition_key)` can create cross-tenant liveness coupling. This is tenant isolation even when no row payload leaks.

## Decision 4: Cross-tenant visibility requires durable audit

**Decision**: `RowScope::All` remains unavailable through ordinary row visibility. Cross-tenant reads require an audited sealed capability issued only after durable audit append succeeds.

**Rationale**: Super-admin access is a high-risk exception. Tracing/span fields are not tamper-evident and cannot satisfy the audit requirement.

## Decision 5: Contract-derived AuthZ is the route gate source

**Decision**: Active routes must declare permission or explicit opt-out. Owner/self scoped behavior comes from contract metadata, not handler-local logic.

**Rationale**: Handler role checks drift and are hard to audit. Contract/codegen funnels are stronger and match RSS architecture constraints.

## Decision 6: FieldMask is a sealed projection concern

**Decision**: Column-level masking belongs in sealed projection/resource view types, not ad hoc serde/handler conditionals.

**Rationale**: Field visibility is not row visibility. A sealed projection creates a single consumer path for PDP masking obligations.

## Decision 7: Define open-source AuthZ parity as safety-objective equivalence

**Decision**: RSS documents OPA, Cedar, SpiceDB/OpenFGA, Casbin, and PostgreSQL RLS as comparison targets, while keeping the runtime boundary in RSS typed / in-process mechanisms. The boundary source is
`docs/architecture/202607021958-014-authz-open-source-parity-boundary.md`.

**Rationale**: GoCell #1337 and RSS both avoid a separate OPA/SpiceDB/OpenFGA process for this slice. A parity matrix is still needed so reviewers can see which security objectives are carried by `RouteAuthorizer`, `diport::Pdp`, typed tenant/RLS gates, audited RowScope, and sealed `ResourceProjection`, and which capabilities remain separate tracked gaps.

**Alternatives considered**:

- Adopt a third-party PDP runtime now. Rejected because #1587 is a boundary/documentation PBI and ADR-006 keeps the external PDP switch behind explicit trigger criteria.
- Treat ABAC as the tenant data boundary. Rejected because tenant isolation remains typed tenant + RLS + serving-role governance, and policy failures must not widen row visibility.
- Treat RLS as route authorization. Rejected because route permission/resource decisions remain the responsibility of `RouteAuthorizer`.
