# Data Model: Tenancy / ABAC / Data Permission Closeout

## TenantId

- Owner: `crates/vocab`
- Shape: canonical UUID newtype.
- Invariant: empty, nil, and non-canonical UUIDs are rejected.
- Consumers: `runctx::AppCtx`, service/repo APIs, `adapters/postgres::cotx`.

## RequestCtx / PrincipalFacet

- Owner: `crates/runctx` with concrete principal implementation in `crates/authn`.
- Shape: sealed immutable authorization snapshot.
- Invariant: only authenticated channel construction; missing ctx is deny.

## Postgres Tenant Scope

- Owner: `adapters/postgres::cotx`.
- Shape: `set_local_tenant`, `tenant_scoped_read`, `producer_tx`.
- Invariant: production GUC writes only via cotx; startup verifies non-bypass role, RLS, policy, and GUC round-trip.

## PartitionKey

- Owner: `crates/consistency` and `crates/diport` emitter wrappers.
- Shape: opaque nonempty ordered-delivery key.
- Target invariant: tenant-scoped constructor or explicit globally unique witness.
- Risk: unscoped key can couple tenants in head-of-partition gating.

## RowVisibility

- Owner: `crates/vocab`, issued by `crates/authn`.
- Shape: sealed obligation for `self`, `device`, `tenant`, or audited cross-tenant.
- Invariant: ordinary constructor cannot mint all-scope; audited constructor requires durable audit success.

## Permission / Policy / Decision

- Owner: `crates/vocab` and `crates/identity`.
- Shape: sealed permission values; policy rule/effect/operator; allow/deny decision.
- Target invariant: route gate does coarse allow/deny; RowScope/FieldMask obligations are consumed by data access/projection layers.

## ResourceProjection / FieldMask

- Owner: `crates/vocab` or domain-specific read model module, finalized by PR8.
- Shape: sealed view of fields allowed to render.
- Invariant: sensitive fields default masked; no opt-out by missing obligation.
