# Implementation Plan: Tenancy / ABAC / Data Permission Closeout

**Branch**: `005-tenancy-abac-dataperm-closeout` | **Date**: 2026-06-28 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `docs/spec/005-tenancy-abac-dataperm-closeout/spec.md`

## Summary

Close the remaining production gaps in the RSS multi-tenant security model by finishing the runtime tenant isolation gate first, then global table tenant scope, RowScope audited visibility, contract-derived ABAC wiring, sealed FieldMask projections, and governance closeout.

The implementation mirrors the proven GoCell #1337 sequencing but adapts enforcement to Rust: prefer types/crate graph/codegen for Hard boundaries, use xtask/dylint/startup probes for database and cross-crate Medium boundaries, and avoid Soft-only rules.

## Technical Context

**Language/Version**: Rust workspace pinned by `rust-toolchain.toml`

**Primary Dependencies**: `tokio`, `sqlx`, `axum`/`tower`, `serde`, workspace crates (`vocab`, `runctx`, `authn`, `identity`, `httpserve`, `consistency`, `diport`, `eventexec`, `audit`, `adapters/postgres`, `xtask`)

**Storage**: PostgreSQL via `adapters/postgres`; in-memory adapters only for tests/demos where already supported.

**Testing**: `cargo test`, `cargo nextest`, adapter integration tests, `cargo xtask verify`, focused xtask/dylint red/green selftests.

**Target Platform**: RSS server/runtime on durable PostgreSQL topology.

**Project Type**: Rust library workspace + runtime assembly.

**Performance Goals**: AuthZ/PDP route gate remains in-process; RLS capability verification runs at startup only; outbox partition enforcement should not regress existing relay throughput materially.

**Constraints**: No Soft-only security enforcement; no request-body tenant source; no handler-local role strings; all generated/active routes fail-closed on missing AuthZ mode; no cross-domain crate dependency violations.

**Scale/Scope**: Cross-cutting security closeout spanning auth, http, data, eventing, observability, and tooling. PRs must stay scoped to PBI-sized increments.

## Constitution Check

- Domain-native boundaries: pass. Changes stay within existing crate ownership and contract/codegen seams.
- AI-robust governance: pass with caveat. Each new invariant must have Hard or Medium enforcement; Soft-only tasks are disallowed.
- Rust workspace discipline: pass. Use existing crates and adapters; no new crate unless a PBI explicitly proves ownership need.
- Security/zero-trust default: pass. Tenant/body/header/PDP/RLS behavior is fail-closed.

## Project Structure

### Documentation

```text
docs/spec/005-tenancy-abac-dataperm-closeout/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── tasks.md
```

### Source Code

```text
crates/vocab/
crates/runctx/
crates/authn/
crates/identity/
crates/httpserve/
crates/consistency/
crates/diport/
crates/eventexec/
crates/audit/
crates/testkit/
adapters/postgres/
xtask/
docs/rules/
docs/architecture/
```

**Structure Decision**: No new workspace layer. This is a closeout feature over established tenancy/AuthZ/RLS seams.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Cross-cutting feature over multiple crates | Tenant/AuthZ/data permissions are runtime security boundaries spanning auth, HTTP, data, eventing, and tooling | Splitting into unrelated features would lose the dependency order and allow partial tenant safety to appear complete |

## Tracking

- Feature work item: #1576
- Child PBI work items: #1577, #1579, #1580, #1581, #1582, #1583, #1584, #1585, #1586
- Feature wave comment: posted on #1576 with marker `pm:feature-wave`

## PR / PBI Slicing

| PR | PBI | PBI title | Priority | Cx | Main area | Goal |
|----|-----|-----------|----------|----|-----------|------|
| PR1 | #1577 | service-token binds tenant header（历史 PBI 标题；机制已由 #1997 改为标准 JWS signed `tenant_id` + challenger equality） | P1 | Cx3 | area-auth | Make internal tenant assertion cryptographically bound before wider header use（现行目标见 #1997 / ADR-007/#017） |
| PR2 | #1579 | rss_app dual-pool bootstrap serving role | P1 | Cx3 | area-data | Route durable serving pool through non-bypass role and readyz role probe |
| PR3 | #1580 | raw-pool and TxManager bypass guard | P1 | Cx2 | area-data | Prevent tenant-scoped code from borrowing raw connections without cotx funnel |
| PR4 | #1581 | outbox tenant-aware ordering boundary | P1 | Cx4 | area-eventing | Remove or type-close cross-tenant partition liveness coupling |
| PR5 | #1582 | tenant repo conformance enrollment | P2 | Cx3 | area-data | Enroll real repos into tenant isolation conformance harness |
| PR6 | #1583 | audited RowScopeAll runtime wiring | P2 | Cx4 | area-auth | Issue cross-tenant visibility only through durable audit success |
| PR7 | #1584 | contract-derived ABAC route hardening | P2 | Cx3 | area-auth | Remove handler-local authorization branches and route modeless gaps |
| PR8 | #1585 | sealed FieldMask / ResourceProjection application | P3 | Cx3 | area-observability | Mask sensitive read fields by default through sealed projection |
| PR9 | #1586 | governance closeout and reverse self-check | P3 | Cx2 | area-tooling | Update docs, ADR refs, xtask verify, and anti-vacuity checks |

## Dependency Strategy

- Critical path: PR1 -> PR2 -> PR3 -> PR4 -> PR6 -> PR7 -> PR8 -> PR9.
- PR5 can start after PR2/PR3 because it consumes stable tenant DB semantics.
- PR7 can start after PR1 and existing PDP model work, but final route closeout should wait for PR6 if route handlers consume RowScope obligations.
- PR9 waits for all implementation PBIs.

## Validation Strategy

- Each PR includes tests or governance selftests that fail without its implementation.
- Database/security PRs include both positive and negative tests.
- Final PR updates `docs/rules/tenancy.md` to remove stale follow-up statements and adds a reverse checklist.
