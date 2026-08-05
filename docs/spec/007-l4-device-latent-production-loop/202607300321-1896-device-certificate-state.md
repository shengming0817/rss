# #1896 device-certificate authority persistence execution plan

This document is the implementation handoff for #1896. Requirements, ownership, logical state,
and proof assignment remain owned by `spec.md`, `data-model.md`, `tasks.md`, `traceability.md`, and
ADR-022 in this specification package; this file does not create a second requirements source.

## Four-principle gate

- **Thorough**: replace the root design errors rather than layering fixes: policy vocabulary has one
  `deviceloop` owner, desired state does not synthesize a fence from generation, server-owned values
  cannot enter mutation inputs, and all same-class digest mix-ups are closed.
- **No backward compatibility**: directly replace the unmerged identity interfaces and unpublished
  certificate schema. Keep no aliases, shims, dual readers, dual writers, or corrective compatibility
  migration.
- **Elegant and simple**: retain one domain vocabulary, one repository port, one PostgreSQL adapter,
  and three authority tables. Do not add command, receipt, operation, scheduler, handler, or runtime
  wiring.
- **AI-HARD**: every new invariant is carried by private/closed Rust types, input-field exclusion,
  PostgreSQL constraints/triggers, FORCE RLS, exact grants, or real-PostgreSQL conformance tests. No
  Soft-only rule is accepted.

## Scope and decisions

- #1896 owns desired/reported/condition storage and storage-level monotonicity only. Its tracker
  target and acceptance criteria are synchronized with the canonical owner graph: #1898 owns the
  idempotent desired-update/durable-target-wake transaction; #1897/#1903 own command and ingress
  evidence; #1900 owns current epoch validation; #1901 owns readiness/artifact evidence.
- Desired persistence contains no `fence_epoch`. Reported persistence records the positive epoch
  carried by the report but does not claim it is current.
- Full certificate policy vocabulary and canonical encoding live in `deviceloop`. Identity keeps
  only sealed tenant/device persistence inputs, semantic digest types, restored snapshots, and its
  repository port.
- Policy hash and server timestamps are database-owned. Condition mutation uses a timestamp-free
  closed condition state; PostgreSQL creates and preserves transition time.
- Report writes return closed zero-write outcomes for missing desired, stale/ahead generation,
  duplicate, same-generation conflict, and stale sequence. This repository emits no matching,
  readiness, receipt, or fencing evidence.

## Implementation DAG

1. Add failing `deviceloop`/identity tests for unique policy ownership, non-interchangeable digests,
   timestamp-free condition mutation, fence-free desired input, closed report outcomes, and dyn port
   compatibility; then directly replace the existing checkpoint implementation.
2. Add the certificate authority migration at the next free serial. It carries database-generated policy hash, full SAN and
   envelope validation, monotonic desired/reported guards, closed conditions, server timestamps,
   ENABLE+FORCE RLS, and exact reader/writer grants.
3. Implement `PgDeviceCertificateRepository` only through typed tenant reader/writer capabilities.
   Add desired CAS, reported high-water, condition upsert, and complete state load; expose an
   inactive identity-domain bundle constructor without assembly wiring.
4. Prove fresh and previous-head-to-certificate migration, CAS conflict/rollback/concurrency, all report outcomes,
   condition transitions, cross-tenant denial, unscoped fail-closed behavior, exact ACL, and serving
   migration denial against real PostgreSQL.

The domain batch precedes the PostgreSQL batch. Within the PostgreSQL batch, migration and adapter
tests are written red before implementation. A single owner edits each shared file.

## Verification and delivery

- Run targeted `deviceloop`, `identity`, and PostgreSQL nextest/check/clippy loops plus migration
  inventory, live tenant catalog/behavior proofs (`integration-critical:postgres-lib`), and
  tenant-transaction guards (`pg-tenant-tx-guard`; further contraction tracked in #1988).
- After targeted failures are resolved, run `make ci CI_BASE=origin/develop` once. If it fails,
  collect and fix the full failure set before targeted reruns and at most one final full CI run.
- Create a PR closing #1896 and explicitly record that target wake remains #1898-owned. Run the ship
  six-dimensional review, fix in-scope Cx1/Cx2 findings, batch-gate any Cx3/Cx4 decisions, publish
  the `pm:ship` artifact, and hand off to the UTC delayed monitor.

## Existing checkpoint

The worktree started from commit `dfdc3d35` and uncommitted migration/test scaffolding from the
superseded plan. History remains preserved without amend. During final conflict precheck, develop
merged saga migration `0080`; the unpublished certificate migration therefore moved atomically to
`0081`, with its upgrade proof rebaselined from 0080. No duplicate serial or compatibility alias is
retained.
