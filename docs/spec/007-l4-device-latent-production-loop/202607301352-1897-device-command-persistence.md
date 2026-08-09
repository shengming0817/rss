# #1897 durable device-command persistence execution handoff

This document records the implemented handoff for #1897. Normative requirements and ownership
remain in `spec.md`, `data-model.md`, `tasks.md`, `traceability.md`, and ADR-022; this file does not
create a second requirement source.

## Four-principle gate

- **Thorough**: replace the memory-only durability gap with a PostgreSQL aggregate, restart-safe
  restore, optimistic concurrency, canonical-active uniqueness, append-once ingress evidence,
  FORCE RLS, and least-privilege proofs.
- **No backward compatibility**: command creation requires both an intent digest and a canonical
  microsecond `DeviceCommandDeadline`. No raw-time overload, default, alias, dual reader/writer,
  backfill, or compatibility migration remains.
- **Elegant and simple**: retain the existing eight-state Rust FSM and add one static store port,
  one PostgreSQL adapter, and two tables. Do not create an in-memory production repository,
  generic workflow/dedup framework, or dynamic DI wrapper.
- **AI-HARD**: opaque production scope, private newtypes, one nonnegative `DeviceSequence` owner,
  ACK-only desired coordinates, report-only `ObservedGeneration`, kind-specific evidence, closed
  mutations/errors, redacted provider sources, input-field exclusion, SQL constraints/triggers,
  partial uniqueness, FORCE RLS, and exact grants carry the invariants. Runtime conformance
  supplies evidence; prose is not enforcement.

## Ownership and implementation

- #1897 owns the durable command aggregate and immutable internal ingress evidence only. #1900
  owns stable intent authoring, current-fence reconciliation, supersession, and outbox composition.
  #1903 owns authenticated ingress UoW, public application receipt, non-oracle mapping, wake, and
  reported/condition mutation.
- `CommandIntentDigest` is an exact redacted 32-byte type embedded in every command state snapshot.
  Creation and transition requests omit server time, persisted state, and caller-selected next
  version. The provider locks/restores the aggregate, applies the canonical FSM at database time,
  and writes only an `Advanced` result under version CAS.
- Durable deadlines are canonical epoch-microsecond values before the store call; sub-microsecond
  inputs fail rather than truncate. Ingress report evidence carries `ObservedGeneration +
  FenceEpoch`, while ACK evidence alone carries a desired `FenceCoordinate`; the compiler rejects
  mixing observation with write authority.
- Provider failures are classified as transient, permanent, or settlement-unknown, and the raw
  source terminates at `RedactedSource`. Persisted row corruption has separate closed command and
  ingress reasons rather than sharing a caller-mutation error bucket.
- The store's associated scope is provider-selected; PostgreSQL binds it exactly to identity's
  opaque `DeviceCertificateScope` and executes only through typed identity read/write transaction
  capabilities. The inactive bundle accessor does not activate a contract or runtime path.
- `device_commands` enforces immutable identity/coordinate/intent/deadline, legal state/time
  matrices, exact version increments, terminal absorption, and one nonterminal command per
  tenant/device/generation/intent. `device_ingress_receipts` uses `(tenant_id,event_id)` identity,
  kind-specific fields, immutable fingerprint/disposition, and append-only ACL.

## Overall command deadline

- A command has exactly one durable overall deadline. The ordinary periodic `ReconcileWorker`
  due scan is the recovery and restart carrier; there is no command-specific sweeper, attempt
  store, probe, runtime harness, or production-profile role.
- Before making a normal certificate decision, the reconciler submits only its sealed
  attempt/lease/epoch/wake-version/desired-generation fence. In one tenant-bound write
  transaction fixed `SECURITY DEFINER` selector/settler funnels validate that fence. The selector
  locks the current-generation command and returns database transaction time; the provider restores
  the aggregate and applies the canonical Rust `DeviceCommandMutation::timeout` FSM; the settler
  revalidates the fence, selected identity, exact version advance, deadline, and authoritative time
  before persisting the snapshot. Callers cannot select a command, optimistic version, or clock
  value; `rss_app` receives EXECUTE on the fixed eligibility wrappers and retains no raw command
  UPDATE permission.
- Due `queued`, `published`, or `received` commands advance once through
  the same closed transition and lifecycle trigger used by every durable command mutation; replay
  returns the closed `AlreadyExpired` outcome without a write. The reconciler persists
  `CommandTimedOut` degraded conditions and settles, so it cannot immediately reissue a command
  for the same desired generation. A later desired-generation update may author the next command
  normally.
- RSS deliberately rejects separate ScheduleToSend and SendToComplete timers and the former
  three-tier timeout model. No alias, shim, dual path, or compatibility entry point is retained.

## Verification and delivery

- Unit and compile-fail tests prove digest round-trip, closed states/mutations/evidence, mandatory
  inputs, stable no-op classifications, and invalid restore rejection.
- Provider-neutral testkit conformance is consumed by the real PostgreSQL provider and proves
  create/replay/conflict, reload equivalence, CAS single-winner behavior, and append-once
  replay/conflict without adding workspace dependencies.
- Real PostgreSQL tests prove migration/catalog shape, RLS/ACL/default-deny, restart reload, CAS and
  canonical-active races, tenant isolation, immutable replay, and update/delete denial.
- Targeted crate tests, clippy, migration/RLS/tenant-scope guards, and the PostgreSQL integration
  shard precede the single affected `make ci CI_BASE=origin/develop` preflight. The PR closes #1897
  and records the statig, kube-rs, and SQLx primary references used by the implementation.
