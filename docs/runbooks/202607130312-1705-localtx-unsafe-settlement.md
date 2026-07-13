# LocalTx Unsafe Settlement Runbook

ref: prometheus/prometheus documentation/content/docs/practices/alerting.md@main
ref: open-telemetry/opentelemetry-collector docs/observability.md@main

This runbook handles contract-attributed `LocalTxCommitUnknown` / `LocalTxRollbackFailed` and
boundary-attributed `GenericTxCommitUnknown` / `GenericTxRollbackFailed`. All four represent an
unsafe database settlement that requires a human to verify authoritative state. They are not
retry-budget alerts and must not trigger automatic replay.

Contract-attributed alert scope is limited to the closed labels `domain`, `contract_id`, and
`boundary`. For generic UoW, the generic WARN routing fields are exactly `boundary` and
`final_status`; both values come from the same closed settlement routing used by
`tx_settlement_final_total`. The generic runner is the only generic unsafe-settlement WARN emitter;
HTTP LocalTx keeps its contract-attributed WARN path and does not emit the generic WARN. Tenant,
business key, SQL, payload, and error text are intentionally absent. Obtain any record-level context
from access-controlled tracing or audit storage; never add it to metric labels, WARN routing fields,
or alert annotations.

## First response

1. Acknowledge the alert and record its available closed scope (`domain` / `contract_id` / `boundary`
   for LocalTx, or `boundary` for generic UoW), first-seen time, and deployment identity.
2. Stop automated replay for that contract path or internal boundary. Do not retry the mutation and do not issue manual
   commit, rollback, or corrective SQL.
3. Find the matching WARN event by the available alert scope and time window. For a generic alert,
   match both its closed `boundary` and the alert's `final_status` filter to the identical WARN fields.
   Confirm its settlement; do not infer settlement from `retry_status` or from an exhausted retry loop.
4. Check database availability, failover, connection resets, saturation, and recent deployment
   changes. Preserve traces and database diagnostics before restarting components.
5. Use the owning domain's read path or approved audit tooling to inspect authoritative state. Keep
   tenant and business identifiers in that controlled system, not in Prometheus.

## Commit unknown

`final_status="commit_unknown"` means the commit acknowledgement was not observed. The write may or
may not be durable.

1. Keep the mutation fenced from replay; a blind retry can duplicate a committed effect.
2. Inspect the authoritative row/version and any transaction/audit evidence using the contract's
   normal ownership boundary.
3. If the intended state is already durable, close the incident without replay and verify dependent
   reads remain consistent.
4. If the intended state is absent, reconcile only through an approved idempotent domain operation
   after the database is healthy. The password-change CAS path has no generic replay command; do not
   invent one with direct SQL.
5. Escalate to the owning domain when state cannot be proven. Preserve the ambiguous operation as an
   incident artifact rather than guessing its outcome.

## Rollback failed

`final_status="rollback_failed"` means rollback was requested but its successful completion was not
observed. The transaction and underlying connection are unsafe for reuse.

1. Do not retry on the same transaction or connection. Confirm the pool/driver discarded the failed
   connection and inspect database/session health.
2. Verify authoritative state through the owning domain read path; do not assume rollback completed.
3. Reconcile through an approved domain operation only after the database is healthy and the actual
   state is known. Never repair the row with direct SQL.
4. If rollback failures repeat across connections, treat the database or network path as degraded
   and stop the affected write path until the infrastructure cause is removed.

## Retry exhaustion is diagnostic only

Retry exhaustion is intentionally not a page in `docs/ops/localtx-alerts.rules.yaml`. A transient
sequence can exhaust while the last observed settlement is safely `rolled_back`; paging it separately
would duplicate database availability/error-rate alerts and obscure the unsafe settlement signal.
Use these dashboard panels for diagnosis:

- failed attempt rate by `domain`, `contract_id`, `boundary`, and `retry_class`;
- final settlement rate by `domain`, `contract_id`, `boundary`, and `final_status`;
- P95 attempts by `domain`, `contract_id`, `boundary`, and `final_status`.

Correlate sustained transient/exhausted WARN evidence with database availability and request error
rate. Promote it to a deployment-specific warning only when a measured SLO supplies a stable
threshold and the alert has a distinct operator action.

## Resolution

Resolve only after authoritative state is known, unsafe automatic replay remains disabled or has
been deliberately restored, and the database cause is understood. Record the chosen reconciliation
operation and its audit evidence. Confirm no new `commit_unknown` or `rollback_failed` samples appear
for the affected scope during the observation window.
