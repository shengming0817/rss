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
`tx_settlement_final_total`. The shared private settlement router is the only generic
unsafe-settlement WARN emitter: bounded generic retries reach it through `run_pg_tx_retry`, while
non-retrying outbox producers must consume their move-only `ProducerTxAttempt` through
`into_result` with `boundary="outbox.producer"`. HTTP LocalTx keeps its contract-attributed WARN
path and does not emit the generic WARN. Tenant, business key, SQL, payload, and error text are
intentionally absent. Obtain any record-level context from access-controlled tracing or audit
storage; never add it to metric labels, WARN routing fields, or alert annotations.

## Static proof preflight

The [LocalTx static proof report](../ops/localtx-proof-report.md) inventories the contract-attributed
routes, probes, journeys, metrics, alerts, and this runbook. Generate the machine-readable form with
`cargo xtask localtx report --format json`, check the command exit code, fully parse the document, and
parse `status` before using it. A policy failure is represented by `status = "failed"` even though the
command exits successfully; structural failures exit non-zero with empty stdout. Current CI does not
generate or upload this static report. If an operator retains or transfers one, publish only a complete
parsed report by an atomic rename, because a stdout writer failure can leave a truncated redirected file.

The report has `evidenceScope = "staticInventory"`: it does not execute `promtool`, a real backend, or
the alert. It does not replace #1776 required real-backend evidence and cannot prove the outcome of the
incident being handled. Use it only to confirm the expected static operator carriers and ownership;
authoritative state and runtime evidence remain mandatory below.
Its operations block is `referenceOnly` with `includedInReportStatus = false`: report `status` excludes
operations validation, promtool, real-backend execution, and CI artifact/job state.

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
   after the database is healthy. Since #1842, password-change is an OutboxFact producer transaction,
   not an HTTP LocalTx route; its generic `outbox.producer` commit-unknown path still has no replay
   command. Do not invent one with direct SQL or relabel it as LocalTx evidence.
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
This retry-pressure signal is diagnostic-only; it does not change the meaning of
`LocalTxCommitUnknown` or `LocalTxRollbackFailed` and must not trigger replay.
Use these dashboard panels for diagnosis:

- failed attempt rate by `domain`, `contract_id`, `boundary`, and `retry_class`;
- deadline exhaustion rate by `domain`, `contract_id`, `boundary`, and closed `stage`;
- final settlement rate by `domain`, `contract_id`, `boundary`, and `final_status`;
- P95 attempts by `domain`, `contract_id`, `boundary`, and `final_status`.

Correlate sustained transient/exhausted WARN evidence with database availability and request error
rate. Promote it to a deployment-specific warning only when a measured SLO supplies a stable
threshold and the alert has a distinct operator action.

## Deadline exhaustion is diagnostic only

`localtx_deadline_exceeded_total{domain,contract_id,boundary,stage}` is the only shared LocalTx
deadline dashboard signal. Its `stage` is closed to `acquire`, `begin`, `setup`, `operation`,
`backoff`, `commit`, or `rollback`; tenant, SQL, business key, error text, duration, payload, and raw
deadline never become labels. The metric has no paging rule in `docs/ops/localtx-alerts.rules.yaml`.

Use `acquire` for pool pressure, `begin` / `setup` for transaction-start and GUC installation,
`operation` for the mutation body, and `backoff` for a shared budget that ended before another
attempt. For `commit` / `rollback`, correlate `localtx_final_total` and connection quarantine, then
verify authoritative state before any reconciliation. A deadline stage is timing evidence, not
settlement evidence: it must not trigger replay or be converted into `rolled_back`,
`rollback_failed`, or `commit_unknown` without the corresponding typed settlement result.

This diagnostic remains on the shared dashboard even when retry pressure is otherwise low. Escalate
through existing database availability, pool saturation, request error-rate, or unsafe-settlement
alerts only when their own conditions are met; do not add a deployment-independent deadline page.

## Connection quarantine

`PostgresLocalTxConnectionQuarantineBurst` means armed LocalTx leases have continuously discarded pooled
PostgreSQL connections for at least 15 minutes. Its only label is the closed lifecycle `stage`:
`begin`, `body`, `commit`, or `rollback`. It is a connection-lifecycle warning, not settlement
evidence; cancellation and panic can legitimately produce no `localtx_final_total` sample.

1. Correlate the stage with request cancellation/timeout rates, database latency or failover, pool
   saturation, and the matching `localtx connection quarantined` WARN events.
2. Confirm replacement connections are being established and the affected pool is not exhausting
   its acquire budget. Do not re-enable or reuse an old backend to reduce churn.
3. For `commit` or `rollback`, inspect authoritative domain state before any reconciliation. The
   quarantine signal alone cannot prove whether the server accepted the settlement command.
4. Do not add tenant, SQL, key, payload, or raw error labels. Use access-controlled traces and audit
   storage for record-level investigation.
5. Resolve after quarantine stops, pool capacity recovers, and any ambiguous authoritative state is
   handled through the owning domain operation without blind replay.

## Resolution

Resolve only after authoritative state is known, unsafe automatic replay remains disabled or has
been deliberately restored, and the database cause is understood. Record the chosen reconciliation
operation and its audit evidence. Confirm no new `commit_unknown` or `rollback_failed` samples appear
for the affected scope during the observation window.
