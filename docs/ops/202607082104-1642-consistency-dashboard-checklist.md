# Consistency Dashboard Checklist

ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main
ref: oxidecomputer/steno src/saga_action_generic.rs@main
ref: mdeloof/statig statig/src/lib.rs@main

本清单定义 #1642 的 shared server dashboard 面板组合。表中 panel 只消费当前长驻 runtime 通过
`/health/v1/metrics` 暴露的 metric；缺失的 inbox backlog 明确标为 `not currently exported` 并跟踪
#1683。#2010 已把 active Projection worker 的低基数 runtime metric 接到 scrape；shadow 的
activation label / emitter 由 sealed bind 支持，但只有将来 assembly 真正 `bind_shadow` 后才会出现
shadow series。本清单不因此新增 shadow lifecycle、dashboard panel、alert 或 SLO。

Dashboard 不是 enforcement carrier。metric 名、label 闭值集、PII 边界和 tenant scope 以
`docs/rules/observability.md`、`docs/rules/eventbus.md`、对应 Rust newtype / enum / constructor funnel
和 alert rule 文件为准。

## Global Rules

- Metrics endpoint: `/health/v1/metrics` on the Health listener.
- Prometheus scrape must set `metrics_path: /health/v1/metrics`.
- Health listener is anonymous NoAuth and must stay loopback / cluster-internal only.
- Allowed label values are the documented closed sets. Do not add dashboard variables from free-form
  input.
- Interpret `phase` per metric: relay tick uses `claim|publish`; same-ID expiry uses
  `automatic|redrive`. Do not merge both metrics into one phase selector.
- Forbidden label sources: payload, error text, partition key, topic when not already a metric
  label, subject, actor, request input, handler error, event id, dead-letter id, saga id, step name,
  device id, command id, raw broker metadata, lease token, deadline/timestamp,
  secret or URL credential.

## Panels

| Panel | Query | Labels shown | Existing alert / action |
|---|---|---|---|
| Outbox oldest pending age | `max by (domain) (outbox_oldest_pending_age_seconds)` | `domain` | `OutboxBacklogOldestAgeHigh`; check relay / broker / DB |
| Outbox pending depth | `sum by (domain) (outbox_pending_depth)` | `domain` | `OutboxPendingDepthHigh`; check throughput and relay batch |
| Outbox partition blocked | `sum by (domain, contract_id, tenant_id) (outbox_partition_blocked_depth)` | `domain`, `contract_id`, `tenant_id` | `OutboxPartitionBlocked`; inspect DLX head, no partition key in metric |
| DLX archive pending | `dead_letter_archive_pending_depth` | none | 与 oldest age 一起看；NaN/缺失不是 0 |
| DLX archive oldest pending | `dead_letter_archive_oldest_pending_age_seconds` | none | `DlxArchiveOldestPendingHigh`；查 `dlx_lifecycle` / `dlx_archive_ready` 与独立依赖 |
| DLX lifecycle outcome | `sum by (outcome) (increase(retention_sweep_ticks_total{target="dead_letter"}[5m]))` | `outcome` | `DlxArchiveLifecycleFailure`；transient/invariant 均已停止 purge |
| Certificate revocation retention outcome | `sum by (outcome) (increase(retention_sweep_ticks_total{target="certificate_revocations"}[5m]))` | `outcome` | `CertificateRevocationRetentionFailure`；查 sweeper readyz / PG maintenance capability |
| Certificate revocation expired backlog | `retention_expired_backlog_depth{target="certificate_revocations"}` | `target`（闭值） | 与 oldest age 一起看；NaN/缺失不是 0 |
| Certificate revocation expired oldest age | `retention_expired_oldest_age_seconds{target="certificate_revocations"}` | `target`（闭值） | `CertificateRevocationRetentionBacklogHigh`；年龄从固定 5min grace 结束后起算 |
| Outbox publish disposition | `sum by (domain, status) (rate(outbox_publish_total[5m]))` | `domain`, `status` | Requeue storm / reject path diagnosis |
| Outbox DLX rate | `sum by (domain) (rate(outbox_dlx_total[5m]))` | `domain` | `OutboxDlxGrowth`; identify tenant before tenant-scoped DLQ CLI |
| Outbox same-ID window expiry | `sum by (domain, phase) ((increase(outbox_same_id_window_expired_total[10m]) > 0) or ((outbox_same_id_window_expired_total > 0) unless (outbox_same_id_window_expired_total offset 10m)))` | `domain`, `phase` (`automatic`/`redrive`) | `OutboxSameIdWindowExpired`; filtering zero increase prevents it from masking the `unless offset` first-series arm; broker publish was skipped, inspect DLX and maintenance audit |
| Outbox settlement failures | `sum by (domain, operation, reason) (rate(outbox_relay_settlement_failure_total[5m]))` | `domain`, `operation`, `reason` | `OutboxSettlementExpired` / `OutboxSettlementIntegrityFailure` / `OutboxSettlementFailureRateHigh`; expired/payload_protection/invariant are critical, timeout/lost_lease/storage identify pool, lock, transaction or ownership pressure |
| Relay tick P95 | `histogram_quantile(0.95, sum by (phase, le) (rate(outbox_relay_tick_duration_seconds_bucket[5m])))` | `phase` | `OutboxRelayTickSlow`; split claim vs publish pressure |
| Consumer settle outcome | `sum by (domain, action, outcome) (rate(consumer_settle_total[5m]))` | `domain`, `action`, `outcome` | Broker settle failures and reject/requeue mix |
| Consumer DLX write | `sum by (domain, outcome) (increase(consumer_dlx_write_total[5m]))` | `domain`, `outcome` | `ConsumerDlxWriteError`; DLX audit write failed |
| Consumer release failed | `sum by (domain) (increase(consumer_release_failed_total[5m]))` | `domain` | `ConsumerReleaseFailed`; claim release failed after DLX failure |
| Consumer lease lost | `sum by (domain) (rate(consumer_lease_lost_total[5m]))` | `domain` | `ConsumerLeaseLostHigh`; check handler duration and lease TTL |
| Saga DLX | `sum by (domain, contract_id, outcome) (increase(saga_dead_letters_total[10m]))` | `domain`, `contract_id`, `outcome` | `SagaDeadLetterGrowth` / `SagaDeadLetterWriteError` |
| LocalTx failed attempt rate | `sum by (domain, contract_id, boundary, retry_class) (rate(localtx_retry_attempts_total[5m]))` | `domain`, `contract_id`, `boundary`, `retry_class` | Diagnostic only; correlate sustained transient failures with DB health and request error rate |
| LocalTx deadline exhaustion rate | `sum by (domain, contract_id, boundary, stage) (rate(localtx_deadline_exceeded_total[5m]))` | `domain`, `contract_id`, `boundary`, `stage` (`acquire`/`begin`/`setup`/`operation`/`backoff`/`commit`/`rollback`) | Diagnostic only; no paging. Correlate the closed stage with DB latency, pool pressure, retry backoff and request errors; do not infer settlement or replay |
| LocalTx final settlement rate | `sum by (domain, contract_id, boundary, final_status) (rate(localtx_final_total[5m]))` | `domain`, `contract_id`, `boundary`, `final_status` | `LocalTxCommitUnknown` / `LocalTxRollbackFailed`; do not infer settlement from retry status |
| LocalTx attempts P95 | `histogram_quantile(0.95, sum by (domain, contract_id, boundary, final_status, le) (rate(localtx_attempts_bucket[5m])))` | `domain`, `contract_id`, `boundary`, `final_status` | Retry-pressure diagnosis; exhaustion alone does not page |
| PostgreSQL LocalTx connection quarantine | `sum by (stage) (increase(postgres_localtx_connection_quarantine_total[5m]))` | `stage` (`begin`/`body`/`commit`/`rollback`) | `PostgresLocalTxConnectionQuarantineBurst`; correlate sustained cancellation/timeout pressure with pool churn without inferring settlement |
| Generic/plain producer final settlement rate | `sum by (boundary, final_status) (rate(tx_settlement_final_total[5m]))` | `boundary`, `final_status` | `GenericTxCommitUnknown` / `GenericTxRollbackFailed`; the signal intentionally has no HTTP contract identity |

## Explicit Gaps

| Gap | Current status | Follow-up |
|---|---|---|
| Inbox backlog depth / age | `consistency::InboxBacklog` and Postgres sampling exist, but runtime Prometheus export is not currently wired. | #1683 |
| Projection replay duration | #2010 exports long-lived active worker lag, checkpoint freshness, apply failure, Projection DLQ backlog and throughput on the `bind_active` scrape path. Shadow series remain dormant until an assembly binds shadow. The one-shot replay CLI intentionally does not emit worker metrics or a duration family. | N/A；不在 #2010 范围内 |

Do not synthesize these gaps with ad hoc SQL dashboard panels in this PR. If a deployment needs inbox
backlog before #1683 or replay duration, treat the panel as deployment-local and keep it out of the
shared ops contract.

## Shared Dashboard Omissions

| Signal | Existing carrier | Shared dashboard status |
|---|---|---|
| DLQ redrive outcome | `dlq_redrive_total{tenant_id,kind,outcome}` is an operator mutation counter. A one-shot `rss dlq` process does not provide a stable Prometheus scrape target; long-term evidence is `dlq.maintenance` audit/log plus relay/consumer metrics. | Omitted from the shared `/health/v1/metrics` dashboard. A deployment-local recorder panel may exist outside this contract. |
| Reconcile results | `reconcile_total{result}` is emitted by the `eventexec` reconcile worker library when an owning runtime wires that worker with a recorder. | Omitted until the server/runtime assembly exposes a reconcile worker metric on its Health listener. |

## Drilldown Links

- Runbook index: `docs/runbooks/202607082104-1642-consistency-ops-runbook-index.md`
- Outbox / inbox redrive: `docs/ops/202607081909-1440-outbox-inbox-redrive-runbook.md`
- Projection replay / swap: `docs/runbooks/202607080828-1638-projection-replay-shadow-swap.md`
- Outbox / consumer / saga alert rules: `docs/ops/outbox-relay-alerts.rules.yaml`
- Cross-domain transport alert rules: `docs/ops/transport-dispatch-alerts.rules.yaml`
- LocalTx unsafe settlement rules: `docs/ops/localtx-alerts.rules.yaml`
- LocalTx unsafe settlement response: `docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md`

## AI-HARD Check

- No new Soft-only rule is introduced here.
- Label allowlists are references to existing closed enum / newtype / constructor carriers.
- Tenant-scoped redrive remains enforced by the existing DLQ operator capability, tenant parameter,
  service-token replay nonce and audit path.
- The remaining inbox metric carrier is tracked by #1683; Projection worker metric identity and
  labels come from the sealed #2010 Rust scope rather than this checklist.
- The LocalTx deadline panel consumes the typed `LocalTxObservation` metric and closed stage only;
  it does not create a paging rule or a parallel PostgreSQL deadline metric contract.
- Operator-local and journey/library-only metrics are explicitly omitted from the shared server
  dashboard until their runtime scrape surface exists.
