# Consistency Dashboard Checklist

ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main
ref: oxidecomputer/steno src/saga_action_generic.rs@main
ref: mdeloof/statig statig/src/lib.rs@main

本清单定义 #1642 的 shared server dashboard 面板组合。表中 panel 只消费当前长驻 runtime 通过
`/health/v1/metrics` 暴露的 metric；缺失的 inbox backlog 和 projection runtime metric 明确标为
`not currently exported`，分别跟踪 #1683 / #1684。

Dashboard 不是 enforcement carrier。metric 名、label 闭值集、PII 边界和 tenant scope 以
`docs/rules/observability.md`、`docs/rules/eventbus.md`、对应 Rust newtype / enum / constructor funnel
和 alert rule 文件为准。

## Global Rules

- Metrics endpoint: `/health/v1/metrics` on the Health listener.
- Prometheus scrape must set `metrics_path: /health/v1/metrics`.
- Health listener is anonymous NoAuth and must stay loopback / cluster-internal only.
- Allowed label values are the documented closed sets. Do not add dashboard variables from free-form
  input.
- Forbidden label sources: payload, error text, partition key, topic when not already a metric
  label, subject, actor, request input, handler error, event id, dead-letter id, saga id, step name,
  device id, command id, ack id, dispatch key, raw broker metadata, token, secret or URL credential.

## Panels

| Panel | Query | Labels shown | Existing alert / action |
|---|---|---|---|
| Outbox oldest pending age | `max by (domain) (outbox_oldest_pending_age_seconds)` | `domain` | `OutboxBacklogOldestAgeHigh`; check relay / broker / DB |
| Outbox pending depth | `sum by (domain) (outbox_pending_depth)` | `domain` | `OutboxPendingDepthHigh`; check throughput and relay batch |
| Outbox partition blocked | `sum by (domain, contract_id, tenant_id) (outbox_partition_blocked_depth)` | `domain`, `contract_id`, `tenant_id` | `OutboxPartitionBlocked`; inspect DLX head, no partition key in metric |
| Outbox publish disposition | `sum by (domain, status) (rate(outbox_publish_total[5m]))` | `domain`, `status` | Requeue storm / reject path diagnosis |
| Outbox DLX rate | `sum by (domain) (rate(outbox_dlx_total[5m]))` | `domain` | `OutboxDlxGrowth`; identify tenant before tenant-scoped DLQ CLI |
| Relay tick P95 | `histogram_quantile(0.95, sum by (phase, le) (rate(outbox_relay_tick_duration_seconds_bucket[5m])))` | `phase` | `OutboxRelayTickSlow`; split poll vs publish pressure |
| Consumer settle outcome | `sum by (domain, action, outcome) (rate(consumer_settle_total[5m]))` | `domain`, `action`, `outcome` | Broker settle failures and reject/requeue mix |
| Consumer DLX write | `sum by (domain, outcome) (increase(consumer_dlx_write_total[5m]))` | `domain`, `outcome` | `ConsumerDlxWriteError`; DLX audit write failed |
| Consumer release failed | `sum by (domain) (increase(consumer_release_failed_total[5m]))` | `domain` | `ConsumerReleaseFailed`; claim release failed after DLX failure |
| Consumer lease lost | `sum by (domain) (rate(consumer_lease_lost_total[5m]))` | `domain` | `ConsumerLeaseLostHigh`; check handler duration and lease TTL |
| Saga DLX | `sum by (domain, contract_id, outcome) (increase(saga_dead_letters_total[10m]))` | `domain`, `contract_id`, `outcome` | `SagaDeadLetterGrowth` / `SagaDeadLetterWriteError` |

## Explicit Gaps

| Gap | Current status | Follow-up |
|---|---|---|
| Inbox backlog depth / age | `consistency::InboxBacklog` and Postgres sampling exist, but runtime Prometheus export is not currently wired. | #1683 |
| Projection replay lag / duration | Projection CLI prints status / stop fields, but runtime Prometheus metrics are not currently exported. | #1684 |

Do not synthesize these gaps with ad hoc SQL dashboard panels in this PR. If a deployment needs them
before #1683 / #1684, treat the panel as deployment-local and keep it out of the shared ops contract.

## Shared Dashboard Omissions

| Signal | Existing carrier | Shared dashboard status |
|---|---|---|
| DLQ redrive outcome | `dlq_redrive_total{tenant_id,kind,outcome}` is an operator mutation counter. A one-shot `rss dlq` process does not provide a stable Prometheus scrape target; long-term evidence is `dlq.maintenance` audit/log plus relay/consumer metrics. | Omitted from the shared `/health/v1/metrics` dashboard. A deployment-local recorder panel may exist outside this contract. |
| Reconcile results | `reconcile_total{result}` is emitted by the `eventexec` reconcile worker library when an owning runtime wires that worker with a recorder. | Omitted until the server/runtime assembly exposes a reconcile worker metric on its Health listener. |
| Device command convergence | `device_command_convergence_lag_seconds{result}` is emitted by the `deviceloop` L4 journey carrier. | Omitted until an owning runtime or probe exposes the journey metric as a stable server scrape target. |

## Drilldown Links

- Runbook index: `docs/runbooks/202607082104-1642-consistency-ops-runbook-index.md`
- Outbox / inbox redrive: `docs/ops/202607081909-1440-outbox-inbox-redrive-runbook.md`
- Projection replay / swap: `docs/runbooks/202607080828-1638-projection-replay-shadow-swap.md`
- Outbox / consumer / saga alert rules: `docs/ops/outbox-relay-alerts.rules.yaml`
- Cross-domain transport alert rules: `docs/ops/transport-dispatch-alerts.rules.yaml`

## AI-HARD Check

- No new Soft-only rule is introduced here.
- Label allowlists are references to existing closed enum / newtype / constructor carriers.
- Tenant-scoped redrive remains enforced by the existing DLQ operator capability, tenant parameter,
  service-token replay nonce and audit path.
- Missing metric carriers are tracked by #1683 and #1684 instead of being documented as if they
  already existed.
- Operator-local and journey/library-only metrics are explicitly omitted from the shared server
  dashboard until their runtime scrape surface exists.
