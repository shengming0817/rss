# Consistency Ops Runbook Index

ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main
ref: oxidecomputer/steno src/saga_action_generic.rs@main
ref: mdeloof/statig statig/src/lib.rs@main

本索引是 #1642 的一致性运维入口。它不新增治理机制；所有 label 闭值集、PII 边界、tenant scope 与
redrive 权限均引用已有 Hard / Medium carrier。若某模块尚无 runtime metric，本页明确标为
`not currently exported`，并引用后续 backlog issue；#1683 inbox backlog 已不属于该集合。

## Coverage Matrix

| Module | Runbook | Metric | Alert | Dashboard | Redrive | Carrier |
|---|---|---|---|---|---|---|
| Outbox relay / backlog | `docs/ops/202607081909-1440-outbox-inbox-redrive-runbook.md` | exported | `docs/ops/outbox-relay-alerts.rules.yaml` | `docs/ops/202607082104-1642-consistency-dashboard-checklist.md` | tenant-scoped `rss dlq redrive-outbox` | `OutboxMetricScope`, `RelayConfig`, `OutboxContractId`, `TenantId`, closed settlement operation/reason; see `docs/rules/observability.md` |
| Inbox / consumer | `docs/ops/202607081909-1440-outbox-inbox-redrive-runbook.md` | consumer metrics plus inbox stale-claim depth/oldest-age exported; active-owner failure semantics use NaN (#1683) | existing consumer rules only; no inbox backlog alert | same checklist; no shared inbox backlog panel authorized | tenant-scoped `rss dlq replay-dead-letter` | generated `InboxBacklogSelection`, private `InboxMetricScope`, `TenantId`, typed maintenance lane; see `docs/rules/observability.md` |
| DLX lifecycle | this index | archive pending depth/oldest age + closed lifecycle outcome exported | `DlxArchiveLifecycleFailure`, `DlxArchiveOldestPendingHigh` | same checklist | no cold list/inspect/replay; expired receipt only via verified HEAD-missing proof | typed receipt/proof, dedicated PG/Vault/S3 credentials, verified WORM store; see `docs/rules/eventbus.md` / `observability.md` |
| Saga | this index | saga DLX exported | `docs/ops/outbox-relay-alerts.rules.yaml` | same checklist | no replay; diagnostic DLX only | `SagaInstanceRef`, `SagaExecutorConfig` domain / contract binding, `saga_dead_letters_total` label closure |
| LocalTx / generic UoW / plain producer settlement | `docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md` | `localtx_retry_attempts_total`, `localtx_deadline_exceeded_total`, `localtx_final_total`, `localtx_attempts`, `postgres_localtx_connection_quarantine_total`, `tx_settlement_final_total` | unsafe settlement only: `docs/ops/localtx-alerts.rules.yaml`; deadline diagnostic has no page | same checklist | no automatic replay for unsafe settlement or deadline exhaustion | `observ::LocalTxObservation` for HTTP contracts; Postgres generic runner and move-only plain producer attempt for boundary-only settlement; closed boundary/retry/deadline-stage/final-status/quarantine-stage enums; see `docs/rules/observability.md` |
| LocalOnly proof / receipt coverage | `docs/runbooks/202607141556-1771-local-only-proof.md` | schema v4 fail-closed source registry; no runtime metric | none | not applicable | not applicable | generated active LocalOnly registry + opaque success receipt (Hard upstream), xtask provenance/exact-set scan (Medium downstream); see `docs/rules/consistency-l0.md` |
| Projection | `docs/runbooks/202607080828-1638-projection-replay-shadow-swap.md` | exported (#2010)：active worker lag、checkpoint freshness、apply failure、Projection DLQ backlog、processed throughput（production bind_active）；shadow label/emitter 由 sealed bind 支持，但仅当将来 assembly 真正 `bind_shadow` 后才会出现 scrape series；CLI replay 不发 worker metric | none for projection runtime metric | none（无 dashboard/alert/SLO） | no replay to outbox; projection DLX is diagnostic | `ProjectionMetricScope`（active\|shadow bind）、`ProjectionSelector`, `ProjectionVersion`, serial witness, projection DLX store |
| Reconcile | this index | library emit site exists; server runtime scrape not currently wired | no dedicated rule file yet | omitted from shared checklist until runtime wired | not applicable | `ReconcileResultLabel`, `Builder::new(Tenancy, Trigger, ...)`, durable attempt result tables |
| DeviceLatent command convergence | `docs/ops/202608021949-1905-device-latent-inspection.md` | closed JSON/Prometheus inspection with one token-bound tenant, identifier-free numeric observation families, and closed lease churn emit sites; no production dashboard claim | none | omitted; #1905 does not add dashboard hosting | no generic mutation/replay; certificate recovery remains #1972 | typed condition/status read receipt, `DeviceLatentMetric`, closed lease operation/state/reason, generation/fence evidence |

## Outbox Relay / Backlog

Primary runbook: `docs/ops/202607081909-1440-outbox-inbox-redrive-runbook.md`.

Operational signals:

- `outbox_oldest_pending_age_seconds{domain,contract_id,tenant_id}`
- `outbox_pending_depth{domain,contract_id,tenant_id}`
- `outbox_partition_blocked_depth{domain,contract_id,tenant_id}`
- `outbox_publish_total{domain,contract_id,tenant_id,status}`
- `outbox_dlx_total{domain,contract_id,tenant_id}`
- `outbox_relay_tick_duration_seconds{phase}`
- `outbox_relay_settlement_failure_total{domain,contract_id,tenant_id,operation,reason}`

On-call flow:

1. If `OutboxBacklogOldestAgeHigh` or `OutboxPendingDepthHigh` fires, check relay and sampler readyz
   probes first; a missing backlog series is not a sampler heartbeat.
2. If `OutboxDlxGrowth` fires, the alert only carries `domain`. Use that domain and deployment
   ownership data to identify the candidate tenant / contract before running the tenant-scoped DLQ
   `list` / `inspect` commands. Do not infer `partition_key` from metrics; it is intentionally
   absent.
3. If `OutboxPartitionBlocked` fires, inspect the outbox DLX head and only run
   `rss dlq redrive-outbox` after the upstream schema / payload / tenant-envelope cause is fixed.
4. After redrive, watch `outbox_partition_blocked_depth` return to zero and confirm the matching
   publish counter moves to `status="ack"`.
5. If `OutboxSettlementExpired` fires, treat it as a correctness signal: stop dependency-only
   remediation and inspect relay scheduling delay, settle budget, connection pool and lock waits.
   If `OutboxSettlementIntegrityFailure` fires, stop relay dependency-only remediation and use
   `reason=payload_protection|invariant` to inspect the DLX key provider or settlement contract/row
   shape. If `OutboxSettlementFailureRateHigh` fires, use `reason=timeout|lost_lease|storage` and the
   dashboard operation split to distinguish resource pressure, transaction failures and lease ownership churn.

Failure handling stays in the redrive runbook. Direct SQL updates, destructive skip, cross-tenant
redrive, and metric labels derived from payload, error text, subject, actor, event id, lease token,
deadline or partition key are out of bounds.

## Inbox / Consumer

Primary runbook: `docs/ops/202607081909-1440-outbox-inbox-redrive-runbook.md`.

Operational signals:

- `consumer_settle_total{domain,action,outcome}`
- `consumer_dlx_skip_total{domain,reason}`
- `consumer_dlx_write_total{domain,outcome}`
- `consumer_release_failed_total{domain}`
- `consumer_lease_lost_total{domain}`
- `inbox_stale_claim_depth{tenant_id,consumer_group}`
- `inbox_oldest_stale_claim_age_seconds{tenant_id,consumer_group}`

Inbox backlog is emitted only by the active maintenance owner. A receipt enters the metric only when
`status='claimed'` and `claimed_at <= now() - 60s`; oldest age is the complete time since
`claimed_at`, not time beyond the 60-second stale boundary. Query failure and ownership loss write
NaN only for scopes this process has already emitted; an unseen scope legitimately has no series.
A successful active tick writes zero for previously observed scopes that disappeared. For NaN or an
unexpectedly missing known series, inspect the `inbox_sampler` readyz probe and the
`RSS_INBOX_SAMPLE_INTERVAL_MS` cadence first. Then inspect maintenance-owner acquire/renew/fencing
logs: verify the Redis lock is held by one runtime owner, the PostgreSQL CAS epoch advances in the
same lane, and lease loss retires the old owner's series before peer takeover. Finally verify the PG
reader can execute `rss_inbox_sample_backlog(text[])` and cannot read `inbox_receipts` directly.
#1683 adds no shared alert, threshold or dashboard panel.

On-call flow:

1. If `ConsumerDlxWriteError` fires, inspect dead-letter storage, Vault Transit availability, and
   the consumer worker readyz probe. DLX write failure is correctness-relevant because the audit row
   was not persisted.
2. If `ConsumerReleaseFailed` fires, treat it as higher risk than ordinary requeue noise: the worker
   could not release the claim after DLX failure and must reject the broker message.
3. If `ConsumerLeaseLostHigh` fires, check handler latency, inbox lease TTL, worker concurrency, and
   database latency. Lease lost is a hard-fence signal, not a business handler error by itself.
4. Consumer `dead_letter` replay is tenant-scoped and requires a new replay id. Do not delete the
   original dead-letter row or reset `inbox_receipts`.

Allowed labels are the closed sets documented in `docs/rules/observability.md`. Tenant, message id,
payload, handler error and raw broker metadata do not enter consumer metric labels.

## DLX Archive Lifecycle

Operational signals:

- `dead_letter_archive_pending_depth`
- `dead_letter_archive_oldest_pending_age_seconds`
- `retention_sweep_ticks_total{target="dead_letter",outcome="success|transient|invariant"}`
- `retention_sweep_deleted_total{target="dead_letter"}`
- readyz probes `dlx_lifecycle` and `dlx_archive_ready`

On-call flow:

1. `DlxArchiveLifecycleFailure` 触发后先确认 purge 已停止，不要手工删 HOT row 或 receipt。
2. 同时查看两个 readyz probe；检查独立 archiver PG role 、hot/archive Vault token/key、archive
   bucket credential、versioning、COMPLIANCE default retention 和 current/noncurrent lifecycle policy。
3. `outcome="invariant"` 表示 AAD/格式/checksum/既有对象语义冲突；保留对象和 HOT row 证据，
   不得通过改 receipt 或重写对象规避。
4. `outcome="transient"` 恢复依赖后观察后续 tick 转 success、oldest age 下降且 pending depth 归零。
5. backlog gauge 为 NaN/缺失时先恢复 sampler/PG；不得当作空 backlog。

RSS 不得 DeleteObject/list/replay cold archive。Object Lock 到期后，只有 verified archive store HEAD
确认 lifecycle 已删对象，才能产生 `MissingArchiveProof` 删 receipt；HOT row 尚在时会在下一轮
重新归档。

## Certificate Revocation Retention

Operational signals:

- `retention_sweep_ticks_total{target="certificate_revocations",outcome="success|transient|invariant"}`
- `retention_sweep_deleted_total{target="certificate_revocations"}`
- `retention_sweep_duration_seconds{target="certificate_revocations",outcome}`
- `retention_expired_backlog_depth{target="certificate_revocations"}`
- `retention_expired_oldest_age_seconds{target="certificate_revocations"}`
- readyz probe `certificate_revocation_sweeper`

On-call flow:

1. `CertificateRevocationRetentionFailure` 触发时先查 readyz、PostgreSQL 连接/锁等待、migration ledger=72，
   以及两个固定 maintenance function 的 owner/search_path/EXECUTE capability；不要给 serving role raw DELETE。
2. `CertificateRevocationRetentionBacklogHigh` 表示最老证据在固定 5 分钟 grace 结束后又滞留超过 5 分钟；
   对照 depth 和 tick duration 判断是持续写入超过每批 1000 行，还是 sweeper/DB 卡住。
3. backlog gauge 为 `NaN` 或缺失表示同 transaction aggregate sampler 不可用；该 tick 的删除已回滚，
   不得把 gauge 当 0，也不得绕过固定 function 手工清表。
4. 恢复后观察 outcome 转 `success`、oldest age 与 depth 下降。物理 retention 失败不改变
   `not_after <= authoritative database now` 的逻辑过期语义。

## Saga

Saga compensation failures use the unified dead-letter table for diagnostics. There is no saga
redrive path in v1.

Operational signals:

- `saga_dead_letters_total{domain,contract_id,outcome="written"}`
- `saga_dead_letters_total{domain,contract_id,outcome="write_error"}`

On-call flow:

1. For `outcome="written"`, inspect the saga journal and the matching dead-letter row for the
   tenant-scoped instance. The saga already reached a state that needs human intervention.
2. For `outcome="write_error"`, check dead-letter storage and Vault Transit first; the journal
   failed row is the durable fallback, but the DLX audit row is missing.
3. Do not replay saga dead letters into outbox. Fix the underlying action / compensation or data
   invariant, then resume through the saga executor path if supported by the owning workflow.

Carrier summary: saga labels come from `SagaExecutorConfig` owner / contract id and the closed
`written|write_error` outcome. Saga id, step name, tenant, payload and store error text stay out of
metric labels.

## LocalTx / Generic UoW Settlement

Primary runbook: `docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md`.

Operational signals:

- `localtx_retry_attempts_total{domain,contract_id,boundary,retry_class}`
- `localtx_deadline_exceeded_total{domain,contract_id,boundary,stage}`
- `localtx_final_total{domain,contract_id,boundary,final_status}`
- `localtx_attempts{domain,contract_id,boundary,final_status}`
- `postgres_localtx_connection_quarantine_total{stage}`
- `tx_settlement_final_total{boundary,final_status}`

The typed deadline counter is diagnostic-only and has no paging rule. Use its closed
`acquire|begin|setup|operation|backoff|commit|rollback` stage to choose pool, transaction setup,
operation, retry-budget, or settlement diagnostics; never infer settlement or replay from it.
Unsafe `commit_unknown` / `rollback_failed` remains the only LocalTx settlement paging path and
requires authoritative-state verification through the primary runbook.

## Projection

Primary runbook: `docs/runbooks/202607080828-1638-projection-replay-shadow-swap.md`.

Active worker metrics are exported (#2010): `projection_lag`、
`projection_checkpoint_freshness_seconds`、`projection_apply_failure_total`、`projection_dlq_backlog`、
`projection_processed_events_total`（低基数 `projection_id` + `activation`；无 dashboard/alert/SLO）。
Production currently wires `bind_active` only. The sealed `ProjectionMetricScope` emitter already
accepts a `shadow` activation label, but shadow series appear on `/health/v1/metrics` only after a
future assembly actually calls `bind_shadow`; this index does not add shadow lifecycle, panels,
alerts, or SLOs. CLI replay 不发 worker metric；operator 仍用 CLI 打印的 high-water 与 stop reason
做 swap 决策。

Gauge semantics（lag / freshness / DLQ）：

- `NaN` 表示本次 tenant sweep **未闭合**或任一 tenant observation **失败**；禁止把 `NaN`、缺失
  series 或 stale sample 当作 `0` / 健康。
- 低基数聚合故意 fail-closed：单 tenant 观测失败会使整次聚合变为 unknown（三 gauge 同发 `NaN`），
  不得用部分成功 tenant 冒充全集健康。
- `projection_processed_events_total` 与 `projection_apply_failure_total` 是独立 counter 路径，
  **不受** gauge `NaN` 重写或擦除。

On-call flow:

1. For replay or swap work, run `rss projections status` and record active version,
   `selected_generation_high_water_lsn`, source high-water and token.
2. Do not promote a candidate generation unless its checkpoint has caught up to source high-water.
3. Any `stop != completed` blocks swap（含正常有界的 `stop=budget_exhausted`）。Handle the stop reason from the projection runbook before
   retrying.
4. Projection DLX is diagnostic. It is not replayable into outbox through `rss dlq`.
5. 若 lag / freshness / DLQ gauge 为 `NaN` 或缺失，先恢复 worker observation / PG / drain 完整性，
   再解读 backlog；对照 processed / apply counters 判断吞吐与失败是否仍在前进。

Carrier summary: `ProjectionSelector` binds tenant, projection id and version. Projection ids and
versions enter through parsing funnels; projection event ordering is protected by the serial witness
and checkpoint CAS. Worker metrics use sealed `ProjectionMetricScope` minted only after verified
active/shadow bind; production scrape today reflects the active bind path. Label closure 见
`docs/rules/observability.md` Metrics Label 有界例外。

## Reconcile

Reconcile follows a controller model: scheduled / targeted requests drive desired-to-actual
convergence, and failed attempts are classified into the closed result label set. The metric carrier
exists in the worker library, but #1642 does not claim that the current server runtime exports it on
`/health/v1/metrics`.

Library / deployment-local signals:

- `reconcile_total{result="settled"}`
- `reconcile_total{result="requeue_after"}`
- `reconcile_total{result="transient"}`
- `reconcile_total{result="permanent"}`
- `reconcile_total{result="invariant"}`

On-call flow when the owning runtime wires this worker:

1. If `transient` rises, check dependency health and backoff behavior before changing desired state.
2. If `permanent` rises, inspect the durable attempt result and owning domain validation; repeating
   the same request without data or config correction should not help.
3. If `invariant` rises, stop automatic rollout of the owning reconciler and inspect the model/code
   mismatch.
4. If attempts stop while desired changes continue, inspect the `reconcile` readyz probe, leader
   election and target lease state.

Carrier summary: `ReconcileResultLabel` is the single metric label source. `Builder::new` requires
`Tenancy` and `Trigger` as position parameters, and durable attempt results are stored separately
from action-local `recorded` rows.
