# Outbox relay 可观测性：metric / label / SLO 契约

> #1209（归属 Feature #1208）。本文档是 outbox relay/sampler metric 名、label 闭值集、SLO 阈值与
> dashboard 面板的运维契约。label 闭值集纪律单源见 `docs/rules/observability.md` §Outbox Relay Metrics；
> 告警规则见 `docs/ops/outbox-relay-alerts.rules.yaml`。

## 背景

outbox relay/sweeper/consumer 此前全链仅 `tracing` 结构化日志 + readyz 三态 health，无 metrics——运维对
积压、投递延迟、DLX 速率无量化感知。#1209 经注入式 `OutboxMetrics` 端口（`crates/eventexec`，生产实现
`MetricsOutboxMetrics` 经 `metrics` facade global recorder，`adapters/prometheus` 渲染 `/metrics`）暴露最少
metric 集，并给 relay/sweeper 驱动参数加构造期 fail-fast 护栏。

## Metric 集

| metric | 类型 | label | 采集点 | 语义 |
|--------|------|-------|--------|------|
| `outbox_publish_total` | Counter | `domain`,`contract_id`,`tenant_id`,`status` | relay tick 逐条结算 | status=`ack`(已投递)/`requeue`(退避重投)/`reject`(进 DLX) |
| `outbox_dlx_total` | Counter | `domain`,`contract_id`,`tenant_id` | relay 结算 Reject 时 | 永久失败进 DLX；= `outbox_publish_total{status="reject"}` |
| `outbox_relay_envelope_validation_failure_total` | Counter | `domain`,`contract_id`,`tenant_id`,`reason` | relay 发布前本地 envelope header 校验失败 | reason 为 envelope header 闭集 |
| `outbox_pending_depth` | Gauge | `domain`,`contract_id`,`tenant_id` | backlog 采样器（默认 ≤60s/轮） | 可投递 backlog：到期 pending + stale publishing；正常 in-flight publishing 排除 |
| `outbox_oldest_pending_age_seconds` | Gauge | `domain`,`contract_id`,`tenant_id` | backlog 采样器 | `now()−min(created_at)`；**进程内已观测 scope 后续无 backlog ⇒ 0**（非缺失，防 Prometheus 把 drain 误判采样器死亡） |
| `outbox_partition_blocked_depth` | Gauge | `domain`,`contract_id`,`tenant_id` | backlog 采样器 | 同 tenant/domain/partition 前序未 published 阻塞的行数；不暴露 `partition_key` |
| `outbox_relay_tick_duration_seconds` | Histogram | `phase` | relay tick | phase=`poll`(扫描相)/`publish`(逐条中继+adapter 内 settle 相) |
| `dlq_redrive_total` | Counter | `tenant_id`,`kind`,`outcome` | `rss dlq replay-dead-letter` / `redrive-outbox` | operator mutation 结果；kind=`dead_letter_replay`/`outbox_dlx_redrive`；一次性 CLI 发射，长期告警看 audit/log |
| `consumer_dlx_skip_total` | Counter | `domain`,`reason` | consumer fail-closed preflight path | 跳过 app DLX 写入的诊断计数；reason 为 malformed id / tenant authority / envelope header / inbox receipt context 闭集 |
| `consumer_dlx_write_total` | Counter | `domain`,`outcome` | consumer app DLX store wrapper | app DLX 写入结果；outcome=`ok`/`error`，error 同时把 consumer health 标为 degraded |
| `consumer_release_failed_total` | Counter | `domain` | DLX 写失败后 release 也失败 | 正确性告警面；consumer broker `Reject`，避免 Requeue 后被 Duplicate→Ack 吞掉 |
| `consumer_lease_lost_total` | Counter | `domain` | consumer inbox lease CAS hard-fence | handler/tx/commit 期间 lease lost；取消当前执行并 broker Requeue，不写 app DLX |
| `saga_dead_letters_total` | Counter | `domain`,`contract_id`,`outcome` | saga compensation DLX path | saga 补偿失败 dead-letter 写入结果；outcome=`written`/`write_error` |

### Label 闭值集

- `status`：闭合于 `consistency::Disposition::as_label()`，值 `ack`/`requeue`/`reject`。
- `phase`：闭合于 `eventexec::RelayPhase::as_label()`，值 `poll`/`publish`。settle（CAS 落库）是 postgres
  adapter 内部、对 eventexec 不可见，故并入 `publish` 相，不单列。
- `domain`：来自 `RelayConfig` 构造期校验的 domain 集（数量 ≤64 + canonical 标识格式），operator 配置、
  非请求/租户派生，基数有界。**不**经 `observ` typed enum（层矩阵禁 `eventexec`→`observ`）；收敛进 `observ`
  词表统一 otel 映射是 #1076 后续项。
- `contract_id` / `tenant_id`：#1625 例外的 outbox 路由维度，分别来自
  `consistency::OutboxContractId` 与 `vocab::TenantId`。禁止把 payload、topic、subject、actor、metadata、
  error text、handler error 或请求输入放入 label。backlog zero sample 覆盖 adapter 本轮返回的历史 outbox
  scope，以及同一 sampler 进程内曾返回、后续成功采样时消失的 `(domain, tenant_id, contract_id)`；从未出现、
  新进程尚未观测或 recorder 已清理的 scope 不补 series。`outbox_partition_blocked_depth` 只输出 count，不输出
  `partition_key`。
- `consumer_dlx_skip_total.reason`：闭合于 `eventexec::consumer::record_dead_letter_skip` 的模块内 literal 调用点；
  禁止携带 handler error、tenant、message id 或 payload 派生值。当前闭集：
  `malformed_id` / `tenant_authority_missing` / `tenant_authority_invalid` / `tenant_authority_expired` /
  `tenant_authority_binding_mismatch` / `envelope_missing_tenant_id` / `envelope_invalid_tenant_id` /
  `envelope_missing_schema_version` / `envelope_invalid_schema_version` / `envelope_missing_schema_hash` /
  `envelope_invalid_schema_hash` / `envelope_schema_version_mismatch` / `envelope_schema_hash_mismatch` /
  `inbox_receipt_invalid_consumer_group` / `inbox_receipt_empty_domain` / `inbox_receipt_empty_topic` /
  `inbox_receipt_empty_contract_id` / `inbox_receipt_invalid_contract_version` /
  `inbox_receipt_invalid_schema_hash` / `inbox_receipt_invalid_trace` /
  `inbox_receipt_invalid_correlation_id` / `inbox_receipt_invalid_context`。
- `outbox_relay_envelope_validation_failure_total.reason`：闭合于 postgres relay 的 envelope validation reason，
  与 consumer envelope reason 同一字符串集合；该 metric 只描述本地 header gate，broker publish failure
  仍看 `outbox_publish_total` / `outbox_dlx_total`。
- `dlq_redrive_total.kind/outcome`：闭合于 `eventexec::DlqMutationKind::as_label()`、mutation outcome 与
  `DlqError::as_label()`；常见 outcome 为 `inserted` / `already_exists` / `redriven` / `not_found`，依赖或数据错误为
  `invalid_payload` / `invalid_schema_headers` / `payload_key_unavailable` / `payload_key_forbidden` / `store`。禁止把
  event id、dead_letter id、partition key 或错误文本放进 label。
- `consumer_dlx_write_total.outcome`：闭合于 `eventexec::consumer_worker` 的 DLX wrapper，值 `ok`/`error`；
  禁止携带 handler error、tenant、message id 或 payload 派生值。
- `consumer_lease_lost_total`：label 仅 `domain`；它是 lease CAS hard-fence 观测信号，不代表 handler 业务失败。
- `saga_dead_letters_total.outcome`：闭合于 `eventexec::saga` emit site 的模块内 literal，值
  `written`/`write_error`；`domain`/`contract_id` 来自 `SagaExecutorConfig`，禁止携带 saga_id、step、
  tenant、payload 或 store error 派生值。

## SLO 与告警

| 信号 | 阈值 | severity | 规则 |
|------|------|----------|------|
| 投递延迟（最老 pending 龄） | > 5min 持续 2min | critical | `OutboxBacklogOldestAgeHigh` |
| DLX 增长 | 10min 内增长 > 0 | critical | `OutboxDlxGrowth` |
| pending 深度 | > 10k 持续 5min | warning | `OutboxPendingDepthHigh` |
| partition blocked 深度 | > 0 持续 10min | critical | `OutboxPartitionBlocked` |
| 重试风暴（requeue 速率） | > 5/s 持续 5min | warning | `OutboxRequeueStorm` |
| relay tick P95 耗时 | > 5s 持续 5min | warning | `OutboxRelayTickSlow` |
| consumer DLX 写失败 | 5min 内 `outcome="error"` 增长 > 0 | critical | `ConsumerDlxWriteError` |
| consumer release 失败 | 5min 内增长 > 0 | critical | `ConsumerReleaseFailed` |
| consumer lease lost | 5min rate > 1/s 持续 5min | warning | `ConsumerLeaseLostHigh` |
| saga DLX 增长 | 10min 内 `outcome="written"` 增长 > 0 | critical | `SagaDeadLetterGrowth` |
| saga DLX 写失败 | 5min 内 `outcome="write_error"` 增长 > 0 | critical | `SagaDeadLetterWriteError` |

outbox 告警在 PromQL 层按 domain 聚合：depth 用 `sum by (domain)`，oldest age 用 `max by (domain)`，
DLX/requeue 用 `sum by (domain)`，tick 用 `by (phase)`。scoped backlog gauges 对 adapter 返回或进程内已观测的
`(domain, tenant_id, contract_id)` 输出；已观测 scope drain / sweep 后会保留零值 series，空部署、从未出现、
新进程尚未观测或 recorder 已清理的 scope 可以没有 `outbox_pending_depth` series，因此 Prometheus 侧不再用
`absent_over_time(outbox_pending_depth)` 判采样器停更。
采样器/relay worker liveness 的权威信号是 readyz probe（`outbox_sampler` / `outbox_relay`）和外部监控。
`consumer_dlx_skip_total` 不配置告警：它解释 app DLX 未写入的 fail-closed 分支。`consumer_dlx_write_total{outcome="error"}`
是告警面：DLX 未落库时 consumer 会 release inbox claim；release 成功则 broker Requeue，release 失败则
`consumer_release_failed_total{domain}` 增长并 broker Reject，必须由 degraded health + metric 共同暴露。
`saga_dead_letters_total{outcome="written"}` 是人工介入面：补偿失败已进入统一 dead_letter 表；
`outcome="write_error"` 是正确性告警面：journal Failed 行是 durable 审计兜底，但 dead_letter 未落库。
`outbox_relay_envelope_validation_failure_total` 不单独配置告警：对应行会按 permanent failure 进入 outbox
DLX，主告警仍由 `OutboxDlxGrowth` 承载。排障时用 `reason` 区分历史行缺 schema header、schemaVersion
格式错误、schemaHash 格式错误等本地 envelope 问题；对应 dead_letter metadata 会带 `relayFailureReason`。

规则文件 `docs/ops/outbox-relay-alerts.rules.yaml`，`promtool check rules` 校验。

## Dashboard 面板建议

1. **投递延迟**：`max by (domain) (outbox_oldest_pending_age_seconds)` 折线 + 5min SLO 阈值线。
2. **积压深度**：`sum by (domain) (outbox_pending_depth)` 折线 / 堆叠。
3. **partition blocked 深度**：`sum by (domain, contract_id) (outbox_partition_blocked_depth)`。
4. **投递速率与处置分布**：`sum by (domain, status) (rate(outbox_publish_total[5m]))`（ack/requeue/reject 堆叠）。
5. **DLX 速率**：`sum by (domain) (rate(outbox_dlx_total[5m]))`。
6. **Saga DLX 速率**：`sum by (domain, contract_id, outcome) (rate(saga_dead_letters_total[5m]))`。
7. **relay tick 耗时**：`histogram_quantile(0.95, sum by (phase, le) (rate(outbox_relay_tick_duration_seconds_bucket[5m])))`（classic histogram 须 `sum by (..., le)` 包住 `rate(..._bucket)` 再 `histogram_quantile`）。

## 已知差距 / 范围说明

- **tick_duration 仅分 poll/publish 两相（settle 未单独计时）**：issue #1209 原述「分 poll/publish/settle」，但
  settle（CAS 落库）发生在 postgres adapter 的 `relay()` 内部、对 `eventexec` 不可见。从 eventexec 层看，`publish`
  相即 `relay()` 端到端（publish + adapter 内 settle）。若后续需分离 settle 相，须在 adapter 层注入计时器单独发射，
  属 #1208 接线时决策。当前是有意的范围收窄，非遗漏。
- **对标 gocell RelayCollector**：RSS 覆盖 pending depth gauge、oldest-age gauge、三处置耗时（poll/publish）、
  reject 计数（`outbox_dlx_total` = gocell `reject_total` 等效）。**fail-open drop 率无对应**——RSS relay **不采用
  fail-open**：broker 失败走 `Requeue` 退避 / 预算耗尽 `Reject` 进 DLX，无 drop 路径，故不设 `fail_open_drop` metric。
- **relay/sampler worker unhealthy 无专属 Prometheus 告警**：worker 健康经 `WorkerHealth` → readyz probe
  （`outbox_relay`/`outbox_sweeper`/`outbox_sampler`，未导出为 metric）暴露，权威 liveness 信号是 readyz endpoint 的
  外部监控（k8s liveness/readiness）。scoped backlog gauges 可在进程内保留零值 series，但空部署 / 新进程无已观测
  scope 时仍可完全缺失，不能作为采样器 heartbeat；Prometheus 侧仅保留 `OutboxBacklogOldestAgeHigh`（积压增长）等业务信号。如需 worker health
  gauge/heartbeat，属 #1208 接线时决策。
- **acceptance 边界**：#1209 验收标准 = 仪表 seam + 护栏 + 生产实现 + 单元测试（含 facade
  `with_local_recorder` 渲染断言 + postgres `OutboxBacklog` 集成测试 T15–T18，testcontainers gated）。**E2E
  metrics 经 /metrics 实采集**需 runtime 装配 relay/sampler worker（#1429）并挂 HealthListener；验收项为
  `/metrics` 返回 `outbox_publish_total` / `outbox_pending_depth` 等。
- **settings durable journey 模板（#1433）**：`assemblies/runtime/tests/settings_config_publish_durable_e2e.rs`
  用真实 Postgres + `PgConfigUnitOfWork` + `PgOutbox` + 测试 publisher 验证 `settings` 写入、co-tx outbox、
  relay settle、`outbox_publish_total{domain="settings",contract_id="settings.config-version-changed",tenant_id="...",status="ack"}`、
  `outbox_pending_depth{domain="settings",contract_id="settings.config-version-changed",tenant_id="..."}`
  与测试 `outbox_relay_settings` readyz 闭环。`settings.config-version-changed` 现为 active 事件，生产
  relay domain 已包含 `settings`；runtime 通过 generated subscription 接线到 settings subscriber，consumer
  处理时按事件 `(tenant,key,version)` 回读配置仓储并刷新本进程 config cache。该模板仍刻意注入测试 publisher，
  用于隔离验证 settings outbox/relay 指标；生产 AMQP publisher/consumer bridge 覆盖见 runtime durable E2E。
  运行：
  `cargo test -p runtime --features integration --test settings_config_publish_durable_e2e`。

## 配置护栏（误配防护）

relay/sweeper 驱动参数经 `RelayConfig` / `SweeperConfig` 构造期 fail-fast 校验（私有字段 + 唯一 `new()`
funnel，未校验 config 类型层不可表达）：

| 参数 | 范围 | 失败模式 |
|------|------|----------|
| `poll_interval` | [100ms, 300s] | 0ms → `tokio::time::interval` 连发 → poll 热轮询打爆 DB |
| `batch` | [1, 10000] | 0 → poll 恒空 relay 永不推进；过大 → 单 tick 拉爆内存/长事务 |
| `sample_interval` | [1s, 60s] | 0 → 采样聚合查询热轮询；>60s → 5min SLO 窗口采样不足 |
| `domains` | 1..=64 + canonical | 空 → relay 空转；过多/非法 → metrics label 基数失控 |
| `sweep_interval` | ≥1s | 0 → DELETE 热轮询 |
| `retain_seconds` | >0（per-table 下限见下） | outbox 0/负数由 DB 函数 fail-closed；inbox_receipts 低于重投窗口 → 迟到重投误判 Fresh 重复执行 |

## 保留期清理（三张 durable 表，#1210）

同一泛化 `consistency::RetentionSweeper` / `sweeper_loop<S>` 驱动三张表的保留期清理（删除超期**已终结**行，
防无界膨胀）；各表终结谓词 + 时间列 + 默认保留期 + 误配风险：

| 表 | 终结谓词（删除目标） | 时间列 | 默认保留期 | 误配风险 |
|----|---------------------|--------|-----------|----------|
| `outbox` | `status='published'`（dlx 保留供巡检） | `published_at` | 组合根配置（必须 >0） | 非正数 fail-closed；从真实 publish 终态起算，长期 pending 后刚发布不会提前清理 |
| `inbox_receipts` | `status='done'`（claimed 行不删） | `committed_at` | **7 天**（`INBOX_RECEIPT_RETENTION_SECONDS`） | **必须严格大于** outbox 最坏重投窗口（`max_redelivery_window_secs`≈1023s，NServiceBus 去重铁律）——低于/等于即迟到重投被误判 Fresh 重复执行；编译期 const 断言 + 运行期 sweep fail-closed 双档守（INBOX-RECEIPT-RETENTION-FLOOR-01，单源谓词 `retention_meets_redelivery_floor`） |
| `dead_letter` | 全部行（死信均终结） | `last_attempt_at` | **30 天**（`DEAD_LETTER_RETENTION_SECONDS`，合规导向） | 过短 → 合规审计物料过早灭失（清理前冷存储导出见 #1536） |

- 删除时间谓词均用 DB `now()`（不注入 Clock，多实例无跨进程偏移）；sweeper 日志带 `target_table` 区分清理目标（per-target readyz 名见 `SweeperWorker::adopt`）。
- #1429 已接 runtime `outbox` published-row sweeper（`RSS_OUTBOX_RETAIN_SECONDS`，默认 7 天）+ sampler +
  per-domain relay；#1650 已接 runtime `inbox_receipts` sweeper（PG inbox consumer bundle 同源）；#1535 接入
  runtime `dead_letter` sweeper（`RSS_DEAD_LETTER_RETAIN_SECONDS`，默认 30 天）。
- 无界 DELETE → post-GA 批量分页 / 分区见 #1539；inbox_receipts/dead_letter 多租户分租清理见 #1537；sweeper 删除条数 metrics 见 #1538。

## Session expiry sweeper（#1233）

`sessions` 过期清理是 identity 之外的 postgres/runtime maintenance 能力：runtime 的 `session-sweeper`
worker 调用固定 `SECURITY DEFINER` 函数 `rss_sweep_expired_sessions()`，删除 `expires_at <= now()` 的行。
该函数 owner 是 NOLOGIN `rss_session_maintenance`（BYPASSRLS），`rss_app` 只持 `EXECUTE`，不新增表级
maintenance 权限，也不暴露 tenant / raw SQL / retain 参数入口。

- readyz probe：`session_sweeper`。tick 成功为 Healthy，sweep 失败为 Degraded，worker 停止为 Unhealthy。
- 调度 env：`RSS_SESSION_SWEEP_INTERVAL_MS`，默认 300000ms，最小 1000ms；误配 warn + 默认。
- 删除谓词固定为 `expires_at <= now()`，无 grace period；保留 future session 和 revoked-but-future session。

## 接线（#1429）

runtime durable event transport 现在把 outbox relay / sampler / sweeper 与 consumer bundle 作为
`DomainModuleResult` 产物输出：

- per-domain relay：`outbox_relay_identity` / `outbox_relay_settings` readyz probe，按 active/provisioned
  发布域 AMQP publisher 中继 outbox；`settings.config-version-changed` 已有 production consumer queue 与
  settings subscriber。
- sampler：`outbox_sampler` readyz probe，按 `RSS_RELAY_SAMPLE_INTERVAL_MS` 采样 backlog gauges。
- sweeper：`outbox_sweeper` readyz probe，按 `RSS_OUTBOX_SWEEP_INTERVAL_MS` 清理超
  `RSS_OUTBOX_RETAIN_SECONDS` 的 `published` outbox 行。
- consumer bundle：`event_consumer`（或按 topic 后缀区分）readyz probe，按 subscriber binding 接入
  PG `inbox_receipts`、DLX store、AckableSubscriber 与 ConsumerWorker；`inbox_sweeper` readyz probe 按同一
  sweep interval 清理超 `INBOX_RECEIPT_RETENTION_SECONDS` 的 done 去重行。
- saga worker：live saga contract/factory registration 才注册 `saga_executor:<owner>__<contract_slug>` readyz
  probe；source/store infra 错误 Degraded，worker 停止 Unhealthy。无 live registration 不注册假 probe。
- dead-letter sweeper：`dead_letter_sweeper` readyz probe，按 `RSS_OUTBOX_SWEEP_INTERVAL_MS` 清理超
  `RSS_DEAD_LETTER_RETAIN_SECONDS` 的 dead_letter 行。
