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
| `outbox_relay_tick_duration_seconds` | Histogram | `phase` | relay tick | phase=`claim`(原子租约相)/`publish`(同批即时并发中继的 wall time + adapter 内 settle 相) |
| `outbox_same_id_window_expired_total` | Counter | `domain`,`contract_id`,`tenant_id`,`phase` | broker publish 前 DB preflight | phase=`automatic`/`redrive` 的绝对 same-ID deadline 到期；不调用 broker，行 settle 到 DLX |
| `outbox_relay_settlement_failure_total` | Counter | `domain`,`contract_id`,`tenant_id`,`operation`,`reason` | postgres settlement funnel | operation=`published|retry|dlx|same_id_expiry_dlx`；reason=`timeout|expired|lost_lease|storage|payload_protection|invariant` |
| `dlq_redrive_total` | Counter | `tenant_id`,`kind`,`outcome` | `rss dlq replay-dead-letter` / `redrive-outbox` | operator mutation 结果；kind=`dead_letter_replay`/`outbox_dlx_redrive`；一次性 CLI 发射，长期告警看 audit/log |
| `consumer_dlx_skip_total` | Counter | `domain`,`reason` | consumer fail-closed preflight path | 跳过 app DLX 写入的诊断计数；reason 为 malformed id / tenant authority / envelope header / inbox receipt context 闭集 |
| `consumer_dlx_write_total` | Counter | `domain`,`outcome` | consumer app DLX store wrapper | app DLX 写入结果；outcome=`ok`/`error`，error 同时把 consumer health 标为 degraded |
| `consumer_release_failed_total` | Counter | `domain` | DLX 写失败后 release 也失败 | 正确性告警面；consumer broker `Reject`，避免 Requeue 后被 Duplicate→Ack 吞掉 |
| `consumer_lease_lost_total` | Counter | `domain` | consumer inbox lease CAS hard-fence | handler/tx/commit 期间 lease lost；取消当前执行并 broker Requeue，不写 app DLX |
| `saga_dead_letters_total` | Counter | `domain`,`contract_id`,`outcome` | saga compensation DLX path | saga 补偿失败 dead-letter 写入结果；outcome=`written`/`write_error` |

### Label 闭值集

- `status`：闭合于 `consistency::Disposition::as_label()`，值 `ack`/`requeue`/`reject`。
- `outbox_relay_tick_duration_seconds.phase`：闭合于 `eventexec::RelayPhase::as_label()`，值
  `claim`/`publish`。settle（CAS 落库）是 postgres adapter 内部、对 eventexec 不可见，故并入
  `publish` 相，不单列。
- `outbox_same_id_window_expired_total.phase`：闭合于 postgres `SameIdDeliveryPhase::as_label()`，值
  `automatic`/`redrive`。同名 `phase` key 必须用 metric 名限定其闭值集；该 counter 不携带 event id、
  deadline/timestamp、payload、error text 或 partition key。
- `outbox_relay_settlement_failure_total.operation`：闭合于 postgres `SettlementOperation::as_label()`，值
  `published`/`retry`/`dlx`/`same_id_expiry_dlx`；`reason` 闭合于
  `SettlementFailureReason::as_label()`，值 `timeout`/`expired`/`lost_lease`/`storage`/
  `payload_protection`/`invariant`。Tokio deadline、pool timeout、SQLSTATE `57014`/`55P03` 统一映射为
  `timeout`；普通连接/事务/SQL 错误、DLX capsule 保护错误和闭值/行形状违约分别映射后三类。event id、
  lease token、deadline/timestamp、payload 与错误文本均不得进入 label。
- `claim` 相完整覆盖 `PgOutbox::claim_batch`。该 provider 铸造并按值交接 opaque
  `PgClaimedOutboxEntry`；lease/durable context 不进 `consistency` 公开可 hydrate 面，也不进 metric
  label。relay 只借出 typed metric subject，因此 operator 不应从 metric 反推 token/deadline。
- `domain`：来自 provider 构造期绑定并经 `claim_domain()` 暴露的 typed `vocab::DomainName`；
  `RelayConfig` 不保存 domain，`claim_batch(limit)` 也不接受 raw domain。该值由 assembly/provider 声明、
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
  `DlqError::as_label()`；常见 outcome 为 `inserted` / `already_exists` / `redriven` / `not_found` / `expired`，依赖或数据错误为
  `invalid_payload` / `invalid_schema_headers` / `payload_key_unavailable` / `payload_key_forbidden` / `store`。禁止把
  event id、dead_letter id、partition key 或错误文本放进 label。
- `consumer_dlx_write_total.outcome`：闭合于 `eventexec::consumer_worker` 的 DLX wrapper，值 `ok`/`error`；
  禁止携带 handler error、tenant、message id 或 payload 派生值。
- `consumer_lease_lost_total`：label 仅 `domain`；它是 lease CAS hard-fence 观测信号，不代表 handler 业务失败。
- `saga_dead_letters_total.outcome`：闭合于 `eventexec::saga` emit site 的模块内 literal，值
  `written`/`write_error`；`domain`/`contract_id` 来自 `SagaExecutorConfig`，禁止携带 saga_id、step、
  tenant、payload 或 store error 派生值。

### Relay 并发与租约预算

- `RelayConfig::max_in_flight` 构造期只接受 `1..=64`，同时是单轮 claim 上限与 publish 并发上限。claim
  返回后同批立即并发 dispatch，不能用整批串行发布造成批尾已持 lease 却排队等待。
- SQL head-of-partition gate 保证同批对每个非空 `(tenant_id, domain, partition_key)` 至多一个唯一队头；
  不同 partition 与无序 entry 可并发，分区内顺序仍由数据库 gate 承载。
- 每条 broker publish 前，Postgres provider 以 DB 当前时间做 token/deadline lease budget preflight；剩余
  租约必须严格大于 typed `publish + settle + safety` 预算，否则不得调用 broker。默认预算是
  `60s / 40s / 5s / 5s`；每项最大 `86_400_000ms`（24h，含边界），`86_400_001ms` 会在 runtime、
  AMQP 二次构造或 SQL claim/preflight 边界 fail-closed。四项 `RSS_RELAY_*_MS` 缺失才使用默认，存在但非法会阻止启动。
  AMQP basic publish 与 confirm 共享 40s publish deadline；Postgres 通用 watchdog 默认 45s，所有 settle
  完整操作默认限时 5s。timeout/confirm/settle 不确定结果可能已经 delivery，按 at-least-once 路径用稳定
  身份重试，不能从客户端 timeout 推断“broker 未收到”。
- 同一 preflight 先按行的 `same_id_delivery_phase=automatic|redrive` 检查对应持久化绝对 deadline。到期时
  不调用 broker，写安全 DLX 摘要并增加 `outbox_same_id_window_expired_total`；自动重试与 operator redrive
  因而都无法无限延长同一 event id 的投递寿命。
- `publish` phase histogram 记录这一批即时并发 relay 的 wall time，不是各 entry 耗时之和。接近配置的
  publish/watchdog deadline 时，优先排查 broker confirm 延迟、`phase=basic_publish|confirm|publisher_watchdog`
  与 lost-lease/reclaim 日志；不得把 payload/metadata/连接 URL 复制到排障日志或工单。

## SLO 与告警

| 信号 | 阈值 | severity | 规则 |
|------|------|----------|------|
| 投递延迟（最老 pending 龄） | > 5min 持续 2min | critical | `OutboxBacklogOldestAgeHigh` |
| DLX 增长 | 10min 内增长 > 0 | critical | `OutboxDlxGrowth` |
| same-ID 窗口到期 | 10min 内增长 > 0，或首次非零 series 且 10min offset 不存在 | critical | `OutboxSameIdWindowExpired` |
| settlement lease 到期 | 5min 内 `reason="expired"` 增长 > 0，或首次非零 series 且 5min offset 不存在 | critical | `OutboxSettlementExpired` |
| settlement integrity/protection | 5min 内 `reason=~"payload_protection|invariant"` 增长 > 0，或首次非零 series 且 5min offset 不存在 | critical | `OutboxSettlementIntegrityFailure` |
| settlement timeout/lost lease/storage | 按 domain/reason 的 5min rate > 1/s 持续 5min | warning | `OutboxSettlementFailureRateHigh` |
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
DLX/requeue 用 `sum by (domain)`，settlement failure 用 `sum by (domain, reason)`，tick 用
`by (phase)`。scoped backlog gauges 对 adapter 返回或进程内已观测的
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
`OutboxSameIdWindowExpired` 不能只用 `increase(counter[10m])`：首次且唯一一次到期会创建值为 `1` 的
counter series，窗口内只有一个样本时 `increase` 可能没有结果。规则以 `increase(...) OR
((counter > 0) unless (counter offset 10m))` 补捉新 series；连续存在的旧非零 series 因 offset 已存在而不触发，
新 series 到达 offset 边界后也退出，因此不会把历史累计值持续重复分页。可执行语义锁见
`docs/ops/outbox-relay-alerts.test.yaml`，同时覆盖首次单次到期、旧 series 静止和已有 series 后续增长。
`OutboxSettlementExpired` 与 `OutboxSettlementIntegrityFailure` 使用同一 first-series 语义，窗口为 5min；
timeout/lost-lease/storage 告警由持续速率测试锁定。

## Dashboard 面板建议

1. **投递延迟**：`max by (domain) (outbox_oldest_pending_age_seconds)` 折线 + 5min SLO 阈值线。
2. **积压深度**：`sum by (domain) (outbox_pending_depth)` 折线 / 堆叠。
3. **partition blocked 深度**：`sum by (domain, contract_id) (outbox_partition_blocked_depth)`。
4. **投递速率与处置分布**：`sum by (domain, status) (rate(outbox_publish_total[5m]))`（ack/requeue/reject 堆叠）。
5. **DLX 速率**：`sum by (domain) (rate(outbox_dlx_total[5m]))`。
6. **same-ID 窗口到期**：`sum by (domain, phase) ((increase(outbox_same_id_window_expired_total[10m]) > 0) or
   ((outbox_same_id_window_expired_total > 0) unless
   (outbox_same_id_window_expired_total offset 10m)))`；`phase` 在此只显示 `automatic|redrive`。右侧是首次
   非零 series 补偿；左侧的 `> 0` 必须保留，否则零增长 series 会遮住补偿分支。
7. **settlement failure**：`sum by (domain, operation, reason) (rate(outbox_relay_settlement_failure_total[5m]))`；
   `expired|payload_protection|invariant` 直接按 critical 规则处置，`timeout|lost_lease|storage` 用于连接池、
   锁等待、事务和 ownership 诊断。
8. **Saga DLX 速率**：`sum by (domain, contract_id, outcome) (rate(saga_dead_letters_total[5m]))`。
9. **relay tick 耗时**：`histogram_quantile(0.95, sum by (phase, le) (rate(outbox_relay_tick_duration_seconds_bucket[5m])))`（classic histogram 须 `sum by (..., le)` 包住 `rate(..._bucket)` 再 `histogram_quantile`；此处 `phase=claim|publish`）。

## 已知差距 / 范围说明

- **tick_duration 仅分 claim/publish 两相（settle 未单独计时）**：issue #1209 原述「分
  claim/publish/settle」，但
  settle（CAS 落库）发生在 postgres adapter 的 `relay()` 内部、对 `eventexec` 不可见。从 eventexec 层看，`publish`
  相即 `relay()` 端到端（publish + adapter 内 settle）。若后续需分离 settle 相，须在 adapter 层注入计时器单独发射，
  属 #1208 接线时决策。当前是有意的范围收窄，非遗漏。
- **对标 gocell RelayCollector**：RSS 覆盖 pending depth gauge、oldest-age gauge、三处置耗时
  （claim/publish）、
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

relay/sampler/sweeper 驱动参数经 `RelayConfig` / `SamplerConfig` / `SweeperConfig` 构造期 fail-fast 校验（私有字段 + 唯一 `new()`
funnel，未校验 config 类型层不可表达）：

| 参数 | 范围 | 失败模式 |
|------|------|----------|
| `poll_interval` | [100ms, 300s] | 0ms → `tokio::time::interval` 连发 → claim 定时轮询打爆 DB |
| `max_in_flight` | [1, 64] | 0 → claim 恒空、relay 永不推进；过大 → 在途 I/O/内存失控且 lease 预算承压 |
| `sample_interval` | [1s, 60s] | 0 → 采样聚合查询热轮询；>60s → 5min SLO 窗口采样不足 |
| sampler `domains` | 1..=64 + canonical | 空 → sampler 无 scope；过多/非法 → metrics label 基数失控；relay domain 不走此参数 |
| `sweep_interval` | ≥1s | 0 → DELETE 热轮询 |
| `retain_seconds` | >0（仅 outbox caller config） | outbox 0/负数由 DB 函数 fail-closed；inbox_receipts 与 dead_letter lifecycle 不接受 caller retain 参数 |

same-ID 正确性策略不属于上述性能/保留期调参。数据库 singleton `event_delivery_policy` 冻结
`same-id-delivery-v1`：automatic retry 24h、same-ID redrive 24h、safety 24h、inbox receipt 7d。runtime
启动期只接受数据库中唯一一行与 release 常量完全一致，且 retention 必须严格覆盖三段窗口；不提供 correctness
环境变量、CLI 参数或 assembly override。

## 保留期与 DLX lifecycle（三张 durable 表，#1210/#1168）

outbox/inbox 使用 bounded retention sweep；dead_letter 使用独立 archive-before-purge state machine：

| 表 | 终结谓词（删除目标） | 时间列 | 默认保留期 | 误配风险 |
|----|---------------------|--------|-----------|----------|
| `outbox` | `status='published'`（dlx 保留供巡检） | `published_at` | 组合根配置（必须 >0） | 非正数 fail-closed；从真实 publish 终态起算，长期 pending 后刚发布不会提前清理 |
| `inbox_receipts` | `status='done'`（claimed 行不删） | `committed_at` | **7 天**（数据库 singleton policy） | 必须严格大于 automatic 24h + redrive 24h + safety 24h；DB CHECK 与 runtime 精确策略 hydration 双重 fail-closed，避免 receipt 先删除后同 event id 再次执行 |
| `dead_letter` | verified WORM receipt 存在且 lock 尚有效 | `last_attempt_at` | hot **精确 30 天**（不可配置） | 未归档、回执不完整、lock 非 COMPLIANCE/已到期均 fail-closed 不删 |

- 删除时间谓词均用 DB clock（不注入 Clock，多实例无跨进程偏移）；sweeper 日志带 `target_table` 区分清理目标（per-target readyz 名见 `SweeperWorker::adopt`）。inbox sweeper 调用零参数
  `rss_sweep_inbox_receipts()`，函数从 policy 读取 7d，每 tick 按 `(committed_at,tenant_id,event_id,consumer_group)`
  固定最多删除 1000 条 done receipt；不存在 retain 参数 overload。
- #1429 已接 runtime `outbox` published-row sweeper（`RSS_OUTBOX_RETAIN_SECONDS`，默认 7 天）+ sampler +
  per-domain relay；#1650 已接 `inbox_receipts` sweep。两者均稳定排序且每轮最多 1000 条。
- DLX worker 每轮最多处理 100 个 archive candidate、1000 个 verified hot purge、100 个 expired receipt
  reconcile；归档 transient failure 保留 hot row并继续本批、health 为 Degraded，AAD/格式/既有对象语义冲突为
  Invariant、health 为 Unhealthy 且本轮禁止 purge。
- 低基数指标固定为 `retention_sweep_deleted_total{target}`、`retention_sweep_ticks_total{target,outcome}`、
  `retention_sweep_duration_seconds{target,outcome}`，以及 archive pending depth/oldest age/outcome/duration；
  `target/outcome` 来自闭枚举；不伪造未单独计时的 phase 粒度，并禁止
  tenant/id/object key/payload/error text 标签。

## AuthGrant expiry sweeper（#1233，#1834）

`auth_grants` 过期清理是 identity 之外的 postgres/runtime maintenance 能力：runtime 的
`auth-grant-sweeper` worker 调用固定 `SECURITY DEFINER` 函数
`rss_sweep_expired_auth_grants()`，删除 `expires_at <= now()` 的根；复合外键级联清理已关闭刷新族。
该函数 owner 是 NOLOGIN `rss_auth_grant_maintenance`（BYPASSRLS），`rss_app` 只持 `EXECUTE`，不新增表级
maintenance 权限，也不暴露 tenant / raw SQL / retain 参数入口。

- readyz probe：`auth_grant_sweeper`。tick 成功为 Healthy，sweep 失败为 Degraded，worker 停止为 Unhealthy。
- 调度 env：`RSS_AUTH_GRANT_SWEEP_INTERVAL_MS`，默认 300000ms，最小 1000ms；误配 warn + 默认。
- 删除谓词固定为 `expires_at <= now()`，无 grace period；保留 future AuthGrant。

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
  sweep interval 调用数据库 policy-bound 零参数函数，清理超 7d 的 done 去重行；assembly 不传 retain 值。
- saga worker：live saga contract/factory registration 才注册 `saga_executor:<owner>__<contract_slug>` readyz
  probe；source/store infra 错误 Degraded，worker 停止 Unhealthy。无 live registration 不注册假 probe。
- DLX lifecycle：`dlx_lifecycle` readyz probe + `dlx-lifecycle` worker，以固定 30 秒周期按 hot
  30 天策略执行 archive/receipt/purge/reconcile。它不复用 outbox/inbox sweep interval，也没有
  retention env。
