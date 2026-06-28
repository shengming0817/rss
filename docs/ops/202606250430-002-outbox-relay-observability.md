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
| `outbox_publish_total` | Counter | `domain`,`status` | relay tick 逐条结算 | status=`ack`(已投递)/`requeue`(退避重投)/`reject`(进 DLX) |
| `outbox_dlx_total` | Counter | `domain` | relay 结算 Reject 时 | 永久失败进 DLX；= `outbox_publish_total{status="reject"}` |
| `outbox_pending_depth` | Gauge | `domain` | backlog 采样器（默认 ≤60s/轮） | status=pending 且到期行数 |
| `outbox_oldest_pending_age_seconds` | Gauge | `domain` | backlog 采样器 | `now()−min(created_at)`；**无 pending ⇒ 0**（非缺失，防 Prometheus 把 drain 误判采样器死亡） |
| `outbox_relay_tick_duration_seconds` | Histogram | `phase` | relay tick | phase=`poll`(扫描相)/`publish`(逐条中继+adapter 内 settle 相) |
| `consumer_dlx_skip_total` | Counter | `domain`,`reason` | consumer fail-closed path | 跳过 app DLX 写入的诊断计数；当前 reason=`tenant_missing` |

### Label 闭值集

- `status`：闭合于 `consistency::Disposition::as_label()`，值 `ack`/`requeue`/`reject`。
- `phase`：闭合于 `eventexec::RelayPhase::as_label()`，值 `poll`/`publish`。settle（CAS 落库）是 postgres
  adapter 内部、对 eventexec 不可见，故并入 `publish` 相，不单列。
- `domain`：来自 `RelayConfig` 构造期校验的 domain 集（数量 ≤64 + canonical 标识格式），operator 配置、
  非请求/租户派生，基数有界。**不**经 `observ` typed enum（层矩阵禁 `eventexec`→`observ`）；收敛进 `observ`
  词表统一 otel 映射是 #1076 后续项。
- `consumer_dlx_skip_total.reason`：闭合于 `eventexec::consumer::record_dead_letter_skip` 的模块内 literal 调用点；
  禁止携带 handler error、tenant、message id 或 payload 派生值。

## SLO 与告警

| 信号 | 阈值 | severity | 规则 |
|------|------|----------|------|
| 投递延迟（最老 pending 龄） | > 5min 持续 2min | critical | `OutboxBacklogOldestAgeHigh` |
| DLX 增长 | 10min 内增长 > 0 | critical | `OutboxDlxGrowth` |
| pending 深度 | > 10k 持续 5min | warning | `OutboxPendingDepthHigh` |
| 重试风暴（requeue 速率） | > 5/s 持续 5min | warning | `OutboxRequeueStorm` |
| relay tick P95 耗时 | > 5s 持续 5min | warning | `OutboxRelayTickSlow` |
| 采样器停更 | 10min 无新样本 | warning | `OutboxSamplerNoData` |

告警均 `by (domain)` / `by (phase)` 聚合保来源可定位。采样器停更用 `absent_over_time`（捕捉运行后卡死，非仅首启动）。
`consumer_dlx_skip_total` 不配置告警：它解释 app DLX 未写入的 fail-closed 分支，实际告警面仍是 broker settle
失败、DLX/reject 增长和业务积压。

规则文件 `docs/ops/outbox-relay-alerts.rules.yaml`，`promtool check rules` 校验。

## Dashboard 面板建议

1. **投递延迟**：`max(outbox_oldest_pending_age_seconds) by (domain)` 折线 + 5min SLO 阈值线。
2. **积压深度**：`outbox_pending_depth` by domain 折线 / 堆叠。
3. **投递速率与处置分布**：`rate(outbox_publish_total[5m])` by status（ack/requeue/reject 堆叠）。
4. **DLX 速率**：`rate(outbox_dlx_total[5m])` by domain。
5. **relay tick 耗时**：`histogram_quantile(0.95, sum by (phase, le) (rate(outbox_relay_tick_duration_seconds_bucket[5m])))`（classic histogram 须 `sum by (..., le)` 包住 `rate(..._bucket)` 再 `histogram_quantile`）。

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
  外部监控（k8s liveness/readiness）。Prometheus 侧 worker 卡死靠 `OutboxSamplerNoData`（采样停更）+
  `OutboxBacklogOldestAgeHigh`（积压增长）间接体现。如需 worker health gauge，属 #1208 接线时决策。
- **acceptance 边界**：#1209 验收标准 = 仪表 seam + 护栏 + feature-gated 生产实现 + 单元测试（含 facade
  `with_local_recorder` 渲染断言 + postgres `OutboxBacklog` 集成测试 T15–T18，testcontainers gated）。**E2E
  metrics 经 /metrics 实采集**需 relay/sampler worker 被组合根实例化 + 启 `metrics-facade` feature，属 #1208 接线的
  acceptance gate——#1208 issue body 须含验收项「/metrics 返回 `outbox_publish_total` / `outbox_pending_depth` 等」。

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
| `retain_seconds` | ≠0（per-table 下限见下） | 0 → 删除 just-published 行；inbox_dedup 低于重投窗口 → 迟到重投误判 Fresh 重复执行 |

## 保留期清理（三张 durable 表，#1210）

同一泛化 `consistency::RetentionSweeper` / `sweeper_loop<S>` 驱动三张表的保留期清理（删除超期**已终结**行，
防无界膨胀）；各表终结谓词 + 时间列 + 默认保留期 + 误配风险：

| 表 | 终结谓词（删除目标） | 时间列 | 默认保留期 | 误配风险 |
|----|---------------------|--------|-----------|----------|
| `outbox` | `status='published'`（dlx 保留供巡检） | `created_at` | 组合根配置（无硬下限） | retain=0 → 删 just-published 行 |
| `inbox_dedup` | `status='done'`（claimed 行不删） | `claimed_at` | **7 天**（`INBOX_DEDUP_RETENTION_SECONDS`） | **必须严格大于** outbox 最坏重投窗口（`max_redelivery_window_secs`≈1023s，NServiceBus 去重铁律）——低于/等于即迟到重投被误判 Fresh 重复执行；编译期 const 断言 + 运行期 sweep fail-closed 双档守（INBOX-DEDUP-RETENTION-FLOOR-01，单源谓词 `retention_meets_redelivery_floor`） |
| `dead_letter` | 全部行（死信均终结） | `last_attempt_at` | **30 天**（`DEAD_LETTER_RETENTION_SECONDS`，合规导向） | 过短 → 合规审计物料过早灭失（清理前冷存储导出见 #1536） |

- 删除时间谓词均用 DB `now()`（不注入 Clock，多实例无跨进程偏移）；sweeper 日志带 `target_table` 区分清理目标（per-target readyz 名见 `SweeperWorker::adopt`）。
- 三表 sweeper worker spawn + env/assembly 读保留期 + per-target readyz 探针注册 = Feature #1208 接线（见下）。
- 无界 DELETE → post-GA 批量分页 / 分区见 #1539；inbox_dedup/dead_letter 多租户分租清理见 #1537；sweeper 删除条数 metrics 见 #1538。

## 接线（范围外，独立 issue）

relay/sweeper/sampler worker 当前**未被任何组合根实例化**。本 issue 交付仪表 seam + 护栏 + feature-gated
生产实现 + 告警/文档；组合根实例化三 worker、启 `eventexec/metrics-facade` feature 注入
`MetricsOutboxMetrics`、`/metrics` 挂 HealthListener 属 Feature #1208 接线 issue。
