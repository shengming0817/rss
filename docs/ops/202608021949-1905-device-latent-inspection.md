# DeviceLatent read-only inspection

本页是设备证书 DeviceLatent 收敛的只读观察入口。它不激活 draft HTTP contract，不提供
force-resync、resume、quarantine/unquarantine、cancel、supersede 或直接 SQL 修复。证书专项恢复仍由
#1972 的 owner 承担。

## Signals

数值观测使用以下固定 histogram family；应用层 label 集为空，Prometheus exporter 仅可附加其固定
`quantile` label：

- `device_latent_generation_lag`
- `device_latent_drift_age_seconds`
- `device_latent_queue_age_seconds`
- `device_latent_ack_latency_seconds`

每次成功 inspection 使用同一 PostgreSQL 只读事务内取得的数据库时钟生成一组样本：generation lag 为
`desired - reported`（无 report 时 reported 为 0）；drift age 只来自当前 `Ready/StateDrift` 的 transition；
queue age 为 queued→published，尚未 publish 时为 queued→数据库观察时刻；ACK latency 为
published→received，尚未 received 时为 published→数据库观察时刻，未 publish 时不发射。任何倒序或未来
时间戳都 fail closed，不发射部分样本，也不输出状态。

上述四个 histogram 是 `rss device-latent inspect --output prometheus` 的 one-shot 输出面；它们不证明
reconcile worker 存活，也不替代 serving scrape。

Condition 只允许 `Ready`、`Reconciling`、`PendingDevice`、`Degraded`、`Quarantined`、`Deleting`；
status/reason 必须来自同一 typed condition 分支。不要把缺失 series 当作零值，也不要根据单次 inspection
推断后台 worker 存活。

## Reconcile Signals（worker + scrape 接线后）

`device_latent_lease_churn_total` 由 `eventexec` reconcile worker 在 claim/extend/release 路径 emit，**不是**
inspection one-shot 的一部分。当前 runtime / deviceidentity pilot 在 serving scrape 与
`ReconcileScheduler` 装配完成前，该 counter **不可用于 on-call**（见 runbook index 的 scrape-not-wired
说明）。仅当 worker 已运行且 Prometheus scrape 已接线时，才把 lease churn 纳入值班判断。

接线后的闭集标签为
`device_latent_lease_churn_total{operation="claim|extend|release",state="held|lost|error",reason="<closed>"}`，
其中 `reason` 闭值为：

- `due_scan`
- `targeted_wake`
- `renewal`
- `attempt_cancelled`
- `append_attempt_failed`
- `attempt_result_record_failed`
- `superseded_replacement`
- `stale_generation`
- `claim_not_admitted`
- `shutdown_before_replacement`
- `pause_before_replacement`
- `replacement_not_started`

上述 family 禁止 tenant、device、command、target、holder、attempt、payload、certificate、artifact 或错误文本
label。

## Authenticated inspection

命令没有环境变量 tenant allowlist，也不读取 ambient `std::env` 授权配置。唯一 `--tenant` 同时绑定
maintenance service token 验证和 tenant-scoped status read；因此 operator tenant 与目标 tenant 不存在两个可
替换输入。命令动作、contract 和 permission 固定为 `identity:device-certificate-status:read`：

```text
rss device-latent inspect \
  --operator-service-token-stdin \
  --tenant <canonical-tenant-uuid> \
  --device-id <lowercase-hyphenated-non-nil-device-uuid> \
  --output json
```

`--output` 是闭值 `json|prometheus`，省略时默认 `json`。所有必填、唯一、值域和 canonical UUID 校验完成后才
消费 stdin 中的单个 maintenance service token；`--help` 不消费 stdin，也不捕获 runtime 配置。`resume` 及其它
未知 action 在 runtime 配置和 provider 初始化前拒绝。

命令同时验证 token 与同一个 tenant、固定 contract/permission 和 canonical device resource；任一不一致都在
读取存储前以不含目标标识的固定错误拒绝。
读取使用 tenant-scoped PostgreSQL read lane 与 read-only transaction；目标 tenant/device 的存在性只在成功授权后
求值。独立的 operator tenant / target tenant 组合在 CLI 中不可表达。

`--output json` 复用 generated status DTO，只输出 generation、fence epoch 和闭状态；status schema 不含
tenant/device/command 标识、command payload 或 certificate material。`--output prometheus` 在 one-shot 进程中
安装真实 Prometheus recorder，记录本页四个闭合 histogram family 并把可直接抓取的 exposition 输出到 stdout。两种
模式都不输出 tenant、device、command、payload 或 certificate 标识。日志、trace 与 durable maintenance audit 只记录
固定 action/outcome/reason，不记录命令参数中的标识。

## Observe and escalate

1. 先比较 generation lag 与 condition：`Reconciling`/`PendingDevice` 表示仍在收敛，`Degraded` 或持续
   `StateDrift` 才进入异常调查。
2. 再比较 drift age、queue age 与 ACK latency。queue/ACK 同时升高时先检查 transport。仅在 reconcile worker 与
   scrape 已接线时，才额外观察 lease churn：`lost|error` 增长时检查数据库延迟、lease TTL、worker drain 和
   leader ownership。
3. 使用只读 inspection 保存脱敏 JSON、UTC 时间窗口和固定 metric family 的聚合证据。不得复制 token、原始
   command ID、payload、CSR、certificate、artifact 或 tenant/device label 到工单、日志或 dashboard。
4. 需要止损时，只能在现有 deployment/admission owner 中暂停新的策略接纳并执行既有 drain 流程；本命令不改变
   desired state、command、condition、lease 或 reconcile target。
5. 依赖恢复后继续观察。如需证书专项恢复，携带脱敏证据升级到 #1972 owner；不要使用通用
   `reconcile-target resume` 代替证书恢复证明。

若 inspection 返回认证/授权失败，先修复 operator token 及其 tenant binding；若返回
`configuration|storage|operator provider|operator authentication|operator authorization|status not found|status projection|output|audit|shutdown`
固定错误，保留现场并升级相应 owner。最终 CLI 错误不回显 provider/sqlx source、DSN 或目标标识。任何失败都不得
通过另加 tenant 参数、手工改表、伪造 condition 或重放 payload 绕过。

## Operator clap 诊断契约（全 family 共用）

`rss` operator CLI（`dlq` / `device-latent` / `audit-ledger` / `settings-config-values` /
`l2-dr-recovery` / `projections` / `sagas` / `reconcile-target` 等）在 clap prepare-first 路径上遵守：

1. **Family 桶**：非 help/version 的 clap 失败映射为固定文案
   `{family}: <bucket>; see --help`，其中 bucket 为
   `missing required argument` / `missing subcommand` / `unknown subcommand` /
   `unexpected argument` / `invalid value` / `invalid arguments`。不得把 clap `err` 原文拼进诊断。
2. **SECRET 不回显**：value_parser 与 post-clap ensure 禁止插值 argv / `SECRET_BAIT`；presence-only
   `--operator-service-token-stdin` 不得接受赋值。
3. **prepare-first**：`prepare_*` 完成 argv + stdin token 校验后，才打开 runtime / secret bundle；
   `--help` 不消费 stdin、不捕获配置。`help` 子命令已禁用，只用 `--help`。
4. **settings 租户范围**：`settings-config-values maintenance` 必须显式 `--tenant <uuid>` 或
   `--all-tenants`（互斥）；省略不得默默全租户写。
