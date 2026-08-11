# #1440 Outbox / Inbox DLQ Redrive Runbook

ref: GoCell framework/kernel/outbox/state.go@043add59bbe840e4a90a4253feec21f074b590dd
ref: Spring Modulith spring-modulith-events/spring-modulith-events-jdbc/src/main/java/org/springframework/modulith/events/jdbc/JdbcEventPublicationRepositoryV2.java@c75f173e5201208d8129b4cd8c112defb1158c67

## Scope

本 runbook 覆盖 runtime operator CLI：

- `rss dlq list`
- `rss dlq inspect`
- `rss dlq replay-dead-letter`
- `rss dlq redrive-outbox`
- `rss dlq resolve-expired-outbox`

v1 不提供 destructive `skip`。deadline 内的 partition unblock 通过 redrive outbox DLX 队头完成；
deadline 已过的队头只能经 `resolve-expired-outbox` terminal funnel 以受审计的
`accepted_gap` 或 `compensated` 结清。

## Bounded same-ID policy

RSS 使用数据库 singleton `event_delivery_policy(policy_revision='same-id-delivery-v1')` 冻结 automatic retry
24h、same-ID operator redrive 24h、safety 24h 与 inbox receipt retention 7d；7d 必须严格大于前三段之和。
Spring Modulith 的 JDBC repository 提供同 publication id 的原子 resubmit，但上游没有 maximum same-ID
horizon；RSS 明确增加两个持久化绝对 deadline，防止 receipt 过期后旧 id 再触发 durable effect。

- 首次 automatic claim 冻结 `automatic_retry_deadline`；首次进入 DLX 冻结
  `same_id_redrive_deadline`。两个 deadline 一经写入就不会因 retry 或 redrive 延长。
- `same_id_delivery_phase` 仅为 `automatic|redrive`。redrive 成功切到 `redrive` 并保留两个 deadline。
- automatic 或 redrive phase 在 publish preflight 发现 deadline 到期时，不调用 broker，行 settle/保留在
  DLX；operator redrive 在 redrive deadline 到期后返回 typed `Expired` 且不修改行。
- 本 policy 没有环境变量、CLI flag 或 caller retain override；数据库值与 release 常量不完全一致时 runtime
  启动 fail-closed。

## Preconditions

必须先确认：

- operator service token 可被 PDP 验证，且其闭值 caller 必须是
  `ServiceCallerDomain::MaintenanceOperator`（canonical `sub=rss-maintenance-operator`）。
- operator service token 的 `issuer/audience/已验证 kid/jti` 会被长度分帧并 SHA-256；Postgres
  `service_token_replay_keys` 只持久化固定 32-byte digest。同一 scope 的 token 跨 CLI 进程重放会被拒绝，
  replay store 不可用时认证 fail-closed。
- 命令带 `--operator-service-token-stdin`、`--operator-tenant`、`--tenant`；token 只从标准输入读取。
- 环境变量 `RSS_DLQ_OPERATOR_GRANTS` 包含精确 grant：`action|tenant`。caller 已由上述 typed
  service-token 认证前置，不再从配置字符串选择。
- 仅 `replay-dead-letter` 需要 DLQ payload 解密依赖：`RSS_DLX_PAYLOAD_KEY_NAME`、`RSS_VAULT_ADDR`、`RSS_VAULT_TOKEN`、`RSS_VAULT_TRANSIT_MOUNT`。`list`、`inspect` 与 `redrive-outbox` 不依赖 payload key provider。
- `resolve-expired-outbox` 不读 payload，但需要精确的
  `resolve-expired-outbox|tenant` grant、变更工单号，以及策略所要求的 evidence。
- CLI 必须走离线、connect-only 的 `PgRuntimeDeps::connect_maintenance` 连接；它绝不执行 migration。长期 serving role
  `rss_app` 没有 `rss_outbox_redrive(text,uuid)` EXECUTE；不要把 migrator 凭据注入 server serving pool。

审计固定写入：

- kind: `dlq.maintenance`
- action: `dlq.<action>.start|finish`

## Commands

列出当前租户 DLQ：

```bash
export OPERATOR_SERVICE_TOKEN_FILE='/run/secrets/rss-operator-service-token'
export OPERATOR_TENANT='00000000-0000-4000-8000-000000000001'
export TENANT='00000000-0000-4000-8000-000000000002'
export RSS_DLQ_OPERATOR_GRANTS="list|$TENANT"

rss dlq list \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --source outbox_relay \
  --producer-domain identity \
  --contract-id identity.session-created \
  --limit 50 < "$OPERATOR_SERVICE_TOKEN_FILE"
```

`list` / `inspect` 的每条 DLQ summary 输出为一行 JSON（JSONL）：自由文本字段（如 `errorSummary`）不参与空格分隔解析。

检查 outbox DLX 行：

```bash
rss dlq inspect \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --kind outbox-dlx \
  --id "$EVENT_ID" < "$OPERATOR_SERVICE_TOKEN_FILE"
```

重放 consumer `dead_letter`：

```bash
rss dlq replay-dead-letter \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --dead-letter-id "$DEAD_LETTER_ID" \
  --replay-id "$NEW_OUTBOX_EVENT_ID" < "$OPERATOR_SERVICE_TOKEN_FILE"
```

redrive outbox DLX：

```bash
rss dlq redrive-outbox \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --event-id "$EVENT_ID" < "$OPERATOR_SERVICE_TOKEN_FILE"
```

结清已过 same-ID deadline 的 outbox DLX 队头：

```bash
export RSS_DLQ_OPERATOR_GRANTS="resolve-expired-outbox|$TENANT"

# 业务确认接受缺口：evidence 严格禁止。
rss dlq resolve-expired-outbox \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --event-id "$EVENT_ID" \
  --change-ticket "$CHANGE_TICKET" \
  --resolution-kind accepted_gap < "$OPERATOR_SERVICE_TOKEN_FILE"

# 已由同 tenant 的 published compensation event 补偿：evidence 严格必填。
rss dlq resolve-expired-outbox \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --event-id "$EVENT_ID" \
  --change-ticket "$CHANGE_TICKET" \
  --resolution-kind compensated \
  --evidence-event-id "$COMPENSATION_EVENT_ID" < "$OPERATOR_SERVICE_TOKEN_FILE"
```

`accepted_gap` 表示业务所有者通过变更工单明确接受未发布事件造成的缺口；
`compensated` 表示另一已 published 事件完成了业务补偿。数据库会验证 compensation event
与 blocked event 同 tenant，且 `causation_id` 精确指向 blocked event。不得用任意已发布事件充当 evidence。

## Partition Blocked

告警 `OutboxPartitionBlocked` 触发时：

1. 设置通用环境：

```bash
export OPERATOR_SERVICE_TOKEN_FILE='/run/secrets/rss-operator-service-token'
export OPERATOR_TENANT='<operator-tenant-uuid>'
export TENANT='<tenant-uuid-from-alert-label>'
export DOMAIN='<domain-from-alert-label>'
export CONTRACT_ID='<contract_id-from-alert-label>'
export RSS_DLQ_OPERATOR_GRANTS="list|$TENANT,inspect|$TENANT,redrive-outbox|$TENANT"
```

2. 找当前 tenant/domain/contract 的 outbox DLX 队头候选：

```bash
rss dlq list \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --source outbox_relay \
  --producer-domain "$DOMAIN" \
  --contract-id "$CONTRACT_ID" \
  --limit 20 < "$OPERATOR_SERVICE_TOKEN_FILE"
```

若命令尾行显示 `has_more=true`，读取 `next_cursor` 后带 `--cursor "$NEXT_CURSOR"` 续页，直到 `has_more=false`。不要用 offset，也不要假设单页覆盖完整 DLQ。outbox DLX 的 `last_attempt` 展示、降序排序和 cursor 均以权威终态时间 `dlx_at` 为单源；后续租约或运维写入导致的 `updated_at` 变化不得改变队列顺序。

3. 核对 `contract_id`、`error_summary`、attempts：

```bash
rss dlq inspect \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --kind outbox-dlx \
  --id "$EVENT_ID" < "$OPERATOR_SERVICE_TOKEN_FILE"
```

4. 修复导致 DLX 的上游问题；若 payload/schema/tenant envelope 仍非法，不要 redrive。
5. 执行 redrive：

```bash
rss dlq redrive-outbox \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --event-id "$EVENT_ID" < "$OPERATOR_SERVICE_TOKEN_FILE"
```

6. 等 relay 发布该队头，再观察 `outbox_partition_blocked_depth{tenant_id,domain,contract_id}` 回到 0。

如果第 5 步返回 `Expired`，不得重试 redrive。取得业务所有者和变更工单批准，按上述
`accepted_gap` / `compensated` 选择执行 `resolve-expired-outbox`。命令只在目标是当前 tenant、
仍为 DLX 且 deadline 已过时成功；成功后原行进入 `abandoned`，并在
`outbox_expired_resolutions` 留下 change ticket、operator subject、resolution 和可选 evidence。
验收时同时确认命令输出 `outcome=resolved`、finish audit 成功，以及 blocked depth 回到 0。

`partition_key` 不在 metric、CLI 输出或 audit resource id 中暴露。需要精确定位时，用 event id 在受控 DB 访问路径中检查。

## Metrics

- `outbox_partition_blocked_depth{domain,contract_id,tenant_id}`：blocked 后继行数。
- `outbox_same_id_window_expired_total{domain,contract_id,tenant_id,phase}`：relay publish preflight 发现
  deadline 到期；`phase=automatic|redrive`，broker publish 未发生。
- `dlq_redrive_total{tenant_id,kind,outcome}`：operator mutation 结果；`kind=dead_letter_replay|outbox_dlx_redrive|outbox_dlx_resolve_expired`，
  outbox redrive outcome 包含 `redriven|not_found|expired`；dead-letter replay 的存储失败直接使用闭值阶段
  `fetch_dead_letter|encode_metadata|append_outbox|projection_mirror|transaction`，不再同时上报 `store`。
  该计数只在进程安装 metrics recorder 时可采集；
  `rss dlq` 是一次性 operator 进程，不承诺 Prometheus scrape 面，长期告警以 relay/consumer 常驻进程 metric
  与 `dlq.maintenance` audit/log 为准。
- `outbox_publish_total{status="requeue|reject"}`：broker publish transient/permanent 处置。
- `outbox_relay_envelope_validation_failure_total{reason}`：本地 envelope/schema header gate。
- `consumer_lease_lost_total{domain}`：consumer inbox lease hard-fence。

`dlq_redrive_total{outcome="not_found"}` 对 outbox redrive 表示未 mutation，命令以非零状态退出且 finish audit 记
`failure/not_found`；常见原因是 wrong tenant、目标非 DLX 或已被其它 operator redrive。
`dlq_redrive_total{outcome="expired"}` 表示目标仍在当前 tenant 的 DLX，但绝对 redrive deadline 已到；行未
mutation，partition 不会被解锁。CLI 输出 `outcome=expired`、以非零状态结束，并写
`dlq.redrive-outbox.finish` failure audit（reason=`expired`）。

## Failure Handling

- `NotFound`（非零退出）：先核对 `--tenant` 与 id；wrong-tenant redrive 不泄漏存在性。
- `Expired`：不要重复 redrive；绝对 deadline 不可续期。只能在变更工单批准后执行
  `resolve-expired-outbox --resolution-kind accepted_gap|compensated`；不直接 broker publish、不创建同 id 兼容路径。
- `InvalidEvidence`：`compensated` evidence 不是同 tenant published event，或 `causation_id`
  不指向 blocked event；修正 evidence，不得改用 `accepted_gap` 规避验证。
- `NotExpired`：目标仍在 redrive window；修复上游后走 `redrive-outbox`，不得提前放弃。
- `NotReplayable`：`outbox_relay`、`saga`、`projection` dead_letter 不支持 replay 成 outbox。
- `InvalidSchemaHeaders` / `InvalidPayload`：先修数据/代码，不要重复 replay。
- `FetchDeadLetter`：先检查 PostgreSQL 可用性与 maintenance tenant transaction；若连接正常，则通过受控
  数据库路径核对 persisted `source_kind` 是否仍属于闭值 catalog。非法 `source_kind` 是 schema/数据不变量
  漂移，修复数据或代码前不得重复 replay；原 dead-letter 未删除。
- `EncodeMetadata`：停止重试并修复 replay metadata 编码不变量；不会产生 outbox 写入。
- `AppendOutbox`：按 SQLSTATE/constraint 检查 outbox 写入权限或约束；fact conflict 仍单独返回 typed conflict。
- `ProjectionMirror`：核对 generated capture 与数据库 projection input catalog 的完整
  domain/contract/version/schema/topic；该阶段失败会回滚同事务内的 outbox 与 projection 写入。
- `Transaction`：检查 begin/commit/rollback 路径与数据库连接；在确认事务结局前不要改用直接 broker publish。

replay 失败日志只提供闭值 stage、SQLSTATE、constraint 或 key-provider kind。payload、metadata、capsule、
key ref 与原始 source chain 不属于诊断面；需要定位时使用命令在 stderr 输出的 `audit_id=<id>`，通过受控
数据库路径核查同一 `request_id` 下的 identity-neutral start attempt 与 verified operator finish 记录。
- `PayloadKeyUnavailable` / `PayloadKeyForbidden`：恢复 Vault/key provider 后重试。
- `Store`：检查 Postgres、RLS、SECURITY DEFINER 函数权限和 migration 版本。

成功 redrive 本身不删除 hot `dead_letter` 行，不修改 payload/schema/seq/partition 或两个绝对 deadline；它只把
outbox DLX 行恢复为 `pending`、切 `same_id_delivery_phase='redrive'`，清 retry/lease，并同时清空
`published_at`、`dlx_at`。hot DLX 历史随后由强制 archive-before-purge lifecycle 转入 WORM cold archive；
operator CLI 不 list/inspect/replay cold archive。

## 0060 breaking rollout

0060 是停机 cutover，不允许新旧 relay/CLI 滚动混跑：

1. 停止全部旧 relay 与仍可能执行 `rss dlq redrive-outbox` 的旧 CLI/job，确认没有在途 maintenance 进程。
2. 在受控 DB owner 路径 inventory 历史 outbox DLX：保存 tenant、event id、domain、contract id、`dlx_at`
   与状态计数到受控审计存储；不导出 payload/metadata，不把 inventory 写入普通日志或工单。
3. 在 primary DB host 以 DB owner 运行 `docs/ops/0060-outbox-capacity-gate.sh` 并取得 PASS；同时确认无长事务
   持有 outbox/inbox DDL 锁且维护窗口覆盖全表 deadline 回填，再运行唯一 migration runner。0060 使用同一
   cutover timestamp 给所有历史 outbox 行写两个 deadline，因此历史 pending/publishing/DLX 在 cutover 后
   立即过期，不能再获得新的 24h redrive 窗口。
4. 验证 policy 恰有一行且值为 `86400/86400/86400/604800`，所有历史 outbox deadline 等于 cutover；验证
   `rss_app` 对 `rss_outbox_redrive(text,uuid)` 无 EXECUTE、maintenance owner 为函数 owner，旧
   `rss_sweep_inbox_receipts(bigint)` 不存在且零参数函数存在。
5. 仅在上述检查通过后启动新 binary/relay。历史 DLX 保留用于审计与业务恢复决策，但 same-ID redrive
   永久返回 `Expired`；不得加兼容函数、deadline reset 或临时旧 binary 路径。

### 0060 容量、WAL/archive 与 replica gate

本节是 0060 rollout 说明的单一事实源；migration README 只链接本节。脚本
`docs/ops/0060-outbox-capacity-gate.sh` 是所有可执行阈值的单一事实源，修改阈值时必须先改脚本，再同步本节的
operator 解释。

10 GiB 只是 outbox 表尺寸上限。全表 `UPDATE` 的固定预算是 data tuple/关系膨胀 12 GiB、WAL 20 GiB、archive
20 GiB，并在每个独立 filesystem 额外保留 5 GiB emergency reserve。开始 migration 前最小 free 为：

| filesystem 布局 | 最小 free |
|---|---:|
| data + `pg_wal` + local archive/spool 共盘 | 57 GiB |
| data + `pg_wal` 共盘，archive 独立/remote | 37 GiB；archive 另有 25 GiB |
| data + archive 共盘，`pg_wal` 独立 | 37 GiB；`pg_wal` 另有 25 GiB |
| `pg_wal` + archive 共盘，data 独立 | 45 GiB；data 另有 17 GiB |
| 三者独立 | data 17 GiB、`pg_wal` 25 GiB、archive 25 GiB |

连接必须使用 libpq 命名 service：`PGSERVICEFILE` 只保存 host/port/db/user/TLS 等非秘密参数，不得包含
`password=`；密码只放在当前 operator 可读的 `PGPASSFILE`，Unix mode 必须为 `0600`。脚本调用 `psql` 时 argv
只含固定 flag 与 SQL，不接收连接 URI。若平台支持 peer 或 workload identity，passfile 可由对应无静态密码的
认证方式取代，但仍不得把 credential 放入 argv。

从仓库根目录执行；`EXPECTED_REPLICAS` 必须与当班 inventory 精确相等。local archive/spool 传实际路径。remote
object archive 除 provider 返回的 available quota 外，必须提供绝对路径 `REMOTE_ARCHIVE_PROBE`；该受控可执行文件
以脚本传入的 exact WAL segment 文件名作为唯一参数，只有 provider 对该同名对象执行 HEAD/read 成功才返回 0。
probe 自身使用 workload identity 或受控环境取认证，不把 provider credential 写入命令行：

```bash
export PGSERVICE=rss-0060-owner
export PGSERVICEFILE=/etc/rss/pg_service.conf
export PGPASSFILE=/run/secrets/rss-0060.pgpass
chmod 0600 "$PGPASSFILE"

EXPECTED_REPLICAS=2 WAL_ARCHIVE_DIR=/srv/postgres/archive \
  docs/ops/0060-outbox-capacity-gate.sh

# remote object archive 示例：25 GiB = 26843545600 bytes
EXPECTED_REPLICAS=2 \
  REMOTE_ARCHIVE_FREE_BYTES=26843545600 \
  REMOTE_ARCHIVE_PROBE=/usr/local/libexec/rss-wal-archive-head \
  docs/ops/0060-outbox-capacity-gate.sh
```

脚本先执行固定内容的非事务
`pg_logical_emit_message(false, 'rss.0060-capacity-gate', 'archive-probe')` 产生一条不含 tenant/event/credential 的
WAL record，且不创建持久数据库对象；随后才以 `pg_walfile_name(pg_switch_wal())` 冻结刚完成的目标 WAL 文件名。
这一顺序排除 idle switch 返回 segment boundary、进而误命中上一已归档文件的陈旧证明。local archive 必须出现
同名普通文件，remote archive 的 provider probe 必须确认同名对象；只有 destination 中 exact segment 可读才
放行。`last_archived_wal` 仅作诊断：繁忙主库可能在轮询前已推进到后续段，不能作为 equality 授权条件；
`archived_count` 增长同样不能替代 exact-segment 证明。证明期间 `failed_count` 或 statistics reset 变化均拒绝
rollout。

所有预期 replica 必须为 `streaming` 且 byte lag ≤256 MiB。非 NULL `replay_lag` 必须 ≤60s；NULL 仅在同一 SQL
快照内 `byte_lag=0` 且 `reply_time` 不早于检查时刻 60s 时代表健康，其它 NULL fail-closed。托管数据库的 PGDATA
不可从本地读取时，用 primary/provider 等价命令留存同样三项容量证据；不得只检查
`pg_total_relation_size('outbox') <= 10 GiB`。

### 0060 迁移中监控与中止阈值

开始唯一正式 runner 后每 15s 采样一次。SQLx 在同一 session 上持有 database-scoped exclusive advisory lock，
覆盖整个 migrator run；因此 runner 身份以该 session lock 为准，不能依赖只在回填期间出现的 SQL 文本。旧
runtime/CLI 已按 rollout 前置步骤停止后，以下查询必须恰好返回一行，再把该 `pid` 一次性记录为
`MIGRATION_PID`。0 行表示 runner 尚未持锁，>1 行表示 owner session 不唯一；两者都 fail-closed，不能猜 PID 或
批量取消：

```sql
SELECT DISTINCT activity.pid,
       activity.xact_start,
       CASE WHEN activity.xact_start IS NULL THEN NULL
            ELSE clock_timestamp() - activity.xact_start END AS transaction_runtime,
       activity.state,
       activity.wait_event_type,
       activity.wait_event
FROM pg_stat_activity AS activity
JOIN pg_locks AS held_lock ON held_lock.pid = activity.pid
WHERE activity.datname = current_database()
  AND activity.usename = current_user
  AND activity.application_name = 'rss-postgres-migrator'
  AND held_lock.locktype = 'advisory'
  AND held_lock.mode = 'ExclusiveLock'
  AND held_lock.granted;

SELECT archived_count, failed_count, last_archived_wal, last_archived_time,
       last_failed_wal, last_failed_time, stats_reset
FROM pg_stat_archiver;

SELECT application_name, state, sync_state,
       pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS byte_lag,
       replay_lag, reply_time
FROM pg_stat_replication;
```

advisory lock 在 0060 提交后、0061 validation 开始前仍由同一 session/PID 持有；这个短暂间隙允许
`xact_start IS NULL`，但不允许重新选择 PID。0060 与 0061 各自进入 transaction 后都以各自的 `xact_start` 计时，
watchdog 因此覆盖 deadline 回填、约束安装、validation 与 ledger 写入，而不是只覆盖 `UPDATE outbox`。

local archive 部署在 primary host 同时执行
`while sleep 15; do df -h "$PGDATA" "$PGDATA/pg_wal" "$WAL_ARCHIVE_DIR"; done`；remote archive 使用 provider
容量面板。触发以下任一条件就取消已记录的**单一** PID：

- 任一 data/WAL/archive filesystem free <5 GiB；
- `pg_stat_archiver.failed_count` 高于预检 baseline，或 primary WAL 仍前进但 archive 连续 120s 无进展；
- 任一预期 replica 非 `streaming`；
- replica byte lag >5 GiB 或 replay lag >5min，连续两个 15s 样本；
- 当前 0060 或 0061 transaction runtime（从非 NULL `xact_start` 计算）≥4m30s，在 5min statement timeout 前
  留出回滚时间。

```bash
case "$MIGRATION_PID" in ''|*[!0-9]*) exit 2 ;; esac
psql -X -v ON_ERROR_STOP=1 -v pid="$MIGRATION_PID" \
  -c 'SELECT pg_cancel_backend(:pid);'
psql -X -v ON_ERROR_STOP=1 \
  -c 'SELECT version, success FROM _sqlx_migrations WHERE version IN (60, 61) ORDER BY version;'
```

取消/timeout 后当前 migration transaction 必须整体回滚：若取消发生在 0060，ledger 不得有 version 60 success
行；若发生在 0061 validation，version 60 可以已成功，但 version 61 不得成功。两种情况都保持旧 relay/CLI
停止；恢复空间、archive 或 replica 后只能让正式 runner 从 ledger 状态继续。禁止手工提交部分 deadline 回填、
伪造 ledger、修改已执行 migration 或临时恢复旧函数。
