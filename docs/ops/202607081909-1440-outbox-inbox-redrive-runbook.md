# #1440 Outbox / Inbox DLQ Redrive Runbook

ref: GoCell framework/kernel/outbox/state.go@043add59bbe840e4a90a4253feec21f074b590dd

## Scope

本 runbook 覆盖 runtime operator CLI：

- `rss dlq list`
- `rss dlq inspect`
- `rss dlq replay-dead-letter`
- `rss dlq redrive-outbox`

v1 不提供 destructive `skip`。partition unblock 只通过 redrive outbox DLX 队头完成；队头重新发布成功后，后继按 outbox partition order 正常 poll。

## Preconditions

必须先确认：

- operator service token 可被 PDP 验证。
- operator service token 的 `jti` 由 Postgres `service_token_replay_nonces` 持久记录；同一 token 跨 CLI 进程重放会被拒绝。
- 命令带 `--operator-service-token`、`--operator-tenant`、`--tenant`。
- 环境变量 `RSS_DLQ_OPERATOR_GRANTS` 包含精确 grant：`subject|action|tenant`。
- 仅 `replay-dead-letter` 需要 DLQ payload 解密依赖：`RSS_DLX_PAYLOAD_KEY_NAME`、`RSS_VAULT_ADDR`、`RSS_VAULT_TOKEN`、`RSS_VAULT_TRANSIT_MOUNT`。`list`、`inspect` 与 `redrive-outbox` 不依赖 payload key provider。

审计固定写入：

- kind: `dlq.maintenance`
- action: `dlq.<action>.start|finish`

## Commands

列出当前租户 DLQ：

```bash
export TOKEN='<operator-service-token>'
export OPERATOR_TENANT='00000000-0000-4000-8000-000000000001'
export TENANT='00000000-0000-4000-8000-000000000002'
export RSS_DLQ_OPERATOR_GRANTS="ops-subject|list|$TENANT"

rss dlq list \
  --operator-service-token "$TOKEN" \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --source outbox_relay \
  --domain identity \
  --contract-id identity.session-created \
  --limit 50
```

`list` / `inspect` 的每条 DLQ summary 输出为一行 JSON（JSONL）：自由文本字段（如 `errorSummary`）不参与空格分隔解析。

检查 outbox DLX 行：

```bash
rss dlq inspect \
  --operator-service-token "$TOKEN" \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --kind outbox-dlx \
  --id "$EVENT_ID"
```

重放 consumer `dead_letter`：

```bash
rss dlq replay-dead-letter \
  --operator-service-token "$TOKEN" \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --dead-letter-id "$DEAD_LETTER_ID" \
  --replay-id "$NEW_OUTBOX_EVENT_ID"
```

redrive outbox DLX：

```bash
rss dlq redrive-outbox \
  --operator-service-token "$TOKEN" \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --event-id "$EVENT_ID"
```

## Partition Blocked

告警 `OutboxPartitionBlocked` 触发时：

1. 设置通用环境：

```bash
export TOKEN='<operator-service-token>'
export OPERATOR_TENANT='<operator-tenant-uuid>'
export TENANT='<tenant-uuid-from-alert-label>'
export DOMAIN='<domain-from-alert-label>'
export CONTRACT_ID='<contract_id-from-alert-label>'
export RSS_DLQ_OPERATOR_GRANTS="ops-subject|list|$TENANT,ops-subject|inspect|$TENANT,ops-subject|redrive-outbox|$TENANT"
```

2. 找当前 tenant/domain/contract 的 outbox DLX 队头候选：

```bash
rss dlq list \
  --operator-service-token "$TOKEN" \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --source outbox_relay \
  --domain "$DOMAIN" \
  --contract-id "$CONTRACT_ID" \
  --limit 20
```

若命令尾行显示 `has_more=true`，读取 `next_cursor` 后带 `--cursor "$NEXT_CURSOR"` 续页，直到 `has_more=false`。不要用 offset，也不要假设单页覆盖完整 DLQ。outbox DLX 的 `last_attempt` 展示、降序排序和 cursor 均以权威终态时间 `dlx_at` 为单源；后续租约或运维写入导致的 `updated_at` 变化不得改变队列顺序。

3. 核对 `contract_id`、`error_summary`、attempts：

```bash
rss dlq inspect \
  --operator-service-token "$TOKEN" \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --kind outbox-dlx \
  --id "$EVENT_ID"
```

4. 修复导致 DLX 的上游问题；若 payload/schema/tenant envelope 仍非法，不要 redrive。
5. 执行 redrive：

```bash
rss dlq redrive-outbox \
  --operator-service-token "$TOKEN" \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$TENANT" \
  --event-id "$EVENT_ID"
```

6. 等 relay 发布该队头，再观察 `outbox_partition_blocked_depth{tenant_id,domain,contract_id}` 回到 0。

`partition_key` 不在 metric、CLI 输出或 audit resource id 中暴露。需要精确定位时，用 event id 在受控 DB 访问路径中检查。

## Metrics

- `outbox_partition_blocked_depth{domain,contract_id,tenant_id}`：blocked 后继行数。
- `dlq_redrive_total{tenant_id,kind,outcome}`：operator mutation 结果；`kind=dead_letter_replay|outbox_dlx_redrive`。该计数只在进程安装 metrics recorder 时可采集；`rss dlq` 是一次性 operator 进程，不承诺 Prometheus scrape 面，长期告警以 relay/consumer 常驻进程 metric 与 `dlq.maintenance` audit/log 为准。
- `outbox_publish_total{status="requeue|reject"}`：broker publish transient/permanent 处置。
- `outbox_relay_envelope_validation_failure_total{reason}`：本地 envelope/schema header gate。
- `consumer_lease_lost_total{domain}`：consumer inbox lease hard-fence。

`dlq_redrive_total{outcome="not_found"}` 对 outbox redrive 表示未 mutation，常见原因是 wrong tenant、目标非 DLX 或已被其它 operator redrive。

## Failure Handling

- `NotFound`：先核对 `--tenant` 与 id；wrong-tenant redrive 不泄漏存在性。
- `NotReplayable`：`outbox_relay`、`saga`、`projection` dead_letter 不支持 replay 成 outbox。
- `InvalidSchemaHeaders` / `InvalidPayload`：先修数据/代码，不要重复 replay。
- `PayloadKeyUnavailable` / `PayloadKeyForbidden`：恢复 Vault/key provider 后重试。
- `Store`：检查 Postgres、RLS、SECURITY DEFINER 函数权限和 migration 版本。

成功 redrive 不删除 `dead_letter` 审计行，不修改 payload/schema/seq/partition，只把 outbox DLX 行恢复为 `pending`，清 retry/lease，并同时清空 `published_at`、`dlx_at`；旧 DLX 历史继续由 append-only `dead_letter` 审计行保存。
