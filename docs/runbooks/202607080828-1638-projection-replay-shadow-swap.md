# Projection Replay / Shadow Swap Runbook

适用范围：`rss projections replay|status|swap` 通用控制面。它只控制 projection shadow replay 与 active pointer promotion，不包含具体业务 read-model 表改造。

## 前置条件

- 使用维护/迁移 Postgres 配置运行 CLI；命令会执行 migration 并写 `auth_audit_events`。
- operator 必须用 service token 通过生产 PDP 验证：`--operator-service-token` + `--operator-tenant`；
  typed caller 必须是 `ServiceCallerDomain::MaintenanceOperator`
  （canonical `sub=rss-maintenance-operator`）。
- operator 必须被显式授权到目标 action/tenant/projection：`RSS_PROJECTION_MAINTENANCE_OPERATOR_GRANTS=action|tenant|projection`，多条用逗号分隔；`action` 只能是 `status`、`replay`、`swap`，caller 不从配置字符串选择。
- projection id 必须来自 `generated::event::PROJECTION_INPUTS` 对应的 runtime registry；未知 id fail-closed。
- `replay`/`swap` 还要求当前 binary 至少注册一个 production projection target；只有 unsupported marker 的 runtime 会 fail-closed。`status` 仍可读取 active pointer 和 high-water。
- replay DLQ 复用 `dead_letter`，需要 Vault transit DLQ 配置：`RSS_DLX_PAYLOAD_KEY_NAME`、`RSS_VAULT_ADDR`、`RSS_VAULT_TOKEN`、`RSS_VAULT_TRANSIT_MOUNT`。
- 当前如果 `PROJECTION_INPUTS` 为空，生产 replay/swap/status 会以 `no generated projection inputs compiled into this runtime` 早失败；fixture 测试负责证明 registry 行为非空转。

## Env Matrix

| Group | Required env | Notes |
|---|---|---|
| Postgres maintenance | `RSS_PG_HOST`, `RSS_PG_PORT`, `RSS_PG_DATABASE`, `RSS_PG_MIGRATOR_USERNAME`, `RSS_PG_MIGRATOR_PASSWORD_FILE` | 维护 CLI 只从绝对只读文件读取窄角色口令；raw env 与双源均拒绝。 |
| Postgres TLS | `RSS_PG_SSL_MODE`, `RSS_PG_SSL_ROOT_CERT_PATH` | 可选；未配置时默认 `verify-full`。本地无 TLS 只能显式降级。 |
| Service-token verifier | `RSS_SERVICE_TOKEN_ISSUER`, `RSS_SERVICE_TOKEN_AUDIENCE`, `RSS_SERVICE_TOKEN_HS256_SECRET_B64URL`, `RSS_SERVICE_TOKEN_HS256_KID` | projection CLI 验证 `--operator-service-token`；缺 issuer/audience/key 会 fail-fast。 |
| Projection authorization | `RSS_PROJECTION_MAINTENANCE_OPERATOR_GRANTS` | typed maintenance caller 认证后的精确三元组 `action|tenant|projection`；无 caller 字符串、无 wildcard。 |
| Projection DLQ Vault | `RSS_DLX_PAYLOAD_KEY_NAME`, `RSS_VAULT_ADDR`, `RSS_VAULT_TOKEN`, `RSS_VAULT_TRANSIT_MOUNT` | replay 遇 poison 会写 projection DLQ；缺失会在构造 DLQ payload protector 时失败。 |
| Vault TLS | `RSS_VAULT_CA_CERT_PEM_PATH` | 可选；私有 CA 时配置 PEM bundle。 |

## Replay Shadow Version

Replay 只从 `projection_events` 读取 matching tenant/projection input events，写 shadow read-model target 和 shadow checkpoint：

```bash
rss projections replay \
  --operator-service-token "$RSS_OPERATOR_SERVICE_TOKEN" \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" \
  --batch-size 1000
```

预期：输出 `operation=replay ... scanned=<n> matched=<n> applied=<n> filtered=<n> skipped=<n> dlq=<n> stop=completed failed_at_lsn=none skipped_at_lsn=none kind=none`。`filtered` 是同一 source stream 中不匹配当前 selector 的事件；它们不写 read-model target，但会推进 shadow checkpoint。Replay 会循环读取批次直到最后一批小于 `--batch-size` 或遇到非 completed stop；Replay 不写 `distributed_cas` active pointer，因此线上 active version 不变。

## Check Active Pointer

```bash
rss projections status \
  --operator-service-token "$RSS_OPERATOR_SERVICE_TOKEN" \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION"
```

记录输出里的 `active_version`、`high_water_lsn`、`selected_shadow_high_water_lsn`、`source_high_water_lsn`、`token`。`--version` 是 selector 必填项，用来读取所选 shadow checkpoint；active pointer key 仍只按 tenant + projection 定位。

## Promote Shadow Version

首次 promote 必须显式声明当前指针未设置：

```bash
rss projections swap \
  --operator-service-token "$RSS_OPERATOR_SERVICE_TOKEN" \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" \
  --expect-unset
```

已有 active version 时必须按当前版本做 CAS precondition：

```bash
rss projections swap \
  --operator-service-token "$RSS_OPERATOR_SERVICE_TOKEN" \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" \
  --expected-active-version "$OLD_VERSION"
```

`--expected-active-version` 和 `--expect-unset` 必须且只能出现一个。swap 会在 CAS 前重新读取 source high-water；如果目标 shadow checkpoint 落后于 source high-water，会以 `projection shadow checkpoint is behind source high-water` 拒绝 promote。stale / concurrent swap 返回 conflict 或 precondition failure，不能重试为弱 promote；先重新 `status` 确认当前 active。

## Rollback

Rollback 不删除 shadow data，不回退 checkpoint。线上事件可能已在 `$NEW_VERSION` active 后继续写入，因此必须先把旧 shadow version 追到 source 尾部，再 swap 回上一版本。

先 replay 旧版本：

```bash
rss projections replay \
  --operator-service-token "$RSS_OPERATOR_SERVICE_TOKEN" \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$OLD_VERSION" \
  --batch-size 1000
```

再 status，确认 `selector_version=$OLD_VERSION` 且 `selected_shadow_high_water_lsn` 已追到 `source_high_water_lsn`：

```bash
rss projections status \
  --operator-service-token "$RSS_OPERATOR_SERVICE_TOKEN" \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$OLD_VERSION"
```

最后按 runbook swap 回上一版本：

```bash
rss projections swap \
  --operator-service-token "$RSS_OPERATOR_SERVICE_TOKEN" \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$OLD_VERSION" \
  --expected-active-version "$NEW_VERSION"
```

完成后再执行 `status`，确认 `active_version=$OLD_VERSION`。保留失败版本的 shadow checkpoint 和 DLQ 记录供诊断。

## Failure Handling

- `no generated projection inputs compiled into this runtime`：当前 build 没有任何 generated projection workflow input；检查 contract/workflow codegen 和部署 artifact。
- `no registered projection targets compiled into this runtime`：当前 binary 只带 generated registry/unsupported marker，没有任何 production read-model target；只能执行 `status`，不能 replay/swap。
- `unknown projection target`：projection id 不在 generated registry，检查 contract/workflow codegen。
- `projection target is not supported by this runtime`：registry 明确标记 unsupported，不能 promote 或 replay。
- `projection shadow checkpoint is missing`：先成功 replay 目标 version，再 swap。
- `projection shadow checkpoint is behind source high-water`：目标 shadow version 尚未追到 source 尾部；重新 replay 到 `selected_shadow_high_water_lsn == source_high_water_lsn` 后再 swap。
- `projection active pointer precondition failed`：当前 active 与命令声明不一致；执行 `status` 后按实际版本重新决定。
- `projection active pointer CAS conflict`：并发 promote 或 stale token；执行 `status` 后人工复核。
- `stop=apply_failed`：检查 `kind`；`transient` 可在依赖恢复后重跑 replay，`permanent`/`invariant` 先查 `dead_letter` 中 projection DLQ 记录并修正 projector 或数据。
- `stop=out_of_order`：source 顺序不满足 projection serial witness；禁止 swap，升级排查 projection_events 读取顺序和数据完整性。
- `stop=fenced`：有并发 replay 推进同一 shadow checkpoint；重新 `status` 后只保留一个 operator 继续。
- `stop=checkpoint_unsaved`：target apply 可能已生效但 checkpoint 未保存；确认 target 幂等后重跑 replay。
- `stop=dead_letter_unsaved`：poison DLQ 写失败；先恢复 Vault/DLQ 依赖，再重跑 replay。
- `stop=source_read_failed`：projection_events 读取失败；按 infra transient/invariant 分类处理后重跑。
- `stop=checkpoint_unread`：shadow checkpoint 读取失败；恢复 checkpoint store 后重跑，不能把失败降级为从头 replay。
- 任意 `stop != completed` 都禁止 swap；先处理 stop 原因，直到 replay 输出 `stop=completed` 且 status 高水位符合预期。
