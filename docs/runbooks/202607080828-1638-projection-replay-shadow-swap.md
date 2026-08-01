# Projection Replay / Shadow Swap Runbook

适用范围：`rss projections replay|status|swap` 通用控制面。它只控制 projection shadow replay 与 active pointer promotion，不包含具体业务 read-model 表改造。

## 前置条件与权限边界

- migration 必须由独立 singleton `rss postgres migrate-all` Job 预先推进到当前 HEAD；Projection CLI 不执行
  migration，也不接受 migrator/serving 凭据。
- Projection CLI 只读取固定路径
  `/var/run/rss/secrets/projection-operator-secret-bundle`；不得挂载
  `/var/run/rss/secrets/serving-secret-bundle`。binary 在 dispatch 时先铸造独立
  `ProjectionOperatorRuntimeInputs`，generic operator/serving runtime input 不能进入 Projection 入口。
- CLI 同时连接两个不可互换的 PostgreSQL 角色：`rss_projection_reader` 只调用 scoped source read/high-water 函数，
  `rss_projection_operator` 只调用 checkpoint/CAS/DLX/audit/token-replay 及已 enrollment target 的固定 apply
  函数。两者均无 raw table 权限，apply 函数不接收 raw payload/config value，
  任一 exact role/config/ACL/function-set 探针漂移都会在命令执行前失败。
- operator 必须用专属 ES256 token 通过生产 PDP 验证：`--operator-service-token-stdin` 从标准输入读取 token，配合
  `--operator-tenant`；token 固定 `typ=rss-projection-operator+jwt`、
  `token_use=projection-operator`，签名内 canonical `tenant_id` 必须与参数一致，typed caller 必须是
  `ServiceCallerDomain::MaintenanceOperator`（canonical `sub=rss-maintenance-operator`）。
- operator 必须被显式授权到目标 action/tenant/projection：`RSS_PROJECTION_MAINTENANCE_OPERATOR_GRANTS=action|tenant|projection`，多条用逗号分隔；`action` 只能是 `status`、`replay`、`swap`，caller 不从配置字符串选择。
- projection id 必须来自 sealed assembly `WorkflowRuntimePlan` 的 `ProjectionTargetView`；target 会铸造绑定
  tenant、projection id、definition version/schema digest 与 input generation 的不可伪造 source scope。generated definition
  存在不代表已激活，unknown、disabled 与 omitted selector 都在 PostgreSQL/Vault/replay 初始化前 fail-closed。
- `replay`/`swap` 要求 plan 精确选中 production projection target；不存在 blanket unsupported marker 或
  generated-catalog fallback。`status` 使用同一 target view。
- replay DLQ 复用 `dead_letter`，需要 Vault transit DLQ 配置：`RSS_DLX_PAYLOAD_KEY_NAME`、`RSS_VAULT_ADDR`、`RSS_VAULT_TRANSIT_MOUNT` 与 operator bundle 的 `replayVaultToken`；legacy `RSS_VAULT_TOKEN` 会 fail closed。
- 当前 assembly target view 为空时，生产 replay/swap/status 在任何 provider 初始化前早失败；fixture 测试
  负责证明非空 exact-set registry 行为不空转。
- `settings.config-projection` 的 PostgreSQL target 已具备 production 权限与 T2 replay 闭环，但 #1919 不激活
  production assembly。只有 #1920 发布的 worker/probe/start/readiness/drain 与 shadow activation 到位后，才可
  对 production Settings 执行本 runbook；#1921 promotion 前不得把 Settings v4 authoritative reads 切到投影。

## Env Matrix

| Group | Required env | Notes |
|---|---|---|
| Projection source | `RSS_PG_HOST`, `RSS_PG_PORT`, `RSS_PG_DATABASE`, `RSS_PG_PROJECTION_READER_USERNAME=rss_projection_reader` + bundle `pgProjectionReaderPasswordFile` | tenant/projection/definition/generation scoped event read + `rss_projection_source_high_water_scoped`；bundle 只保存绝对只读密码文件路径，不保存数据库密码；inline password、password-file env 与双源均拒绝。 |
| Projection control | `RSS_PG_PROJECTION_OPERATOR_USERNAME=rss_projection_operator` + bundle `pgProjectionOperatorPasswordFile` | function-only checkpoint/CAS/DLX/audit/token-replay + enrolled target apply；不继承 reader、serving、raw projection table 或 migrator 权限。 |
| Postgres TLS | `RSS_PG_SSL_ROOT_CERT_PATH` | **必填** trust-anchor PEM。`RSS_PG_SSL_MODE` 已禁止（#1710）；始终 `VerifyFull`。 |
| Projection operator verifier | `RSS_PROJECTION_OPERATOR_TOKEN_ISSUER`, `RSS_PROJECTION_OPERATOR_TOKEN_AUDIENCE`, `RSS_PROJECTION_OPERATOR_TOKEN_JWKS_PATH`, `RSS_PROJECTION_OPERATOR_TOKEN_JWKS_REFRESH_INTERVAL_SECS` | verifier-only ES256/JWKS profile；运行时只持公钥与 durable replay store，没有 signer、共享 secret 或 `RSS_SERVICE_TOKEN_*` fallback。 |
| Projection authorization | `RSS_PROJECTION_MAINTENANCE_OPERATOR_GRANTS` | typed maintenance caller 认证后的精确三元组 `action|tenant|projection`；无 caller 字符串、无 wildcard。 |
| Projection DLQ Vault | `RSS_DLX_PAYLOAD_KEY_NAME`, `RSS_VAULT_ADDR`, `RSS_VAULT_TRANSIT_MOUNT` + bundle `replayVaultToken` | replay 遇 poison 会写 projection DLQ；只构造 hot/replay provider，不读取 archive/general Vault token；token env 被禁止。 |
| Vault TLS | `RSS_VAULT_CA_CERT_PEM_PATH` | 可选；私有 CA 时配置 PEM bundle。 |

专属 carrier 是 `deny_unknown_fields` 的闭合 JSON，三个字段全部必填、非空；没有旧字段、环境 fallback
或 dual-read：

```json
{
  "pgProjectionReaderPasswordFile": "/run/secrets/projection-reader-password",
  "pgProjectionOperatorPasswordFile": "/run/secrets/projection-operator-password",
  "replayVaultToken": "<Vault token limited to the replay DLQ key>"
}
```

环境中出现 `RSS_PG_PROJECTION_READER_PASSWORD`、`RSS_PG_PROJECTION_OPERATOR_PASSWORD`、两个
projection password-file 变量、`RSS_SERVICE_TOKEN_HS256_SECRET_B64URL` 或
`RSS_DLX_HOT_VAULT_TOKEN` 时，快照捕获立即失败；serving secret 环境词表（含 general/archive
Vault、Redis、AMQP、S3 与 serving PostgreSQL secret）同样全部禁用。Compose 的 opt-in `projection-operator` profile
只挂载此 carrier、两份数据库密码文件、专属公钥 JWKS 以及 PostgreSQL/Vault CA；server 不挂载任何
Projection 专属 carrier。`RSS_SERVICE_TOKEN_ISSUER/AUDIENCE/HS256_KID` 即使存在于共享部署环境也不在
Projection 快照目录中，不能影响该 verifier。

`0087 → 0088` 必须按 [`migrations/README.md`](../../adapters/postgres/migrations/README.md) 的 0088 章节执行
non-rolling cutover：冻结并缩容 projection append writer、source reader/operator 后，完成同次 session/lock、
journal/index-space、data/`pg_wal`、archive/replica lag 与 maintenance-window preflight；只有 ledger、index
definition/state 和 exact function ACL postflight 全部通过，才可启动 0088-compatible binary。该 rollout receipt
是 T2 运维门，不新增 T3 carrier；容量 envelope 仍由 #1922 持有。

## Replay Shadow Version

Replay 的 reader 函数在数据库内先按完整 source scope 过滤，再返回 matching events；operator 凭据本身不能
读取 payload。命令写 shadow read-model target 和 shadow checkpoint：

```bash
export RSS_OPERATOR_SERVICE_TOKEN_FILE='/run/secrets/rss-projection-operator-service-token'

rss projections replay \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" \
  --batch-size 1000 < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

预期：输出 `operation=replay ... scanned=<n> matched=<n> applied=<n> duplicates=<n> filtered=<n> skipped=<n> dlq=<n> stop=completed failed_at_lsn=none skipped_at_lsn=none kind=none reason=none`。其中 `matched = applied + duplicates`；`duplicates` 是 target 已提交且 receipt 与稳定事实 digest 一致的重放，业务效果不会重复创建。`filtered` 是同一 source stream 中真正不匹配当前 selector 的事件；它们不写 read-model target，但会推进 shadow checkpoint。Replay 会循环读取批次直到最后一批小于 `--batch-size` 或遇到非 completed stop；Replay 不写 `distributed_cas` active pointer，因此线上 active version 不变。

## Check Active Pointer

```bash
rss projections status \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

记录输出里的 `active_version`、`high_water_lsn`、`selected_shadow_high_water_lsn`、`source_high_water_lsn`、`token`。`--version` 是 selector 必填项，用来读取所选 shadow checkpoint；active pointer key 仍只按 tenant + projection 定位。

`source_high_water_lsn` 来自固定七参数函数 `rss_projection_source_high_water_scoped`。CLI 内部先用独立 operator
凭据为 tenant/projection/definitionVersion/definitionSchemaDigest/inputGeneration 签发一次性 opaque capability，再由
source-reader 凭据携带 capability 的两个 UUID half 调用函数；不得手工复用 token、让 reader 调 issuer，或退回旧
五参数函数。token 固定 30 秒过期；签发后 source 故障产生的 orphan 由 operator-only
`rss_projection_operator_sweep_source_capabilities()` 每次最多回收 1000 行，禁止延长 TTL 或直接改表。它对 sealed
source scope 的每个静态 binding 做 indexed tail seek，不分页扫描历史；有效 scope
尚无已提交事件时返回 typed `None`，CLI status 可显示 `source_high_water_lsn=none` 供诊断。missing/unknown
scope 或 capability 不合法不是 `None`：数据库返回 SQLSTATE `22023`，控制面保留 typed
`SourceScopeInvalid` 并 fail closed，禁止自动
重试、降级到 global tail 或改 scope 猜测重试。100,000 行无关历史上的真实 PostgreSQL buffer regression 只证明
这条 T2 fixed-cost seam，不是 production/T3 成功回执。

## Promote Shadow Version

首次 promote 必须显式声明当前指针未设置：

```bash
rss projections swap \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" \
  --expect-unset < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

已有 active version 时必须按当前版本做 CAS precondition：

```bash
rss projections swap \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" \
  --expected-active-version "$OLD_VERSION" < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

`--expected-active-version` 和 `--expect-unset` 必须且只能出现一个。swap 会在 CAS 前重新读取 source high-water；
如果目标 shadow checkpoint 落后于 source high-water，会以
`projection shadow checkpoint is behind source high-water` 拒绝 promote。status 可以显示 valid-empty `None`，
但 swap 必须以 `projection source high-water is missing; promotion requires a committed source position` 拒绝
`None`；即使存在旧 checkpoint、checkpoint 为 `0` 或 operator 认为空流已追平，也不能 promote。等待完整 scope
出现首个 committed source position，再重新 status/replay。stale / concurrent swap 返回 conflict 或
precondition failure，不能重试为弱 promote；先重新 `status` 确认当前 active。fixed-cost high-water 不证明该
读取与后续 pointer CAS 原子，promote TOCTOU 由 #1921 持有。

## Rollback

Rollback 不删除 shadow data，不回退 checkpoint。线上事件可能已在 `$NEW_VERSION` active 后继续写入，因此必须先把旧 shadow version 追到 source 尾部，再 swap 回上一版本。

先 replay 旧版本：

```bash
rss projections replay \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$OLD_VERSION" \
  --batch-size 1000 < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

再 status，确认 `selector_version=$OLD_VERSION` 且 `selected_shadow_high_water_lsn` 已追到 `source_high_water_lsn`：

```bash
rss projections status \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$OLD_VERSION" < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

最后按 runbook swap 回上一版本：

```bash
rss projections swap \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$OLD_VERSION" \
  --expected-active-version "$NEW_VERSION" < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

完成后再执行 `status`，确认 `active_version=$OLD_VERSION`。保留失败版本的 shadow checkpoint 和 DLQ 记录供诊断。

## Failure Handling

- `postgres projection source reader capability is not exact`：reader role、只读/search_path 配置、ledger SELECT、
  scoped event/high-water function EXECUTE 或无额外权限约束发生漂移；撤销多余 ACL/role config，并恢复精确角色后重试，禁止换成
  serving/migrator 凭据。
- high-water 调用遇到 missing/unknown source scope：tenant 之外的 projection/definition version/schema
  digest/input generation 未命中完整静态 binding 集；SQLSTATE `22023` 是 permanent/invariant identity drift，
  不可重试，不能当成空 source、transient DB failure 或回退到全局尾部。修正 sealed assembly target 后整体重新部署。
- `source_high_water_lsn=none`：仅表示已验证的完整 source scope 尚无已提交事件，typed 结果为 `None`；status
  可展示该诊断值，但 promote 必须拒绝。不得用旧 checkpoint、零 checkpoint 或“空流已追平”推导 promote 成功。
- `projection source high-water is missing; promotion requires a committed source position`：valid-empty scope
  尚未产生可比较的 committed position；保持 active pointer 不变，等待首个 committed source event 后重新
  status/replay，不得自动重试 swap。
- `postgres projection operator capability is not exact`：operator 获得了额外 relation/routine 权限，或固定函数
  集、role 属性/search_path 漂移；恢复 function-only exact set 后重试，禁止授 raw 表权限临时绕过。
- `build assembly-plan projection target registry` / `validate assembly-plan projection target registry coverage`：部署 artifact 的 sealed RuntimePlan 与 binary typed capability 不一致；修正 assembly plan 或 capability wiring 后重新构建并部署。该错误在 PostgreSQL/Vault 初始化前终止。
- `projection is not activated by the assembly plan`：selector 对应的 workflow 被 omitted/disabled，或 identity/mode/version/schema digest 不匹配。核对部署的 RuntimePlan 并激活精确 workflow；`status`、`replay`、`swap` 均不会绕过此检查，且在 provider 初始化前终止。
- `projection target is not activated by the assembly plan`：workflow 已声明但 sealed plan 没有签发匹配 target；核对 shadow/active activation 与完整 typed runtime capability，重新构建并部署，不得从 generated definition ledger 手工补注册。
- `projection is not generated for this runtime` / `projection target is not replayable by this runtime` / `projection target is not swappable by this runtime`：已选择 workflow 的 generated definition、inputs 或 target capability 与命令不一致；修正 codegen 输入或 assembly capability 后整体重新部署，不得使用 unsupported marker 或 raw registry fallback。
- `projection shadow checkpoint is missing`：先成功 replay 目标 version，再 swap。
- `projection shadow checkpoint is behind source high-water`：目标 shadow version 尚未追到 source 尾部；重新 replay 到 `selected_shadow_high_water_lsn == source_high_water_lsn` 后再 swap。
- `projection active pointer precondition failed`：当前 active 与命令声明不一致；执行 `status` 后按实际版本重新决定。
- `projection active pointer CAS conflict`：并发 promote 或 stale token；执行 `status` 后人工复核。
- `stop=apply_failed`：同时检查 `kind` 与 `reason`。`transient` 可在依赖恢复后重跑 replay；`permanent`/`invariant` 先查 `dead_letter` 中 projection DLQ 记录，`reason=conflict` 表示同一 dedupe key 对应不同事实，`reason=out_of_order` 表示未见过的事件低于 target 持久 high-water，二者都必须修正数据或 store 后再继续。
- Settings apply 的精确 `reason` 是稳定 snake_case 闭集：`target_definition_drift`、
  `input_binding_drift`、`tenant_drift`、`payload_malformed`、`payload_value_invalid`、
  `version_regression`、`provider_invariant`、`provider_permanent`、`conflict` 与 `out_of_order`。
  Stop、projection DLQ summary 与 CLI 必须显示同一值；前三类漂移及 provider invariant 属于 `invariant`，
  payload/version/provider permanent 属于 `permanent`。修正 sealed plan、源事实或 provider，禁止改 ACL、
  伪造 metadata 或绕过固定函数；poison DLQ 成功前 checkpoint 不越过该 LSN。
- `kind=commit_unknown reason=commit_unknown`：事务可能已经提交但 ACK 丢失；checkpoint 不会推进，也不会写 poison DLQ。禁止 swap，以完全相同的 selector 与事实重跑 replay；正确 target 应返回 `Duplicate`，最终只保留一个业务效果和一个 receipt。
- `kind=rollback_failed reason=rollback_failed`：回滚结果无法确认；checkpoint 不推进且不写 poison DLQ。禁止自动 skip 或盲目重试，先核实 provider 事务状态并恢复可判定性，再以同一事实重放收敛。
- `stop=out_of_order`：source 顺序不满足 projection serial witness；禁止 swap，升级排查 projection_events 读取顺序和数据完整性。
- `stop=fenced`：有并发 replay 推进同一 shadow checkpoint；重新 `status` 后只保留一个 operator 继续。
- `stop=checkpoint_unsaved`：target apply 可能已生效但 checkpoint 未保存；确认 target 幂等后重跑 replay。
- `stop=dead_letter_unsaved`：poison DLQ 写失败；先恢复 Vault/DLQ 依赖，再重跑 replay。
- `stop=source_read_failed`：projection_events 读取失败；按 infra transient/invariant 分类处理后重跑。
- `stop=checkpoint_unread`：shadow checkpoint 读取失败；恢复 checkpoint store 后重跑，不能把失败降级为从头 replay。
- 任意 `stop != completed` 都禁止 swap；先处理 stop 原因，直到 replay 输出 `stop=completed` 且 status 高水位符合预期。
