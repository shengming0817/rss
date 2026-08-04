# Projection Replay / Active Generation Swap Runbook

适用范围：`rss projections replay|status|swap` 通用控制面。它负责构建 candidate generation，并以原子 swap 选择
active generation；不包含具体业务 read-model 表改造。对 `settings.config-projection`，同一 typed active
selection 同时决定 Settings v3 eventual query 与 background worker 的 generation，Settings v4 authoritative
read 不读取该 selection。

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
- projection id 必须来自 SettingsOnly sealed manifest 新鲜编译并消费 active permit 的
  `SettingsProjectionMaintenancePlan`；target 会铸造绑定
  tenant、projection id、definition version/schema digest 与 input generation 的不可伪造 source scope。generated definition
  存在不代表已激活，unknown、disabled 与 omitted selector 都在任何 status/replay/swap 数据访问前 fail-closed。
- `replay`/`swap` 要求 maintenance plan 精确选中 production projection target；不存在 blanket unsupported marker、
  generated-catalog fallback 或第二套 worker。`status` 使用同一 sealed target registry。
- replay DLQ 复用 `dead_letter`，需要 Vault transit DLQ 配置：`RSS_DLX_PAYLOAD_KEY_NAME`、`RSS_VAULT_ADDR`、`RSS_VAULT_TRANSIT_MOUNT` 与 operator bundle 的 `replayVaultToken`；legacy `RSS_VAULT_TOKEN` 会 fail closed。
- 通用 runtime serving assembly 继续把该 projection 声明为 disabled；生产 `rss projections` 不从它构造
  registry，而是在连接独立 operator/source 凭据后，用 SettingsOnly 同一 manifest/lock 签发的 move-only
  maintenance permit 绑定 exact target。该路径不启动 serving 或 worker。
- SettingsOnly 的 active plan 必须把 exact worker runtime 与同一个 concrete Settings v3 query-service `Arc`
  一次性闭合，并在 inventory seal 前把 callable capability 交给长期 `SettingsProjectionServingDomain`；缺任一
  capability、无人消费或 identity 漂移时 fail-closed。
  Settings v4 始终使用 authoritative repository，不能由 projection pointer、resolver 或 fallback 改写。

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

Settings active serving 的首次 rollout 是 pre-GA non-rolling hard cut：先停止旧 worker 与 projection operator，
再执行当前 migration。migration 删除旧的 Settings projection 派生 generations、rows、dedupe receipts、
candidate-generation checkpoints、quarantine 与 legacy generic-CAS pointer，仅保留可重放 source events 以及独立
DLQ/audit 历史。
不存在旧 JSON pointer parser、backfill、dual-read、alias 或兼容 shim；升级后必须 replay candidate generation，并在
成功 swap 前保持 v3 query fail-closed。旧 binary 不得与新 schema 混跑。

数据库 checkpoint id 的 `:shadow` 后缀是既有持久化编码的历史命名，只表示某个尚未 active 的 candidate
generation checkpoint；它不是独立的 shadow 生命周期、运行模式或 operator 概念。CLI、runbook 与诊断统一使用
`candidate generation` / `candidate-generation checkpoint`。

## Replay Candidate Generation

Replay 的 reader 函数在数据库内先按完整 source scope 过滤，再返回 matching events；operator 凭据本身不能
读取 payload。命令写 candidate generation 的 read-model target 和 candidate-generation checkpoint：

```bash
export RSS_OPERATOR_SERVICE_TOKEN_FILE='/run/secrets/rss-projection-operator-service-token'

rss projections replay \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" \
  --batch-size 1000 \
  --max-events 100000 < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

`--max-events <positive n>` 必填，是本轮有界扫描预算；`--batch-size` 可选。每一批按当前
`remaining = max-events − scanned` 收窄有效 batch，不得一次读超剩余预算。

预期：完整追尾时输出 `operation=replay ... scanned=<n> matched=<n> applied=<n> duplicates=<n> filtered=<n> skipped=<n> dlq=<n> stop=completed failed_at_lsn=none skipped_at_lsn=none kind=none reason=none`。其中 `matched = applied + duplicates`；`duplicates` 是 target 已提交且 receipt 与稳定事实 digest 一致的重放，业务效果不会重复创建。`filtered` 是同一 source stream 中真正不匹配当前 selector 的事件；它们不写 read-model target，但会推进 candidate-generation checkpoint。Replay 会循环读取批次，直到 engine `stop=completed`、遇到非 completed 引擎 stop，或耗尽 `--max-events`（`stop=budget_exhausted`）。`stop=budget_exhausted` 是正常有界退出：checkpoint 保留，可用同一 selector 继续加预算续跑；但预算耗尽本身不证明 candidate generation 已追平，不能据此 swap——必须直到 engine `stop=completed` 且现有 identity/high-water precondition 满足。Replay 不更新 typed active selection，因此 v3 serving 与 active worker 仍使用 swap 前捕获的 active generation。CLI replay 不发 worker metric。

### Recover a quarantined tenant

background worker 遇到 tenant-scoped permanent/invariant/rollback-failed/out-of-order stop 时，会持久化
`state=quarantined`、闭值 reason 与精确 failed LSN。该 tenant 从 worker discovery 排除，其他 tenant 继续；
readiness 为 Degraded/200。重启不会释放 quarantine，也不会反复执行同一 poison。

operator 先修复 projector/input 根因，再按上面的 `replay` 流程把同一 `tenant + projection + v3` 重放通过
failed LSN。最后由持有 typed Replay receipt 的控制面调用
`PgProjectionOperatorCapability<ProjectionReplayAction>::recover_quarantined_tenant(expected_failed_lsn)`；
它只调用 function-only operator seam，且仅当数据库中仍为 `quarantined` 且 failed LSN 精确匹配时转为
`released`。返回 `false` 表示坐标已变化或已由另一 operator 释放，必须重新读取诊断并禁止猜测重试。
不得用 migrator/serving 凭据直接改 quarantine 表；worker/operator 登录均没有 raw relation 权限。

## Check Active Pointer

```bash
rss projections status \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

记录输出里的 `active_version`、`promoted_high_water_lsn`、`selected_generation_high_water_lsn`、
`source_high_water_lsn`、`token`。
`--version` 是 selector 必填项，用来读取所选 candidate-generation checkpoint。active selection 是 tenant-scoped typed
record；它绑定 definition version/schema digest、input generation、promoted high-water 与 fencing token，不是
generic key/value 或调用方可编码的 JSON。

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

## Swap Active Generation

首次 swap 必须显式声明当前 selection 未设置：

```bash
rss projections swap \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" \
  --expect-unset < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

已有 active generation 时必须按当前 generation 做 CAS precondition：

```bash
rss projections swap \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$NEW_VERSION" \
  --expected-active-generation "$OLD_VERSION" < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

`--expected-active-generation` 和 `--expect-unset` 必须且只能出现一个。swap 在单一 PostgreSQL 事务中按固定锁序
取得 projection append advisory lock，锁定 exact input binding、target generation、checkpoint、quarantine 与
active selection，再读取 source high-water 并执行 fenced CAS。只有 definition/schema/input identity 精确、
target 未 quarantined 且 `generation high-water == checkpoint == source high-water` 时才提交 selection；失败时
旧 selection 保持不变。因此 source append 与 swap 不存在 high-water→pointer 的 TOCTOU 窗口。
成功输出使用 `promoted_high_water_lsn=<lsn>`，与 `status` 的同名字段一致；不存在含义不明的
`high_water_lsn` 别名。

status 可以显示 valid-empty `None`，但 swap 必须以 closed `SourceMissing` rejection 拒绝 `None`；即使存在
旧 checkpoint、checkpoint 为 `0` 或 operator 认为空流已追平，也不能 swap。等待完整 scope 出现首个 committed
source position，再重新 status/replay。stale / concurrent swap 返回 typed conflict/fenced/precondition outcome，
不能重试为弱 swap；先重新 `status` 确认当前 active。

## Rollback

Rollback 不删除 candidate generation data，不回退 checkpoint。线上事件可能已在 `$NEW_VERSION` active 后继续写入，因此必须先把旧 candidate generation 追到 source 尾部，再 swap 回上一 generation。

先 replay 上一个 generation：

```bash
rss projections replay \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$OLD_VERSION" \
  --batch-size 1000 \
  --max-events 100000 < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

再 status，确认 `selector_version=$OLD_VERSION` 且 `selected_generation_high_water_lsn` 已追到
`source_high_water_lsn`：

```bash
rss projections status \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$OLD_VERSION" < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

最后按 runbook swap 回上一个 generation：

```bash
rss projections swap \
  --operator-service-token-stdin \
  --operator-tenant "$RSS_OPERATOR_TENANT" \
  --tenant "$TENANT_ID" \
  --projection "$PROJECTION_ID" \
  --version "$OLD_VERSION" \
  --expected-active-generation "$NEW_VERSION" < "$RSS_OPERATOR_SERVICE_TOKEN_FILE"
```

完成后再执行 `status`，确认 `active_version=$OLD_VERSION`。active worker 在当前 batch 结束后重新解析 selection，
从 `$OLD_VERSION` 自己的 checkpoint 继续追尾；切换前已取得 request snapshot 的 v3 query 继续完整读取原
generation，新 request 才观察回滚后的 generation。保留 `$NEW_VERSION` 的 rows、dedupe receipts、checkpoint
与 DLQ 记录供诊断和后续再次 swap；rollback 只切 selection，不删除 generation 数据。Settings v4 不受影响。

## Failure Handling

- `postgres projection source reader capability is not exact`：reader role、只读/search_path 配置、ledger SELECT、
  scoped event/high-water function EXECUTE 或无额外权限约束发生漂移；撤销多余 ACL/role config，并恢复精确角色后重试，禁止换成
  serving/migrator 凭据。
- high-water 调用遇到 missing/unknown source scope：tenant 之外的 projection/definition version/schema
  digest/input generation 未命中完整静态 binding 集；SQLSTATE `22023` 是 permanent/invariant identity drift，
  不可重试，不能当成空 source、transient DB failure 或回退到全局尾部。修正 sealed assembly target 后整体重新部署。
- `source_high_water_lsn=none` / `projection active-generation swap was rejected: SourceMissing`：已验证的完整
  source scope 尚无 committed position；status 可展示 `none`，但 swap 必须拒绝。保持 selection 不变，等待首个
  committed source event 后重新 status/replay；不得用旧 checkpoint、零 checkpoint 或“空流已追平”推导成功。
- `postgres projection operator capability is not exact`：operator 获得了额外 relation/routine 权限，或固定函数
  集、role 属性/search_path 漂移；恢复 function-only exact set 后重试，禁止授 raw 表权限临时绕过。
- `bind SettingsOnly projection maintenance registry` / `validate SettingsOnly maintenance projection coverage`：部署 artifact 的 sealed SettingsOnly manifest/lock 与 operator target capability 不一致；修正 assembly plan 或 capability wiring 后重新构建并部署。独立 operator/source session 会受控关闭，命令不会进入 status/replay/swap 数据操作。
- `projection is not activated by the assembly plan`：selector 对应的 workflow 被 omitted/disabled，或 identity/mode/version/schema digest 不匹配。核对部署的 SettingsOnly plan 并激活精确 workflow；`status`、`replay`、`swap` 均不会绕过此检查。
- `projection target is not activated by the assembly plan`：workflow 已声明但 sealed maintenance plan 没有签发匹配 target；核对 active activation 与完整 typed maintenance capability，重新构建并部署，不得从 generated definition ledger 手工补注册。
- `projection is not generated for this runtime` / `projection target is not replayable by this runtime` / `projection target is not swappable by this runtime`：已选择 workflow 的 generated definition、inputs 或 target capability 与命令不一致；修正 codegen 输入或 assembly capability 后整体重新部署，不得使用 unsupported marker 或 raw registry fallback。
- `projection active-generation swap was rejected: CheckpointMissing|CheckpointStale`：先 replay 目标 generation，
  直到 `selected_generation_high_water_lsn == source_high_water_lsn` 后再 swap。
- `projection active-generation swap was rejected: CheckpointAhead`：checkpoint 超过 scoped source high-water，属于
  不可重试的持久化/invariant 漂移。保持 selection 不变并停止 rollout；查明越权 checkpoint 写入或 source 证据丢失，
  不得通过继续 replay、降低 source HWM 或手改 pointer 绕过。
- `projection active-generation swap was rejected: GenerationMissing|DefinitionMismatch|InputGenerationMismatch|GenerationHighWaterMismatch|TargetQuarantined`：目标 generation 不满足闭合 identity、materialization、high-water 或 quarantine 前置条件；修复目标并重新 replay/status，禁止弱化检查。
- `projection active-generation precondition failed`：当前 active generation 与命令声明不一致；执行 `status` 后按实际 active generation 重新决定。
- `projection active-generation CAS conflict` / `projection active-generation CAS token was fenced`：并发 swap 或 stale token；执行 `status` 后人工复核，
  禁止绕过 token 或改写 typed pointer 表。
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
- `stop=fenced`：有并发 replay 推进同一 candidate-generation checkpoint；重新 `status` 后只保留一个 operator 继续。
- `stop=checkpoint_unsaved`：target apply 可能已生效但 checkpoint 未保存；确认 target 幂等后重跑 replay。
- `stop=dead_letter_unsaved`：poison DLQ 写失败；先恢复 Vault/DLQ 依赖，再重跑 replay。
- `stop=budget_exhausted`：本轮 `--max-events` 预算耗尽的正常有界退出；checkpoint 保留，可提高预算后续跑。
  预算耗尽不证明 candidate generation 已追平，禁止 swap。
- `stop=source_read_failed`：projection_events 读取失败；按 infra transient/invariant 分类处理后重跑。
- `stop=checkpoint_unread`：candidate-generation checkpoint 读取失败；恢复 checkpoint store 后重跑，不能把失败降级为从头 replay。
- 只有 engine `stop=completed` 且 status 高水位符合既有 precondition 才允许 swap；`stop=budget_exhausted` 及其他
  `stop != completed` 均禁止 swap，先处理 stop 原因或续跑直到 `stop=completed`。
