# Saga Production Adoption and Operator Runbook

本 runbook 是 #1926 的 production adoption 与值班入口。行为约束见 `generated / diport::SagaDurableStore / saga conformance`；本页不定义新的
capability 或状态。机器 truth 由下列 carrier 提供：

- `assembly_schema::SagaActivation::Active.requirements()`：active Saga 的 capability exact set；
- sealed `WorkflowRuntimePlan` / `SagaRuntimeView`：本 deployment 的 activation 与 pinned identity；
- `eventexec::SagaStartPort`：业务启动的唯一公开 port；
- `diport::SagaUnresolvedObservation`：blocked backlog 的结构化 current-state 投影；
- `consistency::SagaInstanceStatus` 与 PostgreSQL lifecycle/retention constraints：闭合状态和持久化转换。

## Scope

production adopter 必须是一个真实业务 Saga contract 与 route。`billing.checkout` 仍然只是 draft generated/test
fixture；production assembly、RuntimePlan、database instance、worker、readiness 和 route 都必须 omitted。本文示例中的
owner/contract 不得替换成 `billing.checkout` 来证明生产能力。

业务启动和 operator maintenance 是两条不同边界：

- 业务 route 完成 authentication、exact authorization 与 durable start audit 后，铸造 move-only
  `SagaStartAuthorization`，再调用 `SagaStartPort::start`。业务请求不能选择 definition identity。
- `rss sagas` 只提供 `status`、`retry-compensation`、`repair`、`terminate`。它没有 `start`、`cancel`、通用
  `resume` 或 DLX redrive。

## Adoption gate

### 1. Contract and assembly selection

1. 确认 adopter contract 是 live Saga definition，step/receipt/retry policy 已通过 contract validation；旧 pinned
   definition 仍可由 immutable exact registry 解析。
2. 在目标 assembly manifest v2 中把该精确 workflow activation 设为 `active`。topology、环境变量、generated
   definition 存在或 `billing.checkout` fixture 都不能替代 activation。
3. 生成并提交与 manifest 同步的 AssemblyLock 和 RuntimePlan；deployment 只使用这组 sealed artifact。assembly
   graph 是按需 review presentation，不是 deployment artifact。

运行完整 assembly carrier 检查：

```sh
./hack/cargo.sh xtask contract validate
./hack/cargo.sh xtask assembly validate
./hack/cargo.sh xtask assembly artifacts check
./hack/cargo.sh xtask assembly generate-modules --check
./hack/cargo.sh xtask assembly generate-providers --check
./hack/cargo.sh xtask assembly lock check
./hack/cargo.sh xtask assembly generate-runtime-plans --check
./hack/cargo.sh xtask verify --fast
```

需要人工查看 assembly graph 时运行 `./hack/cargo.sh xtask graph assembly`；输出只落在 ignored 的
`target/xtask/`，不提交、不部署，也不参与 carrier verdict。

### 2. Exact capability closure

逐项核对 sealed plan 选择的 active Saga。清单的枚举和顺序只用于值班核对，exact-set 判定仍由
`SagaActivation::Active.requirements()` 执行。

| Requirement label | Production evidence |
|---|---|
| `typed-actions` | generated sealed definition、完整 typestate factory 和全部 step binding |
| `definition-registry` | pinned identity 到 typed factory 的 immutable exact map，旧 live identity 仍可解析 |
| `durable-store` | 单一 store 同时拥有 instance、lease、journal、protected receipt 与 cursor |
| `hydrator` | protected receipt 按 schema/version 转为唯一合法 typed receipt |
| `effect-probe` | interrupted intent 只能得到 applied、not-applied 或 unknown 的 typed 结论 |
| `dead-letter-store` | compensation failure 的诊断写入；DLX 不是状态或 redrive truth |
| `worker` | 只推进 sealed plan 中已激活、已注册且 pinned 的 runnable instance |
| `readiness` | identity 派生的 worker probe 与当前结构化 unresolved observation |

缺少、重复或多出 capability 时必须在 provider 初始化前停止。operator authorization 是独立 maintenance
boundary，不是第九项 activation requirement。

### 3. Start and recovery exercise

1. 通过 adopter 的业务 route 启动测试 instance，确认 route 只调用 `SagaStartPort::start`，并产生绑定 caller、
   worker identity、tenant/instance 与 start-audit ID 的 durable registration。
2. 用 `rss sagas status` 确认 definition version、schema digest、action generation 与 sealed plan 一致，且初始状态为
   `Ready`。业务输入和 operator 输入都不能选择或覆盖 identity。
3. 让 worker 推进一次正常路径，确认 `Ready | Running | Compensating` 只经 `advance_registered` 推进；重启 worker
   后仍从 durable snapshot、typed hydrate/effect probe 恢复。
4. 在 staging 的隔离 fixture 中验证 unknown effect 进入 `OperatorRequired`，compensation budget 耗尽进入
   `CompensationFailed`。两者都必须离开 runnable listing，并出现在结构化 unresolved backlog 中。
5. 确认 runtime inventory 只报告真实 active adopter；`billing.checkout` 仍 absent。

## Operator authentication and target

PostgreSQL control lane 使用独立 `rss_saga_operator` LOGIN；其函数 owner `rss_saga_operator_owner` 必须永久
`NOLOGIN`。fresh install 由 postgres init 从 `RSS_PG_SAGA_OPERATOR_PASSWORD_FILE` 创建 credential；retained volume 在
0088 成功后执行 `deploy/postgres-upgrade/provision-saga-operator-role.sh`，不得复用 writer、migrator 或 owner 凭据。
provisioning postflight 必须实际登录并得到
`rss_saga_operator:off:pg_catalog, public:off`。每条 start/finish audit 的 `tenant_context` 是 `--tenant` 指定的目标 Saga
tenant；`--operator-tenant` 只约束 service-token authentication，不得写入目标审计维度。
`retry-compensation` 与 `terminate` 的数据库 mutation façade 只授予该 credential；普通 `rss_app` 即使泄露也不能
直接调用这两项 SECURITY DEFINER 函数。startup capability gate 必须验证这一 exact function set。

每次命令都必须从标准输入读取 operator service token。token 文件应由部署 secret mount 提供，并保持仅当前
operator 可读；不要把 token 放进 argv、环境变量、shell history、日志或工单。
stdin 必须是一个非空 UTF-8 token，最多 16 KiB，结尾只能没有换行、一个 LF 或一个 CRLF；第二行、额外空行、
尾随空白、孤立 CR 或 token 后的任何内容都会在连接数据库前被拒绝。

部署 gate：operator 组合根只从 `OperatorRuntimeInputs` 持有的 sealed、bound workflow runtime，以
owner/contract 精确选择唯一 active `SagaOperatorService` target。零个或多个匹配都会在任何 store mutation 前
fail closed；不得临时从 PostgreSQL 构造 raw store 或绕过 definition registry/effect probe。

```sh
export OPERATOR_SERVICE_TOKEN_FILE='/run/secrets/rss-operator-service-token'
export OPERATOR_TENANT='<operator-tenant-uuid>'
export SAGA_TENANT='<saga-tenant-uuid>'
export SAGA_OWNER='<owner-domain>'
export SAGA_CONTRACT_ID='<contract-id>'
export SAGA_ID='<saga-uuid>'
export RSS_SAGA_OPERATOR_GRANTS='status|<saga-tenant-uuid>|<owner-domain>|<contract-id>'
```

grant 的闭合格式是逗号分隔的 `action|tenant|owner|contract`；每次命令必须同时匹配 action、tenant 和完整
worker identity。mutation action 需要分别授予 `retry-compensation`、`repair` 或 `terminate`，status grant 不会隐含
任何写权限。

所有命令都用 `--tenant`、`--owner`、`--contract`、`--saga-id` 绑定 tenant-scoped instance 与
assembly-selected owner/contract identity；不得添加 raw definition、lease、journal、receipt 或状态覆盖参数。
命令 exact set 只有下面四项；每项只接受本行列出的 action-specific evidence：

| Action | Additional required flags |
|---|---|
| `status` | 无；mutation evidence 一律拒绝 |
| `retry-compensation` | `--expected-journal-position`、`--reason-text`、`--change-ticket` |
| `repair` | `--expected-reason`、`--reason-text`、`--change-ticket` |
| `terminate` | `--reason-text`、`--change-ticket` |

未知 action / 非法 argv 返回固定 clap 诊断（`sagas: …; see --help`），不会打印四条 action-specific usage，也不会回显 argv。查看具体参数请用 `rss sagas <action> --help`。不存在隐式默认 action、通用 mutation flags 或别名。

## Status and backlog triage

先运行 status，再决定是否允许变更：

```sh
rss sagas status \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$SAGA_TENANT" \
  --owner "$SAGA_OWNER" \
  --contract "$SAGA_CONTRACT_ID" \
  --saga-id "$SAGA_ID" \
  < "$OPERATOR_SERVICE_TOKEN_FILE"
```

记录输出中的 status、pinned identity、operator reason、unresolved age 与最新 journal basis。输出不得包含 token、
lease token、receipt plaintext、effect key material、payload 或自由错误文本。
status 输出是稳定的 camelCase JSON DTO。`target` 必须回显请求绑定的 `tenant`、`owner`、`contract`、`sagaId`；
found 结果同时包含 `status`、`operatorReason`、pinned definition 字段、`latestJournalPosition`、
`hasEffectIntent`、`unresolvedAt`（Unix seconds）和 `unresolvedAgeSeconds`。missing/identity-conflict 仍回显 target，
其余字段为 `null`，不得从另一个 target 的 row 补值。

worker 暴露的 identity-scoped backlog 是：

- `saga_unresolved_instances{owner,contract_id,state="operator_required|degraded|compensation_failed"}`；
- `saga_unresolved_oldest_age_seconds{owner,contract_id}`；
- readyz probe `saga_executor:<owner>__<contract_slug>`。

计数与 oldest age 来自同一 `SagaUnresolvedObservation`。采样失败时 gauge 是 `NaN`，不是空 backlog；恢复后的
clean tick 必须把当前计数写回零并恢复 Healthy。`CompensationFailed` 是 blocked backlog，不设置 `terminal_at`，
也不进入 30 天 retention。

## Retry a failed compensation

只对 status 返回 `CompensationFailed` 的 instance 使用 `retry-compensation`。先修复导致 compensation 失败的依赖或
业务条件，创建 change ticket，再执行：

```sh
rss sagas retry-compensation \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$SAGA_TENANT" \
  --owner "$SAGA_OWNER" \
  --contract "$SAGA_CONTRACT_ID" \
  --saga-id "$SAGA_ID" \
  --expected-journal-position '<latest-journal-seq>' \
  --reason-text '<reviewed-operator-reason>' \
  --change-ticket '<change-ticket>' \
  < "$OPERATOR_SERVICE_TOKEN_FILE"
```

store 会在 claim 后再次核对 pinned identity、`CompensationFailed`、原始 `unresolved_at` 与精确失败 journal basis；
任一事实已变化都返回 stale/conflict，不得改表后重试。成功转换只能是 `CompensationFailed → Compensating`，并在
同一 fenced transition 写 durable operator audit。随后重新运行 status，确认 worker 接手且 backlog 计数下降。

## Repair an unknown outcome

`repair` 只处理 status 返回 `OperatorRequired` 且 reason/phase 可由 typed effect probe 解析的 instance。先从外部系统
取得权威结果并关联 change ticket；命令会用当前 reason 取得 move-only claim，再由 typed recovery 路径提交
confirmed-applied 或 confirmed-not-applied：

```sh
rss sagas repair \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$SAGA_TENANT" \
  --owner "$SAGA_OWNER" \
  --contract "$SAGA_CONTRACT_ID" \
  --saga-id "$SAGA_ID" \
  --expected-reason '<closed-operator-reason>' \
  --reason-text '<reviewed-operator-reason>' \
  --change-ticket '<change-ticket>' \
  < "$OPERATOR_SERVICE_TOKEN_FILE"
```

unknown、reason drift、identity drift、busy/stale claim 或无法产生 typed receipt/reference 时保持 blocked。不要把
unknown 声明成 transient，不要手工注入 receipt，也不要通过 retry-compensation 绕过 repair。
只有 `Repaired` 才是成功退出并写 finish-success audit；`StillUnknown`、busy、missing、identity/stale 或 interrupted
全部非零退出并写 finish-failure audit。

## Terminate before any effect

`terminate` 只允许 status 为 `Ready` 且尚无任何 forward/compensation effect intent 的 instance。它用于撤回尚未开始
的业务工作，不是取消运行中 Saga、放弃补偿或清理 unresolved backlog 的工具。

```sh
rss sagas terminate \
  --operator-service-token-stdin \
  --operator-tenant "$OPERATOR_TENANT" \
  --tenant "$SAGA_TENANT" \
  --owner "$SAGA_OWNER" \
  --contract "$SAGA_CONTRACT_ID" \
  --saga-id "$SAGA_ID" \
  --reason-text '<reviewed-operator-reason>' \
  --change-ticket '<change-ticket>' \
  < "$OPERATOR_SERVICE_TOKEN_FILE"
```

fenced store 必须再次确认 `Ready` 和无 effect basis 后才能写 `Terminated` 与 operator audit。成功后 status 必须为
`Terminated`，worker 永不恢复它。任何 `Running`、`Compensating`、`OperatorRequired`、`Degraded`、
`CompensationFailed` 或已有 effect intent 的 instance 都必须拒绝 terminate。
同理，retry/terminate CAS 只有 `Applied` 才能退出 0 并写 finish-success audit；busy、missing、identity/stale、
effect-already-started 或 lease-lost 都必须非零退出并写 finish-failure audit。JSON outcome 不能把未应用伪装成成功。

## Retention and forbidden recovery paths

retention eligibility 精确为 `Succeeded | Compensated | Expired | Terminated`，使用数据库权威 `terminal_at`、固定
30 天和每批最多 1000 个 root；root 删除后由 FK cascade 原子删除 journal/receipt。`CompensationFailed`、
`OperatorRequired`、`Degraded` 只进入 unresolved backlog，直到成功 repair/retry 或真实业务状态转换。

`rss sagas` 不提供 retention、start、cancel、generic resume、force-status、receipt injection 或 DLX redrive 命令。
不要直接 UPDATE/DELETE Saga 表、调用内部 maintenance SQL 代替 operator command，或把诊断 dead-letter 重放进
outbox。每次变更后都重新运行 status，并核对 durable operator audit 与 backlog/readyz 恢复结果。
