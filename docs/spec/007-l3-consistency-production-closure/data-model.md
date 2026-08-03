# L3 logical data identities 与 contract proposal 分流

本文只保留后续 PBI 需要共同遵守的 logical identity、状态关系和安全不变量。所有实体均是 proposal，直到对应 PBI
把它落到 current contract schema、Rust type、migration 或 generated artifact；本文不规定 SQL 表/列名，也不是
enforcement carrier。当前 workspace、contract 与一致性语义仍以 [`architecture.md`](../../rules/architecture.md)、
[`contracts/README.md`](../../../contracts/README.md)、[`eventbus.md`](../../rules/eventbus.md) 和
[`saga.md`](../../rules/saga.md) 为准。

## Identity inventory

| Logical identity | 最小 identity / 状态 | 不变量 | Canonical PBI |
|---|---|---|---:|
| WorkflowDefinition | contract ID/version/schema digest；当前 lifecycle 闭值 | definition 不启动 worker；不在 #1912 增加 `retired` | #1913 |
| WorkflowActivation | assembly ID + workflow ID；Projection 四态、Saga 两态 | assembly-local、无隐式 default、digest 必须匹配 definition | #1913 |
| AssemblyWorkflowPlan | assembly generation + closed activation bindings | runtime 只消费 generated plan；global catalog 仅定义 | #1914 |
| ProjectionInputBinding | projection + source contract/version/schema + assembly generation | capture 只接受 assembly plan 中的 exact binding | #1914 |
| ProjectionSourceScope | tenant + projection + definition/generation binding | DB capability 在返回 payload 前过滤；serving 无 raw access | #1915/#1916 |
| ProjectionSourceHighWater | scoped source identity + committed position | 与 capture 同 durable boundary 更新；固定查询次数 | #1916 |
| ProjectionCheckpoint | tenant + projection + generation + monotonic position + fence | apply 成功后 CAS；失败不 skip；stale writer 被拒绝 | #1917 |
| ProjectionGeneration | tenant + projection + immutable generation + schema digest + health/state | rebuild 建新 generation，不原地污染 active data；同名 generation 不跨 tenant 共享状态 | #1918/#1919 |
| SettingsConfigProjectionRowV1 | tenant + generation + config key/version + source identity | metadata-only；禁止 config value/secret/token/raw payload | #1918 |
| ProjectionDedupeReceipt | tenant + projection + generation + source event | 与 read-model mutation 同事务；same event 只有一个 effect | #1917/#1918 |
| ProjectionActivePointer | tenant + fixed projection → generation + definition/schema/input identity + promoted high-water + CAS/fence token | typed single source 同时控制 v3 request 与 active worker generation；swap/rollback 原子 | #1921 |
| SagaDefinitionIdentity | contract ID + definition version + schema digest + action registry generation | instance 创建时完整固定；start/resume 精确解析，unknown identity 无 fallback；registry 不提供 retire/remove | #1923 |
| SagaStepIntent | tenant + saga + pinned definition + step + phase + logical effect key + fenced permit state | 外部 effect 前 durable；attempt 不得改变同一业务 effect identity；只有当前 lease 可取得执行 permit | #1925 |
| SagaStepReceipt | tenant + saga + definition + step + logical effect/idempotency key + protected outcome/reference | 与 intent 共享同一业务 effect identity；same key/same digest 幂等；不同 digest conflict；attempt 只作审计元数据；lease fenced | #1924 |
| SagaInstanceRecoveryState | pinned definition + single-store lease + journal cursor + protected receipt + explicit status/reason | typed hydrate/probe 后恢复到继续、补偿或 operator-required；unknown 不进入 retry | #1925 |
| L3ActivationEvidence | repository HEAD + assembly/workflow/digest + capability/fault/security receipts | exact-set、same-head、无 stale/duplicate/unknown receipt | #1929 |

同一行出现两个 PBI 时，前者拥有通用 primitive/conformance，后者拥有第一个 production adopter；需求的单一
canonical owner 仍以 [`traceability.md`](traceability.md) 为准。

## State relationships

### Definition 与 activation

```text
contract definition (draft | active | deprecated)
        |
        +-- assembly omitted/disabled -> zero runtime/DB/worker/serving side effects
        +-- active definition + projection capture-only/shadow/active
        +-- active definition + saga active
```

`draft + shadow/active` 非法；Saga 不存在 capture-only/shadow。外部 proposal 的 `retired` lifecycle 不在本 PBI
加入 current schema。

### Projection apply 与 serving

```text
scoped source event
  -> target apply + dedupe receipt (one local transaction)
  -> checkpoint CAS
  -> generation caught-up/healthy
  -> append-lock + identity/health/high-water validation + active pointer fenced CAS (one transaction)
  -> one request / one worker batch each binds one generation snapshot
```

active pointer 是 tenant-scoped typed record，不是 generic `distributed_cas` JSON value。pre-GA hard cut 删除旧 pointer
数据与读写函数，不提供 parser、backfill、dual-read、alias 或兼容 shim；登录角色只能经 fixed resolver/status/swap
函数访问。target commit unknown 不推进 checkpoint；重放依赖 target idempotency。pointer unset 时 v3 query fail-closed，
候选 generation 只能由 assembly bootstrap target 构建，不能 serving。

rollback 前把旧 generation replay/catch-up，再用同一 fenced swap 切回。当前 request/batch 继续使用已捕获 snapshot，
后续 request/batch 才观察新 selection；worker 从切回 generation 自己的 checkpoint 继续追尾。rollback 只切 pointer，
不删除被切出的 generation rows、dedupe receipts 或 checkpoint。Settings v4 不经过该 pointer。

### Saga effect 与恢复

#1923 先闭合 definition identity 与同次 run typed receipt；#1924 提供 protected receipt/completion 原子性，
#1925 把 instance、lease、journal、receipt 与 journal cursor 收敛到单一 durable recovery owner。崩溃后不能从
action 重算 receipt；必须先 hydrate durable receipt，或在 intent 未完成时走 typed probe。

```text
validate pinned definition + lease epoch
  -> durable intent + deterministic idempotency key + fenced permit
  -> execute external effect, or probe an interrupted intent
  -> protected receipt + journal transition + cursor (atomic visibility)
  -> continue / compensate / operator-required
```

probe 的 applied 结果携 protected receipt/reference 并完成 transition；not-applied 才能重新取得 permit；unknown
持久化为 operator-required，不能进入普通 retry/backoff。operator repair 必须授权、审计、fenced 且提交 typed
decision。补偿使用 hydrate 后的 durable forward receipt，并遵循独立 idempotency/intent/permit/completion 语义；
generated typed receipt 决定合法输入类型，但不替代 durable store。整个 runtime 只承诺 at-least-once 与 scoped
idempotent effect，不承诺 exactly-once execution。

## 外部 logical contract proposals 的吸收结果

| 外部 proposal | 保留的 normative intent | 后续机器载体 owner |
|---|---|---:|
| Assembly Workflow Activation | closed modes、definition/assembly digest parity、omitted/disabled 零副作用 | #1913/#1914 assembly schema/codegen/runtime plan |
| Projection Operator/Serving | scoped selector、caught-up/health/schema precondition、CAS swap/rollback、per-request/per-batch snapshot、无 raw payload | #1921 typed port + PostgreSQL T2 seam；#1922 既有 CLI/operability owner |
| Saga Definition/Step Authoring | exact pinned identity、deterministic key、sealed typed receipt/compensation、闭合 retry | #1923 contract/codegen/registry/executor；#1925 single durable store |
| Saga Durable Receipt/Recovery | single durable store/lease、journal cursor、protected receipt、typed hydrate/probe/operator 与 crash resume | #1924/#1925 store/executor |
| L3 Activation Evidence | same-head exact capability/security/fault receipts，billing 不得 active | #1929 existing selector/fixed Job |

字段名、Rust trait 签名、TOML/JSON shape 和 evidence schemaVersion 均由对应 PBI 设计与机器载体决定；外部 Markdown
示例不冻结 public API，也不允许作为实现通过证据。
