# ADR-008：wire 破坏式变更检测门 — xtask typed manifest + JSON-Schema diff

- **状态**：Accepted；2026-07-12 amendment 由 issue #1401 完成 manifest wire 语义闭环并立即收紧 active enforcement
- **日期**：2026-06-23；amended 2026-07-12
- **关联**：issue #1140 / #1147 / #1401 · epic #991 / Feature #1131
- **归属**：framework（wire 契约版本治理，provider-agnostic 工具门）
- **AI-robust 评级**：typed serde/codegen funnel **Hard**；历史 Git diff **Medium**；**零 Soft**

---

## 1. 背景

RSS wire contract 由 `contract.toml` 和 JSON Schema 共同表达，HTTP / event / command body 走 serde。
`cargo-semver-checks` / `cargo public-api` 只保护 Rust 公开符号，不能判定 wire 字段、HTTP 语义或 L2
拓扑的历史变化。单看 working tree 的 `contract validate` 也无法回答“这次是否破坏已发布契约”。

因此 wire 版本治理需要一个能读取 Git 基线、以 contract identity 对齐 base 与 working projection、
并对 schema 与 manifest 语义做 fail-closed diff 的机器门。

## 2. 决策

> 不迁 protobuf、不引 Buf CLI；使用 `cargo xtask contract breaking [--against <git-ref>]`
> 对 typed manifest projection 与 JSON Schema 做跨版本 diff。`active` 破坏恒 deny，`deprecated` warn，
> `draft` 跳过。

决策要点：

1. CLI 只接受可选 `--against`；不存在模式 flag、环境开关或时间窗口。
2. working manifest 始终严格解析；为读取实现前历史 ref 保留的窄 base projection 仅是历史 diff
   能力，不是当前格式的兼容 shim。
3. lifecycle 处置由 **base lifecycle** 决定，active 降级为 draft/deprecated 不能绕过门。
4. 新 contract ID/version 且旧 identity 完整保留时放行；删除或破坏旧 identity 仍拦截。
5. base ref 不可解析、Git 命令/对象读取失败、已枚举文件不可读、TOML/JSON 损坏都
   fail-closed；只有 Git 明确证明路径不存在时才视为新契约。重复 identity 直接拒绝。

### 2.1 对标依据

Buf 以 WIRE / WIRE_JSON / FILE 分类管理 protobuf 破坏变更。RSS 的 JSON wire 以字段名为稳定锚，
因此采纳 WIRE_JSON 的规则分类和基线/当前 image 对比模式，但不迁移 wire 表达层。

`ref: bufbuild/buf private/bufpkg/bufcheck/bufcheckserver/internal/bufcheckserverhandle/breaking.go@f6c012f82a281d670803536ddfca30a79fbd74e2`

## 3. 受保护的语义

### 3.1 JSON Schema

| 规则 ID | 破坏语义 |
|---------|----------|
| `FIELD_NO_DELETE` | 删除已有 property |
| `REQUIRED_FIELD_ADDED` | 新增 required 字段 |
| `FIELD_TYPE_CHANGED` | type 不兼容变化 |
| `FIELD_FORMAT_CHANGED` | format 变化 |
| `ENUM_VALUE_DELETED` | 删除 enum 值 |
| `ADDITIONAL_PROPS_TIGHTENED` | `additionalProperties` 收紧 |
| `NULLABLE_REMOVED` | 删除 nullable |
| `REDACTION_POLICY_CHANGED` | `x-pii` / `x-redaction` 漂移 |
| `PROTECTION_POLICY_CHANGED` | `x-protection` / `x-at-rest` 漂移 |

schema 以 contract + logical slot 取并集递归比较；删除整个契约或 slot 不能绕过字段删除检测。

### 3.2 HTTP manifest

| 规则 ID | 破坏语义 |
|---------|----------|
| `HTTP_STATUS_CODE_CHANGED` | `[endpoints.http].successStatus` 变化 |
| `AUTH_REQUIREMENT_CHANGED` | `auth.mode + permission` 变化；说明性 `reason` 不参与比较 |
| `IDEMPOTENCY_LEVEL_CHANGED` | `idempotency` 变化 |

所有 HTTP manifest 必须声明 `successStatus = <200..299>` 与
`idempotency = "idempotent" | "non-idempotent"`。serde 拒未知值，codegen 将它们经 typed
`HttpRouteBinding → HttpRouteEvidence` 单一漏斗传递；不引入 `auth.required` 双真源。

当前 4 个 draft HTTP（`seed.echo`、`audit.session-projection`、`identity.reconcile-loop`、
`settings.config-projection`）的 `successStatus = 200` 仅是非 serving 声明，不构成运行时承诺；
转 active 前必须与实际 handler 对齐。

### 3.3 L2 manifest

| 规则 ID | 破坏语义 |
|---------|----------|
| `TOPIC_CHANGED` / `DELIVERY_CHANGED` / `CONSISTENCY_LEVEL_CHANGED` | event routing 与一致性承诺变化 |
| `OUTBOX_ROLE_CHANGED` / `OUTBOX_ATOMICITY_CHANGED` / `OUTBOX_EMITS_CHANGED` | outbox 职责、原子性或事件集合变化 |
| `SUBSCRIPTION_SET_CHANGED` | subscription 增、删或替换 |
| `SUBSCRIPTION_CONSUMER_CHANGED` / `SUBSCRIPTION_GROUP_CHANGED` | consumer identity 变化 |
| `SUBSCRIPTION_TOPOLOGY_CHANGED` | partition/readiness 变化 |
| `SUBSCRIPTION_EXECUTION_CHANGED` / `SUBSCRIPTION_EFFECT_CHANGED` | execution/effect 变化 |

`emits` 与 subscription 集合排序不敏感，但任何元素增、删、替换都是 breaking。
subscription 必须声明 `execution = "adapter-native" | "domain-effect"`；`domain-effect` 必须配
`effect = "settings-config-version-refresh"`，`adapter-native` 禁止 effect。generated `SubscriptionSpec`
同时携 codegen 从 `(contract id, version, consumer)` 派生的闭枚举 `SubscriptionDispatchKey`；runtime
对该 key 穷尽匹配实际 handler plan，新增订阅未接线即编译失败。guard 只验证该穷尽 funnel 的结构，
不存在按 consumer 推断、wildcard、默认分支、平行实例清单或备用 registry。

## 4. lifecycle 与失败语义

- `active`：任何 finding 都是 deny，返回失败。
- `deprecated`：finding 为 warn，不阻断命令。
- `draft`：跳过历史破坏比较。

不读墙上时钟，不提供 warn/deny 配置面。`cargo xtask verify` 始终运行本门；无法完成
可信基线比较时即失败，不跳过。

## 5. 威胁矩阵 / amendment

**amendment**：2026-07-12 收紧原 ADR 的分期策略。issue #1401 落地后，active 破坏不再存在延期
或人工选择的非阻断期，manifest carrier 与 runtime/codegen 消费也不再是未实现的 follow-up。

| 威胁 | 缓解 | enforcement |
|------|------|-------------|
| 非法或不完整 manifest 值进入代码 | 闭枚举、`deny_unknown_fields`、必填关系、`HttpSuccessStatus`、codegen typed funnel、runtime 穷尽 match | **Hard** |
| active 通过 lifecycle 降级绕门 | 以 base lifecycle 决定 disposition | **Medium** |
| 契约删除、重复 identity 或新版本替换旧版本 | identity 并集比较；删除显式 finding；重复直接失败 | **Medium** |
| Git 基线命令、对象或内容不可靠 | 区分路径确实不存在与读取失败；后者 fail-closed | **Medium** |
| 规则实现恒真或漏比较 | 每条规则 synthetic red/green/anti-vacuity，并覆盖集合重排 | **Medium** |

## 6. AI-robust 分级

| 约束 | 评级 | 载体 |
|------|------|------|
| manifest 值域、必填关系与 generated/runtime 消费 | **Hard** | typed serde、闭枚举/newtype、codegen golden、穷尽 binding |
| 跨版本 wire 语义、lifecycle 与 Git IO | **Medium** | 历史 typed projection diff、synthetic red/anti-vacuity、verify fail-closed |
| 人工清单、延期窗口或可选警告作为 enforcement | **禁止** | 零 Soft |

历史 diff 是 Medium 而非 Hard：“working 是否破坏 base”依赖 Git 中两个时点的内容，Rust 类型系统、
crate 依赖图或可见性都无法独立表达这个时间关系，因此不能再上移。类型能表达的当前值域已全部
收紧到 Hard，其余由可重复、fail-closed 的 Medium 门承担，无 Soft 新增或存量过渡。

## 7. 备选（为何不取）

- **迁移到 protobuf + Buf CLI**：会改写全部 wire 表达、serde camelCase 与 generated 流水线，代价与本问题不成比例。
- **仅依赖人工扇出检查**：不能 fail-closed，是 Soft，与 AI-robust 章程冲突。
- **保留可配置 warn 模式**：允许 active 破坏绕过门，与当前无外部兼容负担的一次性收紧策略相反。
