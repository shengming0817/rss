# ADR-008：wire 破坏式变更检测门 — xtask typed manifest + JSON-Schema diff

- **状态**：Accepted；2026-07-12 amendment 由 issue #1401 完成 manifest wire 语义闭环；2026-07-13 issue #1696 增加固定的 consistency/effect review 窗口
- **日期**：2026-06-23；amended 2026-07-12 / 2026-07-13
- **关联**：issue #1140 / #1147 / #1401 / #1696 · epic #991 / Feature #1131
- **归属**：framework（wire 契约版本治理，provider-agnostic 工具门）
- **AI-robust 评级**：`EffectKind` 等闭值域与穷举 wire 映射 **Hard**；profile 完整性及历史 Git diff **Medium**；**零 Soft**

---

## 1. 背景

RSS wire contract 由 `contract.toml` 和 JSON Schema 共同表达，HTTP / event / command body 走 serde。
`cargo-semver-checks` / `cargo public-api` 只保护 Rust 公开符号，不能判定 wire 字段、HTTP 语义或 L2
拓扑的历史变化。单看 working tree 的 `contract validate` 也无法回答“这次是否破坏已发布契约”。

因此 wire 版本治理需要一个能读取 Git 基线、以 contract identity 对齐 base 与 working projection、
并对 schema 与 manifest 语义做 fail-closed diff 的机器门。

## 2. 决策

> 不迁 protobuf、不引 Buf CLI；使用 `cargo xtask contract breaking [--against <git-ref>]`
> 对 typed manifest projection 与 JSON Schema 做跨版本 diff。`active` 默认 deny；
> `LOCAL_ONLY_BOUNDARY_CHANGED`、`EFFECT_ADDED`、`EFFECT_REMOVED` 是固定 review-only warn，
> 但缺精确 `Contract-Review-Ack` 时 fail-closed；
> `deprecated` warn，`draft` 跳过。

决策要点：

1. CLI 只接受可选 `--against`；不存在模式 flag、环境开关或时间窗口。
2. working manifest 始终严格解析；为读取实现前历史 ref 保留的窄 base projection 仅是历史 diff
   能力，不是当前格式的兼容 shim。历史 subscription 缺 `externalEffectPolicy` 时只按旧闭合矩阵
   唯一归一化（adapter-native → transactional-only；settings refresh → reconcile）；无法唯一推导即
   fail-closed，归一化后仍与 working policy 精确比较。
3. lifecycle 处置由 **base lifecycle** 决定，active 降级为 draft/deprecated 不能绕过门。
4. 新 contract ID/version 且旧 identity 完整保留时放行；删除或破坏旧 identity 仍拦截。
5. base ref 不可解析、Git 命令/对象读取失败、已枚举文件不可读、TOML/JSON 损坏都
   fail-closed；只有 Git 明确证明路径不存在时才视为新契约。重复 identity 直接拒绝。
6. HTTP base/working 两侧都必须携非空、无重复的 typed `effectProfile.effects`；缺失 carrier
   不是历史兼容窗口，不能按空集合或“无变化”处理。

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
| `LOCAL_ONLY_BOUNDARY_CHANGED` | `LocalOnly` 与任一 non-L0 等级之间变化；固定 review-only warn，须精确确认 |
| `EFFECT_ADDED` / `EFFECT_REMOVED` | `effectProfile.effects` 集合增删；每个 effect 独立、稳定报告，须精确确认 |

所有 HTTP manifest 必须声明 `successStatus = <200..299>` 与
`idempotency = "idempotent" | "non-idempotent"`。serde 拒未知值，codegen 将它们经 typed
`HttpRouteBinding → HttpRouteEvidence` 单一漏斗传递；不引入 `auth.required` 双真源。
已知多响应 operation 通过 `[schemas.responses]` 按状态码声明 schema；codegen 为每个响应 DTO 派生
`HttpResponseBinding`，breaking gate 以状态码 slot 比较响应 schema，并把状态集合漂移归入
`HTTP_STATUS_CODE_CHANGED`。

当前 5 个 draft HTTP（`seed.echo`、`audit.session-projection`、`identity.device-certificate-policy-put`、
`identity.device-certificate-status-get`、`settings.config-projection`）的 `successStatus = 200` 仅是非 serving 声明，不构成运行时承诺；
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
| `SUBSCRIPTION_EXTERNAL_EFFECT_POLICY_CHANGED` | 既有 subscription 的事务外副作用策略变化 |

`emits` 与 subscription 集合排序不敏感，但任何元素增、删、替换都是 breaking。
subscription 必须声明 `execution = "adapter-native" | "domain-effect"`；`domain-effect` 必须配
`effect = "settings-config-version-refresh"`，`adapter-native` 禁止 effect。generated `SubscriptionSpec`
同时携非可选闭枚举 `ExternalEffectPolicy` 与 codegen 从 `(contract id, version, consumer)` 派生的
闭枚举 `SubscriptionDispatchKey`。当前只允许 `adapter-native + 无 effect + transactional-only` 和
`domain-effect + settings-config-version-refresh + reconcile` 两组完整语义；policy 无默认、alias 或自由文本。
runtime
对该 key 穷尽匹配实际 handler plan，新增订阅未接线即编译失败。guard 只验证该穷尽 funnel 的结构，
不存在按 consumer 推断、wildcard、默认分支、平行实例清单或备用 registry。

HTTP effect 集合以闭枚举 `EffectKind` 与稳定 wire name 投影，声明顺序不参与 identity。effect 替换必须同时
报告 removal 与 addition；缺失、空集、重复或未知 effect 均 fail-closed。posture report 是 working tree
当前快照，本门直接比较 base/working typed manifest，禁止拿 report artifact 代替历史 diff。

## 4. lifecycle 与失败语义

- `active`：默认 deny；三条固定 review rule 保持 warn，但无精确确认时 gate 失败。
- `deprecated`：finding 为 warn，不阻断命令。
- `draft`：跳过历史破坏比较。

review-only 是按闭枚举 rule 写死的 disposition，不是可选 enforcement。命令对 base commit 与排序后的
rule/subject/detail 做 SHA-256，要求 Git history 中存在精确 `Contract-Review-Ack: sha256:<fingerprint>`
trailer；任一 finding 或 base 漂移都会使旧确认失效。命令不读墙上时钟，不提供 warn/deny 配置面、环境开关
或延期参数。`cargo xtask verify` 始终运行本门；无法完成可信基线比较或读取确认时即失败。同一契约同时出现
review warn 与其它 deny 时保留全部 finding，并以失败退出。

## 5. 威胁矩阵 / amendment

**amendment**：2026-07-12 issue #1401 收紧通用 active wire 规则。2026-07-13 issue #1696 为首次纳入历史
diff 的 LocalOnly 边界与 HTTP effect 集合设固定 review-only 证据窗口；窗口只由三个闭枚举 rule 表达，
并以精确 Git trailer 证明审阅，不是人工口头选择、配置模式或时间开关。其它 active 规则继续 deny。

| 威胁 | 缓解 | enforcement |
|------|------|-------------|
| 非法 manifest 闭值进入代码 | 闭枚举、`deny_unknown_fields`、`HttpSuccessStatus`、codegen typed funnel、runtime 穷尽 match | **Hard** |
| active 通过 lifecycle 降级绕门 | 以 base lifecycle 决定 disposition | **Medium** |
| 契约删除、重复 identity 或新版本替换旧版本 | identity 并集比较；删除显式 finding；重复直接失败 | **Medium** |
| Git 基线命令、对象或内容不可靠 | 区分路径确实不存在与读取失败；后者 fail-closed | **Medium** |
| effect carrier 缺失被解释为空集合或假绿 | base/working HTTP 两侧严格要求 profile 在场、非空且无重复 | **Medium（条件完整性 + 历史读取）** |
| review rule 被 generic consistency deny 覆盖或误放宽其它规则 | LocalOnly 边界使用独立 rule；rule-aware disposition 仅穷举三条 warn，其余默认 lifecycle policy | **Hard 闭枚举 + Medium diff** |
| warning 在绿色命令中被忽略 | base + canonical findings 派生 SHA-256；缺精确 commit trailer fail-closed，漂移不可重放 | **Hard fingerprint 内核 + Medium Git 门** |
| 规则实现恒真或漏比较 | 每条规则 synthetic red/green/anti-vacuity，并覆盖集合重排 | **Medium** |

## 6. AI-robust 分级

| 约束 | 评级 | 载体 |
|------|------|------|
| manifest 闭值域与 generated/runtime 消费 | **Hard** | `EffectKind` 等 typed serde 闭枚举/newtype、codegen golden、穷尽 binding |
| effect profile 在场、非空、唯一 | **Medium** | base/working projection fail-closed、synthetic red/anti-vacuity、verify 必跑 |
| 跨版本 wire 语义、lifecycle 与 Git IO | **Medium** | 历史 typed projection diff、synthetic red/anti-vacuity、verify fail-closed |
| 固定 review evidence | **Hard policy/fingerprint 内核 + Medium 执行门** | 闭枚举 rule、deterministic finding、精确 trailer、verify 必跑 |
| 人工清单、可配置 warn 或时间窗口作为 enforcement | **禁止** | 零 Soft |

历史 diff 是 Medium 而非 Hard：“working 是否破坏 base”依赖 Git 中两个时点的内容，Rust 类型系统、
crate 依赖图或可见性都无法独立表达这个时间关系，因此不能再上移。类型能表达的当前值域已全部
收紧到 Hard，其余由可重复、fail-closed 的 Medium 门承担，无 Soft 新增或存量过渡。

## 7. 备选（为何不取）

- **迁移到 protobuf + Buf CLI**：会改写全部 wire 表达、serde camelCase 与 generated 流水线，代价与本问题不成比例。
- **仅依赖人工扇出检查**：不能 fail-closed，是 Soft，与 AI-robust 章程冲突。
- **可配置 warn 模式**：会让调用方选择性绕过门；本 ADR 只允许三个闭枚举 rule 的固定 review evidence。
- **比较 posture report artifact**：只有 working tree 当前 active 快照，会漏掉删除、降级和 base lifecycle。
