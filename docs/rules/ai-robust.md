# AI-robust 治理章程

RSS 的 AI-robust 治理保护安全、正确性、兼容性和生产运行不变量。关键约束优先由 Cargo/crate 图、visibility、
类型系统、schema 与 codegen 表达；跨文件、真实后端和 production 组合使用确定性的 Medium carrier。

## 风险类型

| 风险 | 保护对象 | 首选证明 |
|------|----------|----------|
| 架构依赖与可见性 | crate/domain 方向、public/internal seam、构造与 lifecycle owner | Cargo graph、visibility、sealed trait、外部 consumer 编译 |
| 契约与兼容性 | contract identity、wire schema、codegen/binding、公开 API | schema、typed binding、deterministic codegen、breaking/deprecation |
| 安全、租户与可信 evidence | verified identity、tenant authority、credential、RLS、receipt | 私有构造、newtype、sealed receipt、真实 verifier/provider conformance |
| 一致性状态转换 | commit/rollback/unknown、idempotency、settlement、checkpoint、fencing | typed state、transaction conformance、fault/recovery proof |
| Runtime 与 production posture | config、plan/lock、provider durability、startup/readiness/drain | typed config、AssemblyLock/RuntimePlan、lifecycle 与 production join |

## 强度

| 级别 | 定义 | 典型载体 |
|------|------|----------|
| **Hard** | 违规不可表达，或修改必然导致 production consumer 编译、构建或构造失败 | Cargo 图、visibility、private field、newtype、sealed trait、typestate、必填构造器、被 production target 编译的 generated Rust |
| **Medium** | 违规可表达，由确定性机器检查或真实 conformance 阻断 | clippy/Dylint、cargo-deny、type-aware gate、bootstrap guard、provider conformance |
| **Soft** | 面向设计与 review 的说明 | 文档、注释、命名与 review guidance |

关键约束采用 Hard 或 Medium；可由类型和依赖图表达的约束采用 Hard。

Hard admission 是 fail-closed 的语义判定：必须能从 Cargo production target、build script 或 production
类型边界派生唯一 owner 与真实 consumer。trybuild/compile-fail 是 external consumer 支持证据，不能声明 Hard；
用于证明 Hard 时复用 production carrier 的 invariant identity。JSON、Markdown、Mermaid、snapshot、golden 与 drift report
均为 presentation/support artifact，最高为 Medium。codegen 只有产物为 Cargo-reachable generated Rust
并实际进入 production 编译时才可作为 Hard truth source。

## 非永久 AI Hard

以下内容不作为永久 AI Hard：

- 普通业务分支、字段校验和领域状态转换；
- helper 名、局部变量名、文件名和文件位置；
- 协议状态机之外的精确调用顺序；
- LOC ratchet；
- README 文案和手工 expected count；
- 无 consumer 的未来 API；
- 通用 CI、构建编排和研发控制平台；
- domain × provider × assembly × binary × fault 测试笛卡尔积；
- 已删除私有 API 的 compile-fail 墓碑；重新引入会恢复真实安全或一致性绕过时，按对应 invariant 保留。

迁移期 carrier 记录 owner、目标 hazard、替代载体和删除条件；目标 invariant 被稳定载体覆盖后移除。

## 证据层

Hard/Medium/Soft 表示 enforcement 强度；T1–T3 表示验证深度。层级定义和 production carrier transition
以 [`project-scope.md`](project-scope.md) 为单一事实源。

- **T1**：Cargo、类型、schema/codegen、compile-fail、组件属性和状态机。
- **T2**：consumer/provider conformance、真实 DB/Broker/identity seam、事务与接缝故障。
- **T3**：production assembly、进程/config/provider join、启动/重启/排空和 operator recovery。

每个 invariant 选择覆盖目标失效模式的最低充分层。T1、T2、T3 分别证明其独有风险。

## 实施前判定

新增或修改 enforcement 前确定：

1. 稳定风险属于架构依赖与可见性、契约与兼容性、安全/租户/evidence、一致性状态转换或 Runtime/production posture。
2. Cargo、类型、schema、codegen 与既有 canonical proof 的覆盖边界。
3. truth owner、risk owner、canonical target 与诊断对象。
4. 最低充分的 Hard/Medium 和 T1/T2/T3。
5. carrier replacement、合并或独立 production hazard。
6. [`project-scope.md`](project-scope.md)、[`dependency-policy.md`](dependency-policy.md) 与门预算的一致性。

## 载体选择

1. Cargo/package graph 与 visibility；
2. Rust 类型系统：newtype、sealed trait、private field、typestate、必填构造器、typed function choice；
3. schema/marker 单源与 deterministic codegen/golden；
4. Cargo/rustc/clippy/cargo-deny；
5. 既有共享 Dylint 或 type-aware gate；
6. provider conformance 与真实后端 T2；
7. production join T3；
8. runtime fail-fast。

机器 metadata 与 Rust source/rustdoc carrier 配置 synthetic red case 与 anti-vacuity。Hard 化后的投影从权威来源派生；
文件路径参与 semantic evidence identity，诊断行号不参与 identity、排序或 committed projection。

## 审查要求

涉及 enforcement 的 finding 必须给出强度与载体说明。

- Hard：说明稳定 type、contract 或 invariant，以及承载它的 Cargo 图、类型、schema/codegen 或构造边界。
- Medium：说明 canonical target、诊断对象和确定性机器载体；存在低成本 Hard 路径时说明上移方案。
- Soft：不立项为 enforcement。

可由 Cargo 图、可见性、private field、newtype、sealed trait、typestate、schema/codegen 或必填构造参数表达的
约束采用 Hard；其余约束采用覆盖目标失效模式的最低充分 Medium carrier。

Funnel 类约束分别说明上游和下游强度；callsite 约束同时说明其上游构造边界。

ADR amendment 落地时同步重评原 ADR 的威胁矩阵或安全模型，并在同一改动中重写冲突段落。

## 风险实施规则

### 架构依赖与可见性

- Cargo manifest 和分层规则表达依赖方向。
- `pub(crate)`、private field、sealed trait 表达 public/internal seam。
- composition root 持有构造与 lifecycle owner。
- 外部 consumer 编译证明稳定 façade 与 contract 可消费性。

### 契约与兼容性

- contract/schema 是 identity、wire 与 lifecycle 的权威声明源。
- typed marker/binding 和 deterministic codegen 派生运行与发布 artifact。
- breaking、deprecation、SemVer 与真实 consumer 共同证明升级和退役语义。
- 可变集合从稳定 ID 与 manifest 派生。

### 安全、租户与可信 evidence

- Verified Principal、TenantContext、DeviceCredential 与 receipt 使用私有构造或 sealed 类型。
- auth、tenant 和 credential 作为必填 typed input 进入执行路径。
- RLS/ACL、tenant transaction、revocation/replay 与 negative authorization 使用 T1/T2 证明。
- production identity/provider join 使用最低充分 T3 证明。

### 一致性、事务与 fencing

- commit outcome、settlement、checkpoint、generation、lease 与 fencing 使用闭值类型。
- LocalTx、outbox/inbox、idempotency 和真实 backend failure mode 使用 conformance 证明。
- stale writer、lease loss、commit unknown、DLQ/recovery 使用独立 fault oracle。
- active L3/L4 value stream 使用 restart 与 operator recovery 证明。

### Runtime 与 production posture

- runtime phase 接收 typed configuration snapshot。
- production provider、AssemblyLock、RuntimePlan、generated binding 与 inventory 保持同一 identity chain。
- lifecycle output 表达 startup rollback、readiness、drain、shutdown 与 restart。
- provider capability/durability 和 production image/runtime join 使用 T2/T3 证明。

## Proof 收敛

- 一个事实对应一个权威声明源，其它 artifact 由该声明源派生。
- 一个 invariant 对应一个 canonical owner；T1/T2/T3 分别覆盖独立风险。
- 回归测试绑定可复发行为；类型封闭后移除对应 source-shape regression。
- integration evidence 进入显式 canonical target，并携带环境与 product assertion 结果。
- fault matrix 按独立 failure mode 组织。
- public-api/SemVer 保护明确公开面。
- proof replacement 先验证 candidate，再切换 selector/owner 并移除旧路径。

## Hard 范本与命名

- crate 图隔离：Cargo dependency 与分层 policy 共同固定依赖边。
- 可见性/newtype/sealed/必填构造器：固定构造入口和可信状态。
- typed function/state choice：不同语义使用不同 API 与类型。
- schema/codegen/golden：声明源派生 wire DTO、marker 与 binding。
- serde 边界：wire 字段由 schema/golden 固定，domain derive policy 由 Dylint 承载。

lint id 使用 `rss_{rule}`；独立治理测试使用稳定规则名；carrier rustdoc/test 头使用
`INVARIANT: <THEME>-<RULE>-NN`。type-aware governance carrier 配置 synthetic red case 与 anti-vacuity。
