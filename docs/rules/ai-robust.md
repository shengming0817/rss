# AI-robust 治理章程

本文只拥有约束强度与证据要求。能力准入见[项目范围](project-scope.md)，架构与依赖方向见
[架构与依赖规则](dependency-policy.md)，兼容承诺见[版本规则](api-versioning.md)，
验证深度与消费组合见[验证范围](verification-scope.md)。

## 风险类型

| 风险 | 保护对象 | 首选证明 |
|------|----------|----------|
| 架构依赖与可见性 | crate 方向、public/internal seam、构造与 lifecycle owner | Cargo graph、visibility、sealed trait、外部 consumer 编译 |
| 契约与兼容性 | contract identity、wire schema、codegen/binding、公开 API | schema、typed binding、deterministic codegen、breaking/deprecation |
| 安全、租户与可信 evidence | verified identity、tenant authority、credential、RLS、receipt | 私有构造、newtype、sealed receipt、真实 verifier/provider conformance |
| 一致性状态转换 | commit/rollback/unknown、idempotency、settlement、checkpoint、fencing | typed state、transaction conformance、fault/recovery proof |
| Library runtime lifecycle | 资源所有权、取消与有界清理 | 所有权约束、状态边界与行为验证 |

## 强度

| 级别 | 定义 | 典型载体 |
|------|------|----------|
| **Hard** | 违规不可表达，或修改必然导致 production consumer 编译、构建或构造失败 | Cargo 图、visibility、private field、newtype、sealed trait、typestate、必填构造器、被 production target 编译的 generated Rust |
| **Medium** | 违规可表达，由确定性机器检查或真实 conformance 阻断 | clippy、cargo-deny、type-aware test、provider conformance |
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
- 已删除私有 API 的 compile-fail 墓碑；重新引入会恢复真实安全或一致性绕过时，按对应 invariant 保留。

迁移期 carrier 记录 owner、目标 hazard、替代载体和删除条件；目标 invariant 被稳定载体覆盖后移除。

## 证据层

Hard/Medium/Soft 表示 enforcement 强度，验证深度由[验证范围](verification-scope.md)定义，两轴不得互相推导。
设计指导不自动构成机器约束，也不能凭规则文字宣称行为已被验证。

## 实施前判定

新增或修改 enforcement 前确定：

1. 稳定风险属于架构依赖与可见性、契约与兼容性、安全/租户/evidence、一致性状态转换或 library runtime posture。
2. Cargo、类型、schema、codegen 与既有 canonical proof 的覆盖边界。
3. truth owner、risk owner、canonical target 与诊断对象。
4. 最低充分的 Hard/Medium 和 T1/T2。
5. carrier replacement、合并或外部产品 hazard 的边界。
6. 能力范围、依赖准入与门预算的一致性。

## 载体选择

1. Cargo/package graph 与 visibility；
2. Rust 类型系统：newtype、sealed trait、private field、typestate、必填构造器、typed function choice；
3. schema/marker 单源与 deterministic codegen/golden；
4. Cargo/rustc/clippy/cargo-deny；
5. 既有共享 Clippy、cargo-deny 或 type-aware test；
6. provider conformance 与真实后端 T2；
7. 外部 consumer 编译与 conformance；
8. library runtime fail-fast。

机器 metadata 与 Rust source/rustdoc carrier 配置 synthetic red case 与 anti-vacuity。Hard 化后的投影从权威来源派生；
文件路径参与 semantic evidence identity，诊断行号不参与 identity、排序或 equality。按需生成的展示报告不是
enforcement carrier，不参与 verify/ci verdict。

## 审查要求

涉及 enforcement 的 finding 必须给出强度与载体说明。

- Hard：说明稳定 type、contract 或 invariant，以及承载它的 Cargo 图、类型、schema/codegen 或构造边界。
- Medium：说明 canonical target、诊断对象和确定性机器载体；存在低成本 Hard 路径时说明上移方案。
- Soft：不立项为 enforcement。

可由 Cargo 图、可见性、private field、newtype、sealed trait、typestate、schema/codegen 或必填构造参数表达的
约束采用 Hard；其余约束采用覆盖目标失效模式的最低充分 Medium carrier。

Funnel 类约束分别说明上游和下游强度；callsite 约束同时说明其上游构造边界。

ADR amendment 落地时同步重评原 ADR 的威胁矩阵或安全模型，并在同一改动中重写冲突段落。

## 风险证明边界

- 架构依赖与可见性证明须对应实际依赖和访问边界，不能用目录名称代替。
- 兼容性证据须覆盖受保护的公共承诺，不能用内部重构理由免除外部责任。
- 身份、事务和消息一致性的证据须区分合法状态转换与可信实现提供的外部事实；
  类型和借用限制不能证明任意外部操作真实执行或未越过信任边界。
- 安全证据覆盖受控身份、必需租户与凭据输入、默认拒绝的授权、隔离、防重放及不安全降级拒绝；
  事务证据覆盖最小权限下的原子性、过期所有权拒绝、不确定结果及未确认资源隔离。
- 资源生命周期证据须覆盖所有权、取消及有界清理的失效模式，不预设具体托管实现。
- 库与 provider 的证明不能代替消费方的生产配置或产品验收。

## Proof 收敛

- 一个事实对应一个权威声明源，其它 artifact 由该声明源派生。
- 一个 invariant 对应一个 canonical owner；验证范围由其独立风险决定。
- 回归测试绑定可复发行为；类型封闭后移除对应 source-shape regression。
- integration evidence 进入显式 canonical target，并携带环境与 provider/library assertion 结果。
- fault matrix 按独立 failure mode 组织。
- public-api/SemVer 保护明确公开面。
- proof replacement 先验证 candidate，再切换 selector/owner 并移除旧路径。

## Hard 范本与命名

- crate 图隔离：Cargo dependency 与分层 policy 共同固定依赖边。
- 可见性/newtype/sealed/必填构造器：固定构造入口和可信状态。
- typed function/state choice：不同语义使用不同 API 与类型。
- schema/codegen/golden：声明源派生 wire DTO、marker 与 binding。
- serde 边界：wire 字段由 schema/golden 与 owner crate tests 固定。

lint id 使用 `rss_{rule}`；独立治理测试使用稳定规则名；carrier rustdoc/test 头使用
`INVARIANT: <THEME>-<RULE>-NN`。type-aware governance carrier 配置 synthetic red case 与 anti-vacuity。
