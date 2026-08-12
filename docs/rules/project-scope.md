# RSS 项目能力与范围

本文是 RSS 能力处置与项目范围的单一事实源。需求判断、方案设计、issue 拆分和 review 必须先映射到本矩阵；
workspace 结构与分层仍以 [`architecture.md`](architecture.md) 为准，本文不复制 crate、contract、provider 或 gate
的当前数量。

## 项目目标

> RSS 是面向 Rust 企业应用的 AI 友好型企业开发框架：以契约驱动、静态装配和封闭官方技术栈提供类似 Spring
> 全家桶的一站式开发体验，原生内建 L0–L4 一致性、多租户隔离以及设备身份认证与零信任执行能力。

## 目标验收边界

| 目标承诺 | 能力 owner | 验收边界 |
|----------|------------|----------|
| AI 友好型企业开发框架 | Domain Governance、Contract / Codegen、Runtime Assembly、Observability | 稳定公开面、deterministic artifact、结构化诊断和 affected verification 形成外部 consumer 可执行闭环 |
| 类 Spring 一站式体验 | Contract / Codegen、Runtime Assembly、DI Port / Adapter | 官方 profile 提供 typed config、静态 composition、lifecycle、health/readiness、测试切片与升级路径 |
| 封闭官方技术栈 | Runtime Assembly、DI Port / Adapter | profile/assembly 声明精确依赖闭包；实际交付 provider 具备 capability、failure、health、lifecycle 与 conformance 证据 |
| L0–L4 一致性 | Consistency L0–L4 | 各等级按最低充分 T1/T2 证明；只有已激活官方 profile 中的 production-ready 纵向能力才闭合 T3 restart、recovery 与 operator evidence |
| 多租户与设备零信任 | Security / AuthN / AuthZ / Tenant、Consistency L0–L4 | verified identity、tenant-safe transaction、授权 obligation、credential freshness、replay/fencing 与 audit 坐标贯通同步和异步路径 |

目标承诺的实际完成状态由下方能力矩阵判定。目标措辞不改变 `Evolve`、`Complete`、`Freeze`、`External` 的 owner
和准入条件。产品面、官方 profile 闭包与实施顺序由
[`ADR-024`](../architecture/202608012034-024-enterprise-framework-product-surface.md) 决定。

## 处置状态

| 状态 | 含义 | 处理方式 |
|------|------|----------|
| **Evolve** | RSS 持续演进的核心能力 | 允许增强正确性、可消费性和运行闭环，但不得吸收相邻产品职责 |
| **Complete** | 已有 contract、provider、primitive 或纵向切片尚未形成完整闭环 | implementation owner 可完成已批准的最小闭环；closeout 本身只核对既有证据，不借补齐之名创造新工作或扩张产品宽度 |
| **Freeze** | 已存在的能力继续保留和维护，但停止横向产品化 | 允许修复、加固、性能优化和兼容演进；不新增相邻资源生命周期 |
| **External** | 当前未进入 RSS，且事实应由相邻控制面拥有 | RSS 最多提供窄 contract、port、adapter 或集成，不拥有其管理面 |

**Freeze 不是删除、迁仓或停止维护。** 本矩阵采用后，存量能力默认保留；追溯拆分、删除或迁仓必须经过单独的
弃用与迁移决策，不能由范围标签自动推出。

## 能力矩阵

| 能力 | Evolve | Complete | Freeze | External |
|------|--------|----------|--------|----------|
| **Domain Governance** | domain/crate 边界、依赖方向、contract-only 跨域通信、ArchRules 和 AI-robust 载体 | 外部 Rust module 静态消费、统一 module factory、规则与事实源去重 | 现有 `xtask` 和治理门继续维护，但冻结通用构建/CI 平台化 | 动态插件运行时、模块市场、安装升级控制面、组织级研发门户和团队/项目管理平台 |
| **Contract / Codegen** | contract schema、生命周期、兼容性、Rust codegen、route/effect/consistency 元数据 | breaking/deprecation 闭环、标准 schema 导出、真实外部 Rust consumer | 保留现有 contract kind、Rust 语言和 schema 输出宽度 | API Gateway、托管 Schema Registry、无真实 consumer 的语言 SDK、全语言 SDK 平台和业务 CRUD/UI generator |
| **Runtime Assembly** | AssemblyLock、RuntimePlan、RuntimeExec、provider 构造、listener、readiness、drain、inventory | 现有 production assembly 的 plan/lock/wiring/inventory 闭合和故障证据 | 现有 Dockerfile、Compose 和应用运行契约继续维护，但不新增 production delivery 投影 | Helm、Kustomize、Terraform、Pulumi、Ingress、NetworkPolicy、HPA/PDB、CRD 和跨集群 orchestrator |
| **DI Port / Adapter** | internal provider-neutral seam、封闭 Official Integration、capability、lifecycle、health、failure posture 与仓内 provider conformance | 现有 provider 的 readiness、故障语义和跨 provider conformance | 现有 adapter 全部保留；新 adapter 必须有 production assembly、两个独立 consumer 或 cross-provider conformance 需求 | 当前通用外部 Provider SPI、无 consumer 的 adapter 堆叠、云厂商资源管理 API、动态插件 ABI、插件市场和 service locator |
| **Consistency L0–L4** | consistency semantics、outbox/inbox、fencing、replay、checkpoint、reconcile 和 fault matrix | 已声明 L3/L4 primitive 的真实纵向切片及其最低充分并发/crash correctness；soak、多副本和长期恢复只在 GA hardening trigger 或已接纳 SLO 下实施 | 现有 primitive 全部保留；新 primitive 必须至少有两个 domain consumer，或属于 safety-critical invariant | BPMN/低代码工作流、MDM/fleet、设备运营平台、Kubernetes Operator framework、XA/2PC 和伪 exactly-once |
| **Security / AuthN / AuthZ / Tenant** | 凭据验证、可信 Principal、授权执行、obligation、RLS、tenant isolation、审计和外部 OIDC/SSO 接入 | 现有 Local Identity & Security Profile 的正确性、安全、并发和恢复闭环 | 现有登录、会话、账户安全、Role/Policy 管理能力保留，但不扩展为企业 SSO/IAM 或租户管理产品 | MFA/Passkey、SCIM、LDAP/AD、federation、realm/client/consent、tenant/org 生命周期、member/invite/domain、套餐/配额/订阅/计费和管理门户 |
| **Observability / Health / Local CI** | RSS 指标与 trace 语义、health/readiness、runtime inventory、项目专属正确性门 | label 闭值、trace continuity 与 correctness diagnosis；最小 SLI/runbook 只在 GA hardening trigger 后实施，dashboard/alert 不因 metric 存在而自动进入范围 | 新 gate 必须绑定独立生产 hazard，并替换或合并既有证明；不继续建设通用 CI 控制面 | CI scheduler、Runner fleet、通用 cache/tool-install/release 平台、监控托管、SIEM 和 incident/on-call 产品 |

矩阵依据分别见 [`architecture.md`](architecture.md)、[`contract-fanout.md`](contract-fanout.md)、
[`api-versioning.md`](api-versioning.md)、[`runtime-assembly-plan.md`](runtime-assembly-plan.md)、
[`runtime-wiring.md`](runtime-wiring.md)、[`eventbus.md`](eventbus.md)、[`localtx.md`](localtx.md)、
[`reconcile.md`](reconcile.md)、[`saga.md`](saga.md)、[`security.md`](security.md)、
[`tenancy.md`](tenancy.md) 与 [`observability.md`](observability.md)。应用运行与生产交付的 owner 边界见
[`Runtime / Delivery Boundary`](../architecture/202607280820-1873-runtime-delivery-boundary.md)。

## 能力边界与完成定义

本节细化上表的稳定语义，不建立第二套能力 taxonomy、package plane 或支持矩阵。具体 crate、provider、contract、
profile 与公开符号仍从 Cargo metadata、manifest、schema、codegen 和 release surface 派生。

以下 Platform vNext 条款已由 #2107 原子 cutover 激活。当前 Cargo graph、Release API、codegen、RuntimeExec
bridge 与 production composition 是现行边界；pre-cutover 0.2 API 仅为历史，不提供 compatibility authority。
这里的历史仅指 pre-cutover 0.2 API；当前实验版允许在 0.2.0 内直接替换该 API，不保留兼容层。

### Domain Governance

- **拥有**：Cargo/crate 依赖方向、visibility、contract-only 跨域通信、composition owner，以及公开面与内部面的隔离。
- **不拥有**：组织级研发门户、团队/项目管理系统、动态模块市场、安装升级控制面，以及无真实 consumer 的公共扩展点。
- **完成**：外部 Rust consumer 只经稳定 façade 或 contract 消费；依赖和构造边界无法由普通 import 绕过；
  修改一项架构事实不要求同步维护平行清单或 scanner 特例。
- **Platform vNext 边界**：Foundation 位于 Platform 之下且不依赖 internal workspace；Platform 只定义 application
  waist 与 host-view ports，assembly/composition 是唯一接线 owner。具体 package 集合与依赖闭包从 Cargo metadata
  和 Release Surface 派生，本文不复制数量或实施 DAG。

### Contract / Codegen

- **拥有**：contract identity、owner、version、lifecycle、schema、effect/consistency/auth 元数据，兼容性校验、
  deterministic Rust codegen、typed runtime binding 与退役语义。
- **不拥有**：通用 API Gateway、托管 Schema Registry、无真实 consumer 的全语言 SDK、业务 CRUD/UI generator，
  以及手工 contract 数量或顺序清单。
- **完成**：声明源可闭合到 compatibility/deprecation、deterministic artifact、runtime binding、真实 consumer、
  升级与 retirement；公开 wire 语义不依赖内部实现形状。
- **公共 identity 边界**：contract ID、version、schema digest 与 descriptor/admission identity 只有一个 Foundation
  定义 owner；Platform、generated 与 runtime 只能消费，不能镜像或重新 mint 同义类型。

### Runtime Assembly

- **拥有**：typed config snapshot、AssemblyLock、RuntimePlan/RuntimeExec、provider/domain binding、listener、资源与
  worker owner、startup rollback、readiness、drain、shutdown 和 runtime inventory。
- **不拥有**：反射 DI、service locator、运行时插件发现、部署/集群/云资源编排，以及平行的 plan/lock/config registry。
- **完成**：production assembly 的 config、lock、plan、generated binding 与 inventory 身份闭合；不存在 demo/no-op
  fallback；已激活官方 profile 的 canonical production artifact 对 partial startup、readiness、drain、restart
  和故障恢复具有最低充分证据。
- **lifecycle 边界**：RuntimeExec 唯一拥有 startup、signal、readiness、admission stop、总 drain budget、shutdown
  与 live inventory。Platform 只能通过必填 internal bridge 读取投影，不公开 RuntimePlan、具体 runtime constructor、
  inventory publisher 或 provider catalog。

### DI Port / Adapter

- **拥有**：domain-shaped port、internal provider-neutral infra seam、封闭 Official Integration、capability、lifecycle、
  health、failure posture 与真实需要的仓内 conformance。`diport` 是 Internal Provider Contract；official adapter
  可直接实现它，并由静态 composition root 经封闭 provider catalog 构造。
- **不拥有**：当前通用外部 Provider SPI、任意实现兼容承诺、社区插件认证/市场、为 mock 或未来可能性创建的 trait、
  对成熟上游 API 的整面镜像，以及无 consumer 的 adapter 堆叠。
- **完成**：domain 不接触 raw provider client；实际交付 provider 的 capability、failure、health 与 lifecycle 证据闭合；
  新 adapter 满足上表的 production assembly、独立 consumer 或 cross-provider conformance 准入条件。

第三方扩展只保留**条件提升机制**。真实独立 provider 与 consumer、capability owner、SemVer/支持责任、typed static
bridge 和最低充分 conformance 同时成立后，必须经独立 scope/ADR/PBI 才能建立 capability-specific Release API。
package metadata 即使届时引入，也只是由工具验证的**不可信候选声明**：扫描或声明不会自动注册 provider，provider
不得自行声明 maturity 或 conformance receipt；显式 assembly 选择与既有
`assembly.toml → generated catalog → AssemblyLock → RuntimePlan` 仍是唯一接纳链。多个真实 capability-specific
SPI 证明稳定共同语义前，不提取通用 provider vocabulary crate。

### Consistency L0–L4

- **拥有**：L0 effect/state/privilege 边界；L1 rollback/commit-unknown；L2 state+fact 原子性、at-least-once、
  inbox/idempotency/settlement；L3 workflow/checkpoint/compensation；L4 offline/late result、generation/lease/fencing。
- **不拥有**：XA/2PC、伪 exactly-once、BPMN/低代码工作流、MDM/fleet/设备运营平台或通用 Operator framework。
- **完成**：不以 primitive、fixture 或 draft contract 存在宣称完成；只有声明为 `Complete` 或 production-ready 的
  纵向能力才要求闭合 contract、真实 provider、production assembly、observability、fault/restart 与 operator recovery。
  primitive 与 draft contract 只闭合最低充分的 T1/T2；正式 production adopter 只有进入已激活官方
  profile 并改变其显式 production join hazard 时才进入 T3。

### Security / AuthN / AuthZ / Tenant

- **拥有**：可信 Principal/Tenant/Device/Workload identity、凭据验证、tenant-safe transaction/RLS、授权 obligation、
  revocation/replay、credential freshness、redaction 与审计；现有 Local Identity 能力按上表 Complete/Freeze。
- **不拥有**：企业 IAM/SSO 管理面、SCIM/LDAP/AD、tenant/org/member 生命周期、套餐计费、MDM/fleet、PKI 门户、
  ZTNA/SASE，以及自研 TLS/X.509/JWT/OAuth/密码学 primitive。
- **完成**：authority 只能来自 verified context；缺失、过期、撤销、replay 或跨 tenant 输入默认失败；tenant、principal、
  device 与 audit 坐标在同步/异步路径连续，管理事实仍由 External owner 持有。
- **mint 边界**：tenant/request/principal reference、deadline/cancellation/obligation 等公共值只有一个 Foundation
  定义 owner，但这些值本身不授予可信性。Official OIDC integration 唯一拥有 JWT/JWS 验证和 JWKS
  fetch/refresh/freshness；只有 AuthN/AuthZ funnel 持有的私有 sealed mint capability 可以构造 trusted context。
  Platform 不接收 raw token/JWKS，不验证凭据，也不 mint identity。

### Observability / Health / Local CI

- **拥有**：结构化日志与脱敏、低基数 metrics、trace continuity、health/readiness、runtime inventory、RSS 语义的
  lag/backlog/outcome，以及确定性本地验证与结构化诊断。
- **不拥有**：telemetry backend/collector 托管、SIEM/incident/on-call 产品、通用 CI/Runner/cache/release 平台、
  第二套 test runner/evidence database，或 Markdown/行数/当前数量 gate。
- **完成**：失败可定位到 capability/contract/provider/assembly/invariant；CI 只执行 canonical proof，不成为业务事实 owner；
  fault/soak/release 证据按风险分层，不要求每次本地修改运行完整矩阵。

## 公共消费边界

- 对外承诺只来自明确的 standalone component、稳定 façade、contract/schema artifact，或经独立范围变更接纳的
  capability-specific extension contract；仓内 `pub` 与 internal signature baseline 不自动构成外部兼容承诺。
- domain、generated internals、provider catalog、RuntimePlan 构造细节、`xtask` 与 journey/fault harness 默认保持 internal。
- 新公开面必须有真实 consumer、owner、版本与退出路径；不得以“未来可能使用”扩大 release surface。
- 第一方 product incubator 是外部 consumer 源码树，不是 RSS workspace、Product Surface 或管理面。RSS 只拥有其
  Release Surface 与 artifact correctness；incubator 自行拥有 workspace、lock、产品构建、CI、发布和安全响应，且只能
  单向消费不可变 Release Surface artifact。具体迁移边界见
  [`ADR-026`](../architecture/202608111253-026-rss-incubator-ownership-migration.md)。

## 验证范围矩阵

能力矩阵决定 RSS 拥有什么；验证范围矩阵决定一项能力最深需要证明到哪里。RSS 采用 V 模型的需求—验收、
架构—集成、设计—组件对应关系，但不为每个测试标签复制一套测试。验证必须选择能够覆盖目标失效模式的最低充分层，
并以唯一主证明为默认。

| 层 | V 模型对应关系 | 主证明 | 范围所有者 | 默认执行边界 |
|----|---------------|--------|------------|--------------|
| **T1 设计与组件证明** | 详细设计 / 实现 ↔ 单元与组件验证 | rustc/Cargo Hard、schema/codegen/golden、表驱动/属性/状态机测试、进程内 component/oneshot | 一个 invariant、crate 或 contract ID | affected PR 默认执行；不得要求真实 production provider 或 binary |
| **T2 能力与接缝证明** | 架构 / 接口设计 ↔ 集成验证 | consumer contract、port/provider conformance、真实 adapter、migration/RLS、事务原子性/幂等及接缝故障 | 一个 contract seam、port 或实际交付 provider | 受影响能力选择有界 critical target；完整矩阵进入 develop/nightly |
| **T3 生产组合与验收证明** | 系统需求 / 官方 profile 设计 ↔ 系统与验收验证 | production binary、真实 provider 组合、配置/CA/secret、readiness、关键纵向 journey、restart/drain 与 image smoke | 一个经 GA hardening trigger 授权的 candidate 或已激活官方 product profile、其唯一 designated/canonical production artifact 及显式接纳的闭集 T3 owner | 相关高风险变更定向执行；完整集合进入 production-runtime/nightly/release |

范围基数按 owner 和独立失效模式确定，不按当前数量做 golden：

```text
T1 = 每个独立 invariant 一个主证明
T2 = 每个独立 seam × 实际交付 provider
T3 = 已授权官方 product profile × 其唯一 designated/canonical production artifact × 显式接纳的闭集 T3 owner
```

禁止生成 domain × provider × assembly × binary/image × fault 的笛卡尔积。高层验证只证明新增接缝：T2 不重复
T1 已封闭的纯域语义；T3 不重复 T2 已封闭的 TLS、ACL、migration、WORM、outage 或 provider fault 矩阵。
完整业务语义只在 production binary 上执行一次，runtime image 只验证 executable、non-root、配置/CA/secret mount、
readiness 与干净退出，除非二者存在独立生产失效模式。

### 能力与验证深度

| 能力 | 默认责任层 | 提升边界 |
|------|------------|----------|
| **Domain Governance** | T1 | 只为类型、crate 图和既有工具无法表达的真实接缝进入 T2；不建设 CI 平台系统测试 |
| **Contract / Codegen** | T1 + T2 | active contract 可通过所属关键 journey 进入 T3，但不要求每个 contract 独立拥有 production journey |
| **Runtime Assembly** | T1/T2；经 trigger 授权的 candidate artifact 或已激活官方 profile 的 canonical artifact 进入 T3 | assembly、`profile = "production"` 或 `supported` lifecycle 本身不授权 T3；只有官方 product profile 明确接纳的闭集 T3 owner 进入其最小 candidate/canonical journey |
| **DI Port / Adapter** | T2 | adapter 在 T3 仅作为 assembly 依赖被接线，不重复自身 conformance/fault suite |
| **Consistency L0–L4** | L0 默认 T1；L1/L2 默认 T2；L3/L4 primitive 默认 T1/T2 | 只有已接纳的 production value stream 或纵向切片进入 T3；draft primitive 不自动获得 production E2E |
| **Security / AuthN / AuthZ / Tenant** | 按 hazard 分布到 T1–T3 | capability/funnel 在 T1，授权拒绝/RLS/真实 verifier 及 adapter TLS/证书校验/拒绝语义在 T2；只有经 trigger 授权 candidate 的 designated artifact 或已激活官方 profile 的 canonical artifact 中 secret/image/进程边界与 TLS/CA/config 接线 join hazard 进入 T3 |
| **Observability / Health / Local CI** | 指标/label/选择语义在 T1；经 trigger 授权 candidate 的 designated artifact 或已激活官方 profile 的 canonical artifact 才能承载真实 probe/lifecycle join T3 | T2 验证 adapter/transport 接缝；CI 是执行载体，不作为 RSS 产品做端到端测试 |

### T3 授权与默认拒绝

- T3 默认全部拒绝。T3 owner 只有两个闭值：`ProfileLifecycleJoin` 证明官方 profile 的 config/startup/readiness/
  drain/restart 与 candidate 阶段唯一 designated artifact 或 active 阶段唯一 canonical artifact 的 join；
  `AcceptedValueStreamJoin` 证明该 profile 已明确接纳的真实纵向 value stream
  在 production process/provider 组合后独有的 join hazard。不得新增第三种 owner，也不得把 domain、consistency level、
  provider fault、observability、security 或 migration 名称改写成新的 T3 owner。
- 只有产品面 ADR 已接纳的官方 product profile 可以申请 T3。候选、参考或内部 profile 默认零 T3；候选 profile 只有在
  GA hardening trigger 明确放行后，才可用独立 issue/PR 建立非 canonical candidate evidence。candidate 真实通过前不得宣称
  profile active、不得进入 canonical selector，也不得替换 legacy owner；真实通过后才按 activation transition 原子激活。
- domain、contract、provider、adapter、consistency level、assembly、binary、image、
  `profile = "production"`、`supported` lifecycle 和 security-critical 标签都不能自动生成 T3 授权。
- 每个已激活官方 profile 只有一个 canonical production artifact 和一个 canonical journey carrier。
  多个独立 hazard 可共享 target、fixture 和基础设施，但每个 hazard 必须有稳定 Evidence ID 与精确可选 selector。
- 已接纳 ADR 中列明的 legacy T3 carrier 只可在 replacement 真实通过前作为冻结的 canonical 迁移证据继续运行；
  它们不等同于 active 官方 profile，不得新增 case、provider、fixture 或产品承诺，并须按 ADR 的处置路线缩减、替换或迁出。
- 当现有官方 profile 无法承载新 hazard 时，结论必须是「需要 T3 范围变更、实施阻塞」；不得先新增 target、
  case、fixture、service 或 image 后再追认产品承诺。

### GA 成熟度任务与触发放行

所有规划、issue、PR 与 review 使用下表的同一闭值判定；不得从 `supported` assembly、已有 metric/checklist 或阶段名称
另行推导授权：

| Profile 状态 | T3 | 最小 SLI / 单环境容量 / 必要 runbook | 新 dashboard / alert | 普通 PR selection |
|--------------|----|--------------------------------------|------------------------|-------------------|
| `candidate`（无 hardening trigger） | 禁止 | 禁止 | 禁止 | 仅既有 affected T1/T2 与已激活 canonical T3 |
| `hardening-authorized` | 仅正式 trigger 明列且经独立 T3 issue/PR 批准的 candidate item | 仅正式 trigger 逐项明列的最低充分项 | 禁止；除非同时满足下述有界例外并逐项明列 | candidate 直接命令验证，不注册 required selector |
| `active` | 运行已激活 canonical T3；扩展仍需独立批准 | 维持已接纳最小项；新增仍逐项触发 | 禁止；除非满足下述有界例外并逐项明列 | affected canonical T3 可进入普通 PR；全集仅 nightly/release |
| GA 后 | 维持 canonical T3；不因 GA 自动扩展 | 仅基于真实流量调优 RSS 自有项 | 仍需 RSS owner 边界内的独立接纳；托管监控保持 External | 不改变既有 selection 分层 |

- GA maturity 默认禁止。GA hardening trigger 明确接纳前（包括 scope freeze 前及 freeze 后尚未启动 hardening 的区间），
  禁止创建或实施以 SLO、容量/性能、dashboard/alert、evidence 聚合、closeout gate、soak/fault matrix 或 T3 扩展为主要
  产出的独立任务。
- GA hardening 不是全局授权。只允许逐项触发已接纳官方 profile 的最小 SLI、一个固定环境容量测量、必要 runbook 和经
  独立 scope/T3 流程批准的最小 production acceptance；不做 provider/环境/tenant/case 矩阵、长期 soak、托管监控或
  通用 evidence 平台。
- 普通能力 PR 只运行既有 affected T1/T2 与已激活 canonical T3 的有界选择，不因 hardening 自动拉起 candidate T3。
  独立 T3 PR 以 evidence plan 中的精确命令直接运行 candidate；candidate 在真实通过并完成 activation 前不注册到普通
  PR required selector。完整 active T3、fault/recovery、performance/soak 仍只进入 develop/nightly/release 或显式 full。
- GA 后才可基于真实流量调优 error budget、paging threshold、容量和长期运行参数；该阶段不改变 `External` 边界：
  autoscaling controller、多区域 delivery、商业 tenant 等级和托管监控仍由外部系统拥有，不能因 GA 完成进入 RSS。
- GA 前例外只限：已接纳官方产品面的 correctness/safety blocker；不测量就无法决定不可逆架构选择；明确的安全、合规或
  数据完整性要求；或已进入 GA hardening 且具有正式 acceptance trigger。每个例外必须同时记录正式 trigger、official
  product/profile、canonical proof owner、最低充分 T1/T2/T3、固定时间与 CI 预算、PR/nightly/release 执行位置、禁止扩张
  的矩阵维度，以及完成后替换或删除的既有证明。只有最低充分层包含 T3 时才填写闭值 T3 owner
  （`ProfileLifecycleJoin | AcceptedValueStreamJoin`）；T1/T2-only 项必须写 `T3 owner=N/A（未申请 T3）`。
  “更完整”“企业级”“多一道保险”不是例外理由。
- 条件延后任务复用现有 `flag-cond` 与 issue `Trigger`，不新增 maturity registry、schema、gate 或状态机。trigger 未满足时
  只能保留条件说明，不得预建实现、benchmark、selector、fixture 或 CI 路径。

### No-new-work closeout

- Closeout 默认 verification-only，只允许回读已有测试/JobResult、核对 canonical owner 与 selector、更新 spec/traceability/
  runbook、记录未完成项，以及关闭、合并或重新打开 issue。文档更新和 Epic 评论不成为新的 evidence owner。
- Closeout 禁止新增或修改产品代码、test carrier、benchmark harness、schema、selector mapping、CI Job/gate/runner、receipt
  聚合或 evidence database，也不得顺手修业务实现。
- Closeout 发现 implementation、proof、selector 或真实执行结果缺失时，结论是对应 canonical implementation issue 未完成；
  必须退回或重新打开原 owner。没有 owner 时由产品 owner 另立实现任务，closeout 自身保持阻塞且不接手补建。

### Production acceptance evidence plan 与 carrier replacement

任何新增、扩展、替换、重新声明或退役 T3 production acceptance carrier，以及切换 canonical
production artifact journey，都必须使用**独立 issue 和独立 PR**。T3 issue/PR 不得与 domain 功能、provider、
assembly 产品实现或其他能力开发混合；如果变更产品承诺，必须先由独立 scope/ADR PR 接纳，再开始 T3
实施 PR。一致性 L0–L4 与验证层 T1–T3 是正交轴；L3/L4 语义不会自动使测试成为 T3。

每个 T3 issue 必须先给出必要性证明：

- 所属已接纳官方 product profile、candidate 阶段唯一 designated production artifact 或 active 阶段唯一 canonical
  production artifact，以及对应产品承诺。
- 精确 join hazard、可观测失效模式，以及为何只有 production binary/image/process/config/provider 组合后才能证明。
- 已有 T1/T2 与 T3 owner，以及它们为何无法表达该失效模式；「完整覆盖」「多一道保险」和覆盖率不是理由。
- 将替换、合并、缩减或删除的旧 evidence，或者为何该失效模式确实无法并入现有 canonical carrier。
- 独立 selector、超时/预计耗时、外部资源、执行频率与失败定位方式。

每个独立 evidence item 必须记录：

- 稳定 Evidence ID、闭值 T3 owner（`ProfileLifecycleJoin | AcceptedValueStreamJoin`）、官方 product profile、candidate
  阶段唯一 designated production artifact 或 active 阶段唯一 canonical production artifact，以及要证明的 invariant
  或 join hazard。
- 唯一 canonical owner、最低充分层，以及精确 executable target/assertion；聚合 receipt 不是第二 owner。
- T1/T2 前置 target、各自证明的事实，以及在 candidate revision 上的真实执行结果；尚未满足时先记录
  blocking issue 与必须达成的绿色标准，并在开始 T3 carrier 工作前更新为真实 receipt。
- T3 新增的 assertion，以及为何该失效模式只能在 production binary/image/process/config/provider
  组合后观测；“完整覆盖”或“多一道保险”不是提升到 T3 的理由。
- 可单独选择的 test/filter/subcommand、timeout/预计耗时、外部资源与既有执行频率/profile。
- 变更类型及其完整 transition：activation 记录 candidate、designated artifact 成为 canonical artifact 的原子切换条件
  与 activation/registration 条件；
  extension-or-redeclaration 记录 canonical owner/assertion 的前后变化与接纳条件；replacement 记录旧
  carrier、新 candidate（退役时明确无 successor）、canonical selector 切换/删除条件，以及需同交付删除的
  target/harness/script/env；无 successor 的 replacement 另记录产品承诺退出依据与最终无残留验证。

lower-layer evidence 未列明或未在 candidate revision 真实执行成功时，不得生成、扩展、重新声明或切换 T3
carrier。skip、未执行、developer/non-production receipt 均不是绿色证据。多个独立 hazard 可共享
setup，但每个 hazard 必须能单独选择、单独复现并直接定位失败，不得藏在一个不可分辨的测试名后。

`activation` 必须在 candidate 真实通过后才激活或注册；`extension-or-redeclaration` 必须在修改后的
carrier 真实通过后才把新的 owner/assertion 声明为 canonical。`replacement` 中，新 candidate 真实通过前旧
carrier 继续是 canonical；通过后，同一交付必须原子完成实际 canonical selector 切换与旧 carrier 删除，
最终不保留 alias、shim 或长期双路径。只有 artifact journey replacement 才要求切换
`assemblies/artifacts.toml` 指针；其它 replacement 切换其实际 selector/registry/profile，不虚构 artifact
matrix 修改。final HEAD 必须重新运行变更后的 canonical carrier 和静态 artifact gate。现有 assembly schema 与
`assembly artifacts check` 只证明当前 checkout 的闭值 carrier 身份与静态形状，不声称证明运行成功、
lower-layer 语义或历史切换顺序；后三者是结构化 review evidence，不是 Markdown enforcement carrier。
candidate revision 的 same-head 运行 receipt 只进入 issue/PR review evidence；禁止写入 `assemblies/artifacts.toml`、
generated inventory 或任何 committed static registry，也不得由静态 gate 把历史执行结果伪装成当前 checkout 事实。

### 选择与去重规则

- **最低充分层**：能由类型系统、crate 图、visibility、sealed trait 或 codegen Hard 化的约束，以 T1 静态证明为主；
  不得再用 xtask、integration 和 journey 逐层重复证明。Hard 是 enforcement 强度，不是强制增加 E2E 的测试层级。
- **运行期必要性**：真实事务、网络、进程、provider 组合、restart 和 drain 无法由编译期证明，可以由 T2/T3
  的 Medium 测试或 fail-fast guard 承载；不能因其不是 Hard 而删除。
- **唯一主证明**：每个 invariant 必须有一个 canonical owner。高一层测试必须写明新增的 join hazard；仅以
  “多一道保险”“完整覆盖”或覆盖率数字为理由的重复测试不进入范围。
- **状态约束**：`Evolve` 可按风险达到声明的最高层；`Complete` 只补缺失闭环；`Freeze` 保留 canonical regression
  但不扩展 provider/场景矩阵；`External` 最多验证 RSS 的 contract/port/adapter 边界，不测试外部控制面生命周期。
- **执行频率**：普通 PR 只在固定 `check`、`test-affected`、`integration-critical` Job 中运行 affected T1 和
  capability map 选出的有界 T2/T3。分析失败、高影响根或保守 rename 升级为 `PrComplete`，仍不得触发
  coverage、audit、全部 integration shard 或其它 `ReleaseCheck` 成员。完整回归、跨 provider conformance、
  fault/recovery、performance/soak 和供应链时效检查只进入 develop/nightly/release 或显式 `ci full`。本地
  `make ci` 保持 10 分钟有界：unknown 忽略并留痕，影响分析失败直接报错，二者均不自动升级 full。
- **测试标签不是层级**：regression 是选择方式，smoke 是深度，fault/concurrency/security/performance 是场景维度；
  它们嵌入最低充分层，不各自复制一套 suite。performance 必须绑定明确的生产 SLO；soak 必须绑定生产 SLO，
  或明确的长时正确性/恢复 hazard，才进入范围。
- **门预算**：新增测试、runner 或 gate 必须说明替换/合并了哪个既有证明，或证明其失效模式在现有 owner 中不可表达；
  测试 inventory 和调度从机器事实源派生，本文不维护当前 target、provider、journey 或 job 数量，也不作为 Markdown enforcement carrier。

## 边界判定

新增 Feature、Epic 或跨能力设计必须回答：

1. **事实归属**：它拥有应用事实、环境事实、身份/组织事实，还是业务事实？
2. **能力映射**：能否唯一映射到矩阵中的既有能力？
3. **复用证明**：是否已有两个独立 consumer，或它是否属于 safety-critical invariant？
4. **上游替代**：成熟的标准、官方工具或开源组件是否已经拥有该能力？
5. **最小实现**：直接使用成熟上游或薄适配是否足够；确需 port 时，typed contract + conformance + 一个参考 adapter 是否足够？
6. **退出能力**：未来移出主仓时，是否无需改变 RSS 核心语义？

默认判定：

```text
环境或集群事实          -> External delivery
用户、凭据或组织事实    -> External SSO/IAM；存量 Local Identity 能力保持 Freeze
套餐、计费或运营事实    -> External SaaS/application control plane
应用正确性不变量        -> RSS candidate
成熟系统已提供          -> 直接使用或薄适配；确需隔离领域语义时才新增 port
单一 consumer           -> 由具体 domain/assembly 拥有，不进入共享内核
两个 consumer 或安全例外 -> 可申请 Evolve/Complete，必要时先记录架构决策
```

不得使用以下推理扩大范围：

```text
使用 Kubernetes  != 建设 Kubernetes 部署平台
使用 OIDC        != 建设企业 IdP
使用 Vault       != 建设 secrets 管理平台
使用 PostgreSQL  != 建设数据库运维平台
存在 reconcile   != 建设 MDM 或设备运营平台
存在 xtask       != 建设 CI 平台
```

## 范围变更

- `Evolve` 和 `Complete` 内的变更可以按现有架构规则实施；不得顺带吸收 `Freeze` 或 `External` 职责。
- `Freeze` 能力可以继续修复、加固、优化和完成兼容演进；新增资源类型、管理 API 或控制面属于范围变更。
- `External` 能力进入仓库前，必须先修改本矩阵并记录 owner、consumer、退出路径与替代方案。
- 新增官方 product profile、激活候选 profile 或扩展其 T3 join-hazard 集合属于范围变更；必须先经独立
  scope/ADR PR 接纳，不得在能力实现或 T3 carrier PR 中顺带扩大。
- 不得以“补完整性”“提供完整体验”或“多一道保险”为由绕过范围边界和门预算。
- 新 enforcement 遵循 [`README.md`](README.md) 的门预算：优先类型、visibility、schema 和既有 conformance；
  新 gate 必须说明替换或删除了哪个既有证明。
- 新依赖、wrapper、port、adapter 与自研机制遵循 [`dependency-policy.md`](dependency-policy.md)：成熟上游优先，
  RSS 只拥有其上的领域语义、受支持组合与正确性闭环。

本文用于需求筛选、方案设计和 review，不是 Markdown enforcement carrier；禁止为矩阵标题、措辞、行数或数量新增
CI 扫描门。
