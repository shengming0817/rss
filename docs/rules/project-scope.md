# RSS 项目能力与范围

本文是 RSS 能力处置与项目范围的单一事实源。需求判断、方案设计、issue 拆分和 review 必须先映射到本矩阵；
workspace 结构与分层仍以 [`architecture.md`](architecture.md) 为准，本文不复制 crate、contract、provider 或 gate
的当前数量。

## 处置状态

| 状态 | 含义 | 处理方式 |
|------|------|----------|
| **Evolve** | RSS 持续演进的核心能力 | 允许增强正确性、可消费性和运行闭环，但不得吸收相邻产品职责 |
| **Complete** | 已有 contract、provider、primitive 或纵向切片尚未形成完整闭环 | 允许完成 production closeout，不借补齐之名扩张产品宽度 |
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
| **DI Port / Adapter** | port、capability、lifecycle、provider conformance 和外部 adapter SPI | 现有 provider 的 readiness、故障语义和跨 provider conformance | 现有 adapter 全部保留；新 adapter 必须有 production assembly、两个独立 consumer 或 cross-provider conformance 需求 | 无 consumer 的 adapter 堆叠、云厂商资源管理 API、动态插件 ABI、插件市场和 service locator |
| **Consistency L0–L4** | consistency semantics、outbox/inbox、fencing、replay、checkpoint、reconcile 和 fault matrix | 已声明 L3/L4 primitive 的真实纵向切片、并发/crash/soak、多副本恢复 | 现有 primitive 全部保留；新 primitive 必须至少有两个 domain consumer，或属于 safety-critical invariant | BPMN/低代码工作流、MDM/fleet、设备运营平台、Kubernetes Operator framework、XA/2PC 和伪 exactly-once |
| **Security / AuthN / AuthZ / Tenant** | 凭据验证、可信 Principal、授权执行、obligation、RLS、tenant isolation、审计和外部 OIDC/SSO 接入 | 现有 Local Identity & Security Profile 的正确性、安全、并发和恢复闭环 | 现有登录、会话、账户安全、Role/Policy 管理能力保留，但不扩展为企业 SSO/IAM 或租户管理产品 | MFA/Passkey、SCIM、LDAP/AD、federation、realm/client/consent、tenant/org 生命周期、member/invite/domain、套餐/配额/订阅/计费和管理门户 |
| **Observability / Health / Local CI** | RSS 指标与 trace 语义、health/readiness、runtime inventory、项目专属正确性门 | label 闭值、trace continuity、reference dashboard/runbook、重复 parser/gate/事实源收敛 | 新 gate 必须绑定独立生产 hazard，并替换或合并既有证明；不继续建设通用 CI 控制面 | CI scheduler、Runner fleet、通用 cache/tool-install/release 平台、监控托管、SIEM 和 incident/on-call 产品 |

矩阵依据分别见 [`architecture.md`](architecture.md)、[`contract-fanout.md`](contract-fanout.md)、
[`api-versioning.md`](api-versioning.md)、[`runtime-assembly-plan.md`](runtime-assembly-plan.md)、
[`runtime-wiring.md`](runtime-wiring.md)、[`eventbus.md`](eventbus.md)、[`localtx.md`](localtx.md)、
[`reconcile.md`](reconcile.md)、[`saga.md`](saga.md)、[`security.md`](security.md)、
[`tenancy.md`](tenancy.md) 与 [`observability.md`](observability.md)。应用运行与生产交付的 owner 边界见
[`Runtime / Delivery Boundary`](../architecture/202607280820-1873-runtime-delivery-boundary.md)。

## 验证范围矩阵

能力矩阵决定 RSS 拥有什么；验证范围矩阵决定一项能力最深需要证明到哪里。RSS 采用 V 模型的需求—验收、
架构—集成、设计—组件对应关系，但不为每个测试标签复制一套测试。验证必须选择能够覆盖目标失效模式的最低充分层，
并以唯一主证明为默认。

| 层 | V 模型对应关系 | 主证明 | 范围所有者 | 默认执行边界 |
|----|---------------|--------|------------|--------------|
| **T1 设计与组件证明** | 详细设计 / 实现 ↔ 单元与组件验证 | rustc/Cargo Hard、schema/codegen/golden、表驱动/属性/状态机测试、进程内 component/oneshot | 一个 invariant、crate 或 contract ID | affected PR 默认执行；不得要求真实 production provider 或 binary |
| **T2 能力与接缝证明** | 架构 / 接口设计 ↔ 集成验证 | consumer contract、port/provider conformance、真实 adapter、migration/RLS、事务原子性/幂等及接缝故障 | 一个 contract seam、port 或实际交付 provider | 受影响能力选择有界 critical target；完整矩阵进入 develop/nightly |
| **T3 生产组合与验收证明** | 系统需求 / assembly 设计 ↔ 系统与验收验证 | production binary、真实 provider 组合、配置/CA/secret、readiness、关键纵向 journey、restart/drain 与 image smoke | 一个 production assembly 及其未被下层证明的 join hazard | 相关高风险变更定向执行；完整集合进入 production-runtime/nightly/release |

范围基数按 owner 和独立失效模式确定，不按当前数量做 golden：

```text
T1 = 每个独立 invariant 一个主证明
T2 = 每个独立 seam × 实际交付 provider
T3 = 每个 production assembly × 尚未被 T1/T2 证明的 production join hazard
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
| **Runtime Assembly** | T3 | 每个 production assembly 只维护覆盖其独有 join hazard 的最小关键 journey 集合 |
| **DI Port / Adapter** | T2 | adapter 在 T3 仅作为 assembly 依赖被接线，不重复自身 conformance/fault suite |
| **Consistency L0–L4** | L0 默认 T1；L1/L2 默认 T2；L3/L4 primitive 默认 T1/T2 | 只有已接纳的 production value stream 或纵向切片进入 T3；draft primitive 不自动获得 production E2E |
| **Security / AuthN / AuthZ / Tenant** | 按 hazard 分布到 T1–T3 | capability/funnel 在 T1，授权拒绝/RLS/真实 verifier 及 adapter TLS/证书校验/拒绝语义在 T2，secret/image/进程边界与 production assembly 的 TLS/CA/config 接线 join hazard 在 T3 |
| **Observability / Health / Local CI** | 指标/label/选择语义在 T1，真实 probe/lifecycle 在 T3 | T2 只验证 adapter/transport 接缝；CI 是执行载体，不作为 RSS 产品做端到端测试 |

### 选择与去重规则

- **最低充分层**：能由类型系统、crate 图、visibility、sealed trait 或 codegen Hard 化的约束，以 T1 静态证明为主；
  不得再用 xtask、integration 和 journey 逐层重复证明。Hard 是 enforcement 强度，不是强制增加 E2E 的测试层级。
- **运行期必要性**：真实事务、网络、进程、provider 组合、restart 和 drain 无法由编译期证明，可以由 T2/T3
  的 Medium 测试或 fail-fast guard 承载；不能因其不是 Hard 而删除。
- **唯一主证明**：每个 invariant 必须有一个 canonical owner。高一层测试必须写明新增的 join hazard；仅以
  “多一道保险”“完整覆盖”或覆盖率数字为理由的重复测试不进入范围。
- **状态约束**：`Evolve` 可按风险达到声明的最高层；`Complete` 只补缺失闭环；`Freeze` 保留 canonical regression
  但不扩展 provider/场景矩阵；`External` 最多验证 RSS 的 contract/port/adapter 边界，不测试外部控制面生命周期。
- **执行频率**：远端 planner 默认运行 affected T1，并按 capability map 选择有界 T2；T3 只由直接影响 assembly、
  production 配置/provider/lifecycle 或安全边界的变更定向触发，未知或影响分析失败时 fail-safe full。完整回归、
  跨 provider conformance、fault/recovery、performance/soak 和供应链时效检查进入 develop/nightly/release。本地
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
5. **最小实现**：port + typed contract + conformance + 一个参考 adapter 是否足够？
6. **退出能力**：未来移出主仓时，是否无需改变 RSS 核心语义？

默认判定：

```text
环境或集群事实          -> External delivery
用户、凭据或组织事实    -> External SSO/IAM；存量 Local Identity 能力保持 Freeze
套餐、计费或运营事实    -> External SaaS/application control plane
应用正确性不变量        -> RSS candidate
成熟系统已提供          -> port + adapter
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
- 不得以“补成熟度”“提供完整体验”或“多一道保险”为由绕过范围边界和门预算。
- 新 enforcement 遵循 [`README.md`](README.md) 的门预算：优先类型、visibility、schema 和既有 conformance；
  新 gate 必须说明替换或删除了哪个既有证明。

本文用于需求筛选、方案设计和 review，不是 Markdown enforcement carrier；禁止为矩阵标题、措辞、行数或数量新增
CI 扫描门。
