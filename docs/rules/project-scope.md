# RSS 项目能力与范围

本文是能力处置与项目边界的规划真源，不是运行证据或 Markdown enforcement carrier。

## 项目目标

RSS 是面向 Rust 企业应用的 AI 友好型框架：以 contract-driven、static composition 和封闭官方技术栈提供
一致的开发体验，内建 L0–L4、一致性、tenant isolation 与 device zero-trust execution。

## 处置状态

| 状态 | 含义 | 允许变更 |
|---|---|---|
| Evolve | RSS 持续演进的核心能力 | 增强正确性、可消费性与运行闭环，不吸收相邻产品职责 |
| Complete | 已有 primitive/contract/provider 尚缺批准的最小闭环 | 完成既定闭环，不借 closeout 创造新工作 |
| Freeze | 存量能力保留但停止横向产品化 | 修复、加固、性能与兼容演进，不新增资源生命周期 |
| External | 事实应由相邻控制面拥有 | 仅提供窄 contract、port、adapter 或集成 |

Freeze 不等于删除、迁仓或停止维护。删除或迁移需要独立弃用决定，不能从状态自动推出。

## 能力矩阵

| 能力 | Evolve / Complete | Freeze / External 边界 |
|---|---|---|
| Domain governance | crate/domain boundary、contract-only、稳定 module factory | 通用构建/CI 平台、插件市场 External |
| Foundation 与 contract/codegen | 稳定公共 primitive、schema、deterministic binding、breaking proof | 无 consumer 的 facade、第二套 wire/runtime External |
| Runtime composition | typed config、static assembly、lifecycle、health/readiness、官方 provider closure | deployment/orchestration、secret projection、autoscaling External |
| DI port/adapter | RSS semantic port、conformance、official reference adapter | 第三方资源管理面 External |
| Consistency L0–L4 | typed effect/transaction/outbox/workflow/fencing/recovery | 外部 DB/broker backup、PITR 与 delivery control plane External |
| Security/auth/tenant | verified identity、authorization obligation、RLS、credential/replay/revocation | 企业 IdP/IAM、MDM、组织目录与企业级策略 authoring External；存量 local identity 与 Role/Policy API Freeze |
| Observability/health/local CI | structured telemetry、redaction、readiness、affected verification | 托管监控、paging/incident 平台、通用 CI service External |
| Device security | candidate only：六契约保持 Draft；production-typed provider/runtime、两个 candidate route、binary/image/config 与最低充分 T1/T2 | supported/canonical promotion、profile activation 与 T3 未授权；fleet/firmware/campaign/inventory/CA control plane External |

## 公共消费边界

- internal `pub`、workspace package 或 generated artifact 不自动成为 Release API。
- 公共面只包含 catalog 接纳、真实 external consumer 可编译、SemVer/breaking proof 和发布 artifact 闭合的能力。
- provider contract 默认 internal；只有独立 consumer、owner、support matrix 与退出路径被接纳后才发布。
- product profile 只消费已接纳能力；profile/assembly 存在不自动扩大产品承诺。

## 能力完成定义

- Domain governance：边界有 Cargo/visibility/type carrier，外部 module consumer 可执行，不复制 exact inventory。
- Contract/codegen：声明、生成、runtime binding、breaking/deprecation 和 consumer proof 同 identity。
- Runtime：manifest/config/provider/lifecycle/health 与 canonical artifact 闭合。
- Adapter：capability、failure、health、lifecycle、conformance 与 composition wiring 同时成立。
- Consistency：最低充分 T1/T2；production join 只有经正式 acceptance 授权才进入 T3。
- Security：verified identity、tenant-safe transaction、obligation、freshness/replay/fencing 与 audit 坐标贯通。
- Observability：闭值字段/label、redaction、readiness 与 affected verification 有 executable owner。

## 边界判定

新增能力依次回答：

1. 事实属于应用、环境、身份/组织还是业务？
2. 是否唯一映射到既有能力 owner？
3. 是否有两个独立 consumer，或属于 safety-critical invariant？
4. 成熟标准/上游是否已拥有？
5. 直接使用或薄适配是否足够？
6. 移出主仓是否不改变 RSS 核心语义？

默认：环境/集群事实交 External delivery；用户/组织交 External IAM；套餐/计费交应用控制面；应用正确性
才是 RSS candidate。成熟机制优先直接使用；单 consumer 由具体 domain/assembly 拥有。

## 范围变更

- Evolve/Complete 可按现有 owner 实施；不得顺带吸收 Freeze/External。
- Freeze 新增资源类型、管理 API 或控制面属于范围变更。
- External 进入仓库前必须先接纳 owner、consumer、退出路径与替代方案。
- 新 official profile、candidate activation 或 production join-hazard 扩展必须独立接纳。
- “完整体验”“多一道保险”“已有 assembly/provider”都不是扩大范围的理由。
- 新 wrapper/port/adapter 遵循成熟上游优先与最小 RSS semantic 原则。
