# ADR-028：device-security Candidate Scope 与 Owner 边界

- **Status**：Accepted
- **Date**：2026-08-12
- **Tracking**：#2109
- **Amends**：[`ADR-022`](202607291724-022-l4-device-latent-production-loop.md)、
  [`ADR-024`](202608012034-024-enterprise-framework-product-surface.md)

## Context

ADR-024 已把 `device-security` 列为 conditional official profile，但没有指定 artifact、真实 consumer 或激活闭包。
当前仓库事实仍是：`assemblies/deviceidentity` 只是 `demo`、library-only、`compile-only` 的 draft pilot；它使用
`DraftArtifactSimulator`，没有 binary、image、listener、public route、canonical journey 或 production
`ProductionEligibility` mint。六个 DeviceLatent contract 已物化为 manifest 与 generated binding，但 lifecycle 全部为
`draft`，也没有 mounted production path。

外部 `rss-main-user-device-abac-speckit-20260811` 与
`rss-incubator-secure-device-rotation-speckit-20260811` 提议把用户授权、Resource Security Fact、设备凭据轮换和 production
profile 收敛为同一产品切片。其中 Resource Security Fact write ingress 既可能被解释为第七个 RSS contract，也可能只是
外部产品/bootstrap 事实；同时，已关闭的 #1910 仍在旧 DeviceLatent 文档中被写成 activation/T3 owner，和 ADR-024 的
T3 默认拒绝、独立 issue/PR 规则冲突。

本次外部输入的 received archive identity 与 SHA-256 由
[`source-baseline.md`](../spec/007-l4-device-latent-production-loop/source-baseline.md#2026-08-12-candidate-scope-rebaseline)
单源记录。

本决策只接纳 candidate product scope 和后续 carrier handoff。它不把未实现类型、artifact、consumer receipt 或 T3
写成当前事实。

## Decision

### Candidate 产品身份

`device-security` 进入已接纳的 official profile **candidate scope**。状态不是 `hardening-authorized` 或 `active`，当前
`T3 owner=N/A（未申请 T3）`。以下 identity 被一次冻结，后续实现只能原地物化，不能另建平行设备框架：

| 产品事实 | 唯一 identity | 当前状态 |
|---|---|---|
| official profile | `device-security` | candidate scope only |
| assembly owner | `assemblies/deviceidentity` / Cargo package `deviceidentity` | demo、compile-only draft pilot |
| candidate binary | package `deviceidentity` / target `deviceidentity-server` | 尚不存在，不是当前 artifact |
| candidate image | `Dockerfile` target `deviceidentity-runtime` | 尚不存在，不是当前 artifact |
| public contract package | internal owner `crates/devicesecuritycontracts` / `devicesecuritycontracts` → public `rss-device-security-contracts` | 已物化的 experimental candidate Release Surface；六契约仍全部为 Draft，未发布、未激活 profile |
| real consumer | `rss-incubator` 的 Secure Device Credential Rotation product/agent | 外部产品 owner，尚无消费回执 |

冻结名称不等于注册 artifact。`assemblies/artifacts.toml` 在 binary、image、typed config、Health inventory 和非空 acceptance
carrier 全部真实存在前继续保留 `deviceidentity = compile-only`；本 ADR 不写入不存在的 binary/image、selector 或 receipt。

### 六契约公共窄腰

`rss-device-security-contracts`（名称映射消费
[`architecture.md` §公开发布命名](../rules/architecture.md#公开发布命名)）只允许从现有 contract/schema 单源派生以下 exact set：

1. `identity.device-certificate-policy-put`
2. `identity.device-certificate-status-get`
3. `identity.apply-device-certificate`
4. `identity.device-command-acked`
5. `identity.device-certificate-reported`
6. `identity.device-ingress-receipted`

Candidate package 可公开稳定 contract ID/version、DTO、schema digest、兼容元数据和规范化错误；不得公开 identity domain
service/repository、`diport`、provider catalog、RuntimePlan、AssemblyLock、generated internal registry 或通用 HTTP/MQTT SDK。
该 package 由同一 contract governance/codegen transaction 派生，不改变六个 contract 的 `draft` lifecycle，
也不注册 route、profile、binary、image、selector 或 T3 evidence。

六契约是一次 breaking exact-set 裁决，不保留 six/seven 双集、alias、shim、双 codegen 或兼容入口。未来若真实 RSS runtime
consumer 必须持续接收新的 device security fact，必须另立 scope/ADR/PBI，证明 authority、freshness、replay、idempotency、
audit 和 non-oracle 语义，并原子替换 exact set；不能先写 ingress 再追认第七契约。

### Resource Security Fact 边界

Resource Security Fact 的 source of truth、authoring lifecycle 和管理面属于 External 产品/control plane。RSS 可通过现有
Common ABAC PIP seam 消费 tenant/resource-bound 的窄 projection，但本 candidate 不新增 public fact CUD contract，
不拥有 inventory、fleet、location、software、任意 JSON 或设备生命周期。

`rss-incubator` 的 disposable candidate/T2 环境可以由其 deployment bootstrap 准备资源事实与 policy；bootstrap 属于外部
产品 fixture，不进入 RSS Release Surface，不能作为 production freshness、authorization receipt 或运行时 authority。
生产 consumer 若不能从独立可信 owner 获得所需事实，结论是产品集成仍阻塞，而不是让 RSS bootstrap 变成控制面。

### Owner 边界

| 事实 | RSS | `rss-incubator` | External control plane |
|---|---|---|---|
| desired/reported generation、fencing、command/receipt、reconcile | 唯一 owner | 只消费公开结果 | 不拥有 |
| verified Principal/Tenant、ABAC evaluation、RLS、authenticated MQTT admission | 唯一 execution owner | 不复制决策/状态机 | 提供 IdP/broker authority 与配置 |
| CA、EST/CSR、SAN/key-use authorization、签名、CRL/OCSP、证书 lifecycle | 只消费窄 closure/artifact | 配置 reference environment | 唯一 owner |
| certificate revocation lifecycle/publication | 只维护决策侧 projection/cache/lookup；fail closed | 不拥有 | 唯一 owner |
| Resource Security Fact source/authoring lifecycle | 只消费窄 projection | 拥有产品 bootstrap/使用场景 | 唯一 production authority |
| operator recovery | `LocalOnly` inspection、自动 repair、fail-closed pause/drain seam；不新增 public CUD | 授权的产品恢复编排与 runbook | 唯一资源/PKI remediation action 与 audit receipt owner |
| rotation product、CLI/reference agent、workspace/lock/CI/安全响应 | 不拥有 | 唯一 owner | 提供依赖服务 |
| RSS Release Surface、SemVer、package/image correctness | 唯一 owner | exact version/digest 消费与报告 | 不拥有 |

依赖方向继续只有 `rss-incubator -> immutable RSS Release Surface artifacts`。Incubator 不能消费 path/git/workspace、RSS
internal crate、generated internals、provider catalog、RuntimePlan 或 T3 harness；其 candidate/T2 receipt 不能自行激活 RSS
profile，也不能成为 RSS production acceptance owner。

### Candidate 到 active 的原子条件

后续工作分成互不混合的两个阶段：

1. **Candidate implementation（只授权最低充分 T1/T2）**：独立 PBIs 原地物化六契约 public package；建立私有 production
   eligibility mint 与不可互换的 assembly-level provider closure/per-command artifact；实现真实 credential rotation
   consumer；物化上述 assembly/binary/image/config 的静态 identity；消除 simulator/no-op/in-memory/plaintext fallback；获得
   真实外部 consumer exact-version/digest receipt，并完成 contract、provider、transaction、MQTT 与组件级
   reload/restart/fencing/disable/drain T1/T2。T1/T2 不得声称 designated binary/image 的真实进程
   startup/readiness/restart/drain 或 secret/CA/config/image join 已闭合。
2. **Activation（当前未授权）**：只有正式 GA hardening trigger 后，才可另建一个内置完整 evidence plan 的独立 T3 carrier
   issue/PR。该 T3 才能证明 designated binary/image 的真实进程 startup/readiness/restart/drain、secret/CA/config/image
   join，以及 federated operator recovery：RSS inspection/自动 repair/pause-drain、incubator 授权产品 runbook、External
   remediation action 与 audit receipt 必须形成可复现闭环，但不新增 RSS 第七契约。Candidate lower-layer receipts 与独立
   production join 必须在同一 candidate revision first-green；随后才可在一个原子 transition 中把六契约从 `draft` 切为
   `active`、把唯一 designated artifact 提升为 canonical，并发布协调 package/image。

任何前置缺失都保持 candidate/draft/compile-only。不得部分激活 contract、先登记 selector、用 static artifact metadata
伪造运行回执，或以 L4/security-critical 名称自动获得 T3。未来 T3 只能使用 `project-scope.md` 的闭值 owner，且仍须独立
证明 production-only join hazard；本 ADR 不预留 Evidence ID、selector、fixture 或 CI lane。

### Supersession

- #1893–#1909 已落地的 provider-neutral semantics 与最低充分 T1/T2 carrier 保留；不重建、不改写为 T3。
- #1910 的“External PKI receipt 后直接 activation/T3”路线被本 ADR supersede。其 closed 状态不代表 production closure、
  binary/image、contract activation 或 T3 已交付。
- #1910 中 assembly-level provider closure 与 per-command authorized artifact 不可互换的安全要求由 #2116 落为 candidate
  T1/T2 carrier：`ExternalPkiProviderClosure` 与 receipt-bound `ProductionEligibility` artifact 是两个 sealed、不可互换的能力。
  这仍不是 assembly/profile activation；#2117 才拥有 required dependency wiring。
- #1982 的 Vault live target 现同时证明真实 `/sign` response 可经过 #2116 closure mint，但测试结果本身仍不能充当
  profile activation receipt。
- #1983 只收敛 `core`/`eventing` 与 legacy carrier，不拥有或 supersede `device-security`。
- #2102 已关闭并解除 scope blocker；#2107 激活前，Platform vNext planned carrier 不能被当作 current-head public waist。

## AI-HARD carrier map

本 ADR 的产品选择和 owner 分工是 policy/review 事实，不伪装为机器 enforcement。当前机器事实继续由已有单链证明：

| 风险 | 当前 canonical carrier | 结论 |
|---|---|---|
| 六个 Draft contract identity/kind/consistency 漂移 | typed contract catalog、schema/codegen exact-set、contract validation | 已有 Hard/Medium；不加第七清单或新 gate |
| simulator artifact 进入 production slot | sealed `DraftEligibility`/`ProductionEligibility`、closure + move-only evidence 的消费式 production authorize、compile-fail tests；`pkiauthmint` wrapper/callsite exact-set 仅作 Medium 纵深门 | 已有 Hard/T1；正式 mint 仅由 provider config identity 一致的 Vault verified evidence + current receipt-bound acquisition 进入 |
| draft pilot 被误报为 deployable artifact | assembly manifest/lock/RuntimePlan、`assemblies/artifacts.toml` 与 artifact validation | 已有 Hard/Medium；当前结论为 compile-only |
| incubator 反向依赖 RSS internals | ADR-026 的独立 repository/Cargo source policy/candidate proof | 已有物理/Cargo/T2 owner |
| public candidate/package drift | contract lifecycle/codegen、Release Surface、release API 与 locked/offline package proof | experimental Draft package 已物化；仍不构成 activation 或 production eligibility |
| future assembly/activation partial cutover | assembly manifest/lock/RuntimePlan 与 profile artifact chain | future implementation handoff；未落地前不得声明 production invariant 已闭合 |

不新增 Markdown scanner、当前数量 gate、device-security 专用 registry、Evidence database 或 shape-only temporary guard。未来 PBI
必须优先使用 schema/codegen、sealed type、必填构造器和既有 assembly/Release Surface gate，并配置与真实风险对应的
synthetic red/anti-vacuity；没有 carrier 就缩窄或延后 claim。

## Four-principle check

- **彻底**：profile、public waist、assembly/image identity、real consumer、RSS/incubator/External owner、六契约、Resource Fact、
  activation 条件和旧 #1910/#1982/#1983 关系一次裁清；冲突规范在同一 PR 直接重写。
- **不向后兼容**：删除 conditional→#1910 的旧激活路线，不保留六/七双集、旧 owner alias、compat package、双 selector 或
  partial activation。
- **优雅简洁**：复用现有 DeviceLatent、Common ABAC、deviceidentity、Release Surface、assembly 和 ADR-026 边界；不新增
  framework、control plane、gate、registry、schema 或 speculative implementation。
- **AI-HARD**：只对已有 Hard/Medium carrier 声称当前事实；缺失的 production closure 明确 handoff，不用 Markdown、issue
  closed 状态或 static catalog 冒充实现与运行证据。

## Consequences

`device-security` 有了可实施的 candidate product identity，但当前 runtime 与 contract 行为不变。后续实现者无需再决定
parallel assembly、package、binary/image、consumer 或 six/seven contract；仍必须通过独立 PBI 交付真实载体。
Resource Security Fact 的缺失生产 authority 会阻塞产品集成，而不会扩张 RSS 为 MDM/fleet/PKI/control-plane 产品。
