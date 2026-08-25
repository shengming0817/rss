# ADR-028：device-security Candidate Scope 与 Owner 边界

- **Status**：Accepted
- **Date**：2026-08-12
- **Last updated**：2026-08-25
- **Tracking**：#2109
- **Amends**：[`ADR-022`](202607291724-022-l4-device-latent-production-loop.md)、
  [`ADR-024`](202608012034-024-enterprise-framework-product-surface.md)

## Context

ADR-024 已把 `device-security` 列为 conditional official profile，但没有指定 artifact、真实 consumer 或激活闭包。
截至 #2117，`assemblies/deviceidentity` 已原地物化为 `production` + `durable-isolated` candidate：具有唯一 binary、
content-addressable image target、闭合 schemaVersion=2 config、RuntimePlan/AssemblyLock/provider inventory、三 listener
和 production `ProductionEligibility` mint。Primary 仅挂载 policy PUT 与 status GET 两个 Draft route；六个 DeviceLatent
contract lifecycle 仍全部为 `draft`。`DraftArtifactSimulator` 与 draft PostgreSQL bundle 只在 `test-support` 图可见。
既有 Ready proof function 由 forward-only migration `0113` 原地升级到 receipt-bound command schema；不新增表、列、角色或
兼容 overload。

外部 `rss-main-user-device-abac-speckit-20260811` 与
`rss-incubator-secure-device-rotation-speckit-20260811` 提议把用户授权、Resource Security Fact、设备凭据轮换和 production
profile 收敛为同一产品切片。其中 Resource Security Fact write ingress 既可能被解释为第七个 RSS contract，也可能只是
外部产品/bootstrap 事实；同时，在 ADR-028 接纳前，旧输入曾把已关闭的 #1910 解释为 activation/T3 owner。该路线现已
被本 ADR supersede，不再构成当前 owner 或兼容入口。

本次外部输入的 received archive identity 与 SHA-256 由
[`source-baseline.md`](../spec/007-l4-device-latent-production-loop/source-baseline.md#2026-08-12-candidate-scope-rebaseline)
单源记录。

截至 #2123，`rss-incubator` 已使用 exact candidate crate 完成公开 contract consumer T2；该回执不启动 RSS image，
也不替代 production lifecycle join。本决策当前接纳 candidate product scope、已完成的 consumer T2 和后续 carrier
handoff；它不把未实现 carrier、T3 receipt 或 profile activation 写成当前事实。

## Decision

### Candidate 产品身份

`device-security` 继续是未激活的 official profile candidate。2026-08-25 trigger 只把
`DS-T3-PROFILE-LIFECYCLE` 提升为 `hardening-authorized`，其 owner 为 `ProfileLifecycleJoin`；artifact、六契约和
profile 本身都未晋级或激活。以下 identity 被一次冻结，后续实现只能原地物化，不能另建平行设备框架：

| 产品事实 | 唯一 identity | 当前状态 |
|---|---|---|
| official profile | `device-security` | 一个 lifecycle evidence hardening-authorized；profile 仍未 active |
| assembly owner | `assemblies/deviceidentity` / Cargo package `deviceidentity` | production candidate，非 official-profile activation |
| candidate binary | package `deviceidentity` / target `deviceidentity-server` | 已物化；必须 `--config <path>`，仅 `--help` 可无配置成功 |
| candidate image | `Dockerfile` target `deviceidentity-runtime` | 已物化；distroless nonroot，固定 ENTRYPOINT，仅含 binary 与 config schema |
| public contract package | internal owner `crates/devicesecuritycontracts` / `devicesecuritycontracts` → public `rss-device-security-contracts` | 已物化的 experimental candidate Release Surface；六契约仍全部为 Draft，未发布、未激活 profile |
| real consumer | `rss-incubator` 的 Secure Device Credential Rotation product/agent | #2123 已完成 exact public contract consumer T2；不是 image lifecycle receipt |

`assemblies/artifacts.toml` 已破坏式升级至 schema v2，并将 `deviceidentity` 的同一行登记为 `candidate`。candidate 必须携带
binary/image/configSchema/healthInventory/exact cargo-test acceptance，且类型层禁止 `reason`/`journey`。Release Surface 可读取
其静态 identity，但 official profile artifact selection 必须拒绝 candidate；未来只能原子把同一行晋级为 `supported` 并补
journey，不能增加第二条激活入口。

### 六契约公共窄腰

`rss-device-security-contracts`（名称映射消费
`Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`）只允许从现有 contract/schema 单源派生以下 exact set：

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

后续工作分成互不混合的三个阶段：

1. **Candidate implementation（只授权最低充分 T1/T2）**：独立 PBIs 原地物化六契约 public package；建立私有 production
   eligibility mint 与不可互换的 assembly-level provider closure/per-command artifact；实现真实 credential rotation
   consumer；物化上述 assembly/binary/image/config 的静态 identity；消除 simulator/no-op/in-memory/plaintext fallback；获得
   真实外部 consumer exact-version/digest receipt，并完成 contract、provider、transaction、MQTT 与组件级
   reload/restart/fencing/disable/drain T1/T2。T1/T2 不得声称 designated binary/image 的真实进程
   startup/readiness/restart/drain 或 secret/CA/config/image join 已闭合。
2. **Hardening evidence（plan 已授权，carrier 未实现）**：#2126 是 `DS-T3-PROFILE-LIFECYCLE` 的唯一完整 Evidence Plan，
   #2129 是未来唯一 carrier。它只证明 designated binary/image 的真实进程 startup/readiness/inventory/restart/drain 与
   secret/CA/config/provider/worker join；#2129 first-green 只产生 review-only lifecycle candidate receipt，不激活
   profile，也不登记 canonical selector。#2130/#2131 只是 Secure Device Rotation `AcceptedValueStreamJoin` 的
   conditional future plan/carrier assignment，仍须各自 Trigger，当前未获本 amendment 授权。ADR-028 要求的
   federated operator recovery——RSS inspection/自动 repair/pause-drain、
   incubator 授权产品 runbook、External remediation action 与 audit receipt——不并入 ProfileLifecycleJoin；没有被
   AcceptedValueStreamJoin 或独立 Evidence Plan 明确接纳并 first-green 前，它继续阻塞 activation。
3. **Activation（仍未授权执行）**：全部 lower-layer receipt、已授权 T3 和 federated operator recovery 必须在同一
   designated candidate closure 上 first-green；随后才能在一个原子 transition 中把六契约从 `draft` 切为 `active`、
   把唯一 designated artifact 提升为 canonical、登记唯一 selector 并发布协调 package/image。

任何前置缺失都保持 candidate/draft。不得部分激活 contract、先登记 selector、用 static artifact metadata
伪造运行回执，或以 L4/security-critical 名称自动获得额外 T3。已授权 evidence 只能使用 `ADR-024` 的闭值 owner，
且仍须独立证明 production-only join hazard；本 ADR 不实现 selector、fixture、CI lane 或 receipt registry。

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
| candidate 被误报为 supported/profile artifact | schema v2 candidate shape、assembly manifest/lock/RuntimePlan、Release Surface selection rejection | Hard/Medium；当前仅 immutable candidate artifact |
| incubator 反向依赖 RSS internals | ADR-026 的独立 repository/Cargo source policy/candidate proof | 已有物理/Cargo/T2 owner |
| public candidate/package drift | contract lifecycle/codegen、Release Surface、release API 与 locked/offline package proof | experimental Draft package 已物化；仍不构成 activation 或 production eligibility |
| assembly/provider/listener/worker 漂移 | 同一 manifest 生成 RuntimePlan、AssemblyLock、provider catalog 与 module glue；启动期 exact join | 已落地 T1/T2；不等于 T3/activation |
| exact image/config/secret/provider lifecycle join | #2126 冻结唯一 plan；#2129 未来以 `production-artifact` exact selector 承载 | 当前只有 Soft handoff；#2129 first-green 前不得声明 T3 已闭合 |
| future activation partial cutover | profile artifact chain、六契约 lifecycle 与同一 artifact 行原子晋级 | future activation handoff；全部 evidence 与 recovery first-green 前不得切换 |

不新增 Markdown scanner、当前数量 gate、device-security 专用 registry、Evidence database 或 shape-only temporary guard。未来 PBI
必须优先使用 schema/codegen、sealed type、必填构造器和既有 assembly/Release Surface gate，并配置与真实风险对应的
synthetic red/anti-vacuity；没有 carrier 就缩窄或延后 claim。

## Four-principle check

- **彻底**：profile、public waist、assembly/image identity、real consumer、RSS/incubator/External owner、六契约、Resource Fact、
  lifecycle plan、operator recovery 缺口、activation 条件和旧 #1910/#1982/#1983 关系一次裁清；冲突规范在同一 PR 直接重写。
- **不向后兼容**：删除 conditional→#1910 的旧激活路线，不保留六/七双集、旧 owner alias、compat package、双 selector 或
  partial activation。
- **优雅简洁**：复用现有 DeviceLatent、Common ABAC、deviceidentity、Release Surface、assembly、标准 inventory 与
  ADR-026 边界；不新增 framework、control plane、gate、registry、schema、runbook 副本或 speculative implementation。
- **AI-HARD**：只对已有 Hard/Medium carrier 声称当前事实；#2126 仅为 Soft decision/handoff，缺失的 production closure
  交给 #2129 exact selector，不用 Markdown、issue closed 状态或 static catalog 冒充实现与运行证据。

## Consequences

`device-security` 已有可构建的 production candidate assembly，且一个 lifecycle Evidence Plan 已获 hardening 授权；
contract lifecycle、official profile selection、artifact lifecycle 与 T3 运行状态仍未改变。
该 candidate 证明本仓拥有的静态 artifact 与 library/component T1/T2；registry provenance、发布、环境选择、真实进程/OCI
secret-config-image join 和 consumer value stream 仍由后续 delivery/T3 owner 证明。
真实 PostgreSQL T2 只在 fixture 中短暂授予 production append funnel，且在 restart proof 前撤销；这证明 candidate library
closure，不修改 serving-role capability baseline，也不构成数据库迁移、activation selector 或 production acceptance。
Resource Security Fact 的缺失生产 authority 会阻塞产品集成，而不会扩张 RSS 为 MDM/fleet/PKI/control-plane 产品。
