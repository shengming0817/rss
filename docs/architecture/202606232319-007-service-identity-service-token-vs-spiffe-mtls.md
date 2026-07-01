# ADR-007：服务/工作负载身份 — service-token+MAC 现在 + `AuthScheme::Mtls` 接缝预留（SPIFFE/SPIRE 推迟）

- **状态**：Accepted（裁决 Feature #1131 deep-research 缺口之零信任服务身份选型；零信任底座前置）
- **日期**：2026-06-23
- **关联**：issue #1139 [ADR 服务/工作负载身份 SPIFFE/SPIRE+mTLS vs service-token] · epic #991 / Feature #1131
- **依赖 ADR**：**ADR-002**（context 控制流值传播 / tenant source）· **ADR-003**（DI port 范式，未来 mTLS verifier 经 port 注入）· **ADR-006**（`diport::Pdp` 接缝 = service-token MAC 验签的未来载体；service-token「验签延后」与 PDP 决策共享同一 verifier port）
- **归属**：framework（服务间认证 / 工作负载身份接缝，provider-agnostic 基础设施治理）
- **AI-robust 评级**：见 §6

> **Superseded by #1500（2026-06-30）**：HTTP/Internal 当前执行策略已切为 SPIFFE/SPIRE + listener 级
> mTLS 默认，service-token 仅作为显式迁移 listener 路径保留。本文保留为 2026-06-23 的历史裁决记录。
>
> **Closeout addendum（#1577 / #1586）**：service-token tenant header MAC 绑定已落地为
> `diport::ServiceTokenTenantBinding` / `diport::service_token_mac_input` +
> `httpserve::service_token_tenant_binding`；HS256 service-token 签名输入绑定 canonical
> `x-tenant-id:<tenant>`。下文关于「MAC binding 尚未实装 / service-token 验签空窗」的表述仅保留为
> 2026-06-23 历史状态，不再代表当前 tenant-header closeout 状态。SPIFFE/mTLS 切换判据仍保留为未来
> 架构依据。

---

## 1. 背景

RSS 内部 service-to-service 认证现状：

- **service-token + MAC-based `X-Tenant-ID`**：`authn::Principal::from_verified_service_token(token: &AccessToken) -> Result<Self, AuthnError>`（`crates/authn/src/lib.rs`，funnel 固定 `Service` principal）。租户在 pre-auth 阶段从 service-token 的 `X-Tenant-ID` 派生（ADR-002：`AppCtx` tenant payload 只在已认证通道构造）——**MAC 验签现状见下方澄清 + §5 威胁矩阵**。
  - **重要现状澄清（与 ADR-006 一致）**：`from_verified_service_token` 当前**仅做结构化解码 + claims 映射**，**MAC / 签名 / exp 校验同样延后给未来 `diport::Pdp`**（`crates/authn/src/lib.rs:8` 注释）——「verified」是 funnel 命名意图（调用方须保证已验签），非「此函数自验」。即 service-token 的 MAC 验签与 JWT 验签共享同一 #1109 verifier port，**当前未实装**（见 §5 威胁矩阵的空窗条目）。本 ADR 不改变这一现状，只裁决「现阶段身份方案 = service-token，而非 SPIFFE」。
- **`AuthScheme::Mtls` variant 已预留**：`crates/primitives/src/authplan.rs` 的 `AuthScheme` 闭值集含 `Mtls`，`require_scheme` 已映射 `AuthScheme::Mtls => RequiredScheme::Mtls`——类型层已为 mTLS 留位，但**无 verifier 实现**。
- runtime-api.md §Internal endpoint：`/internal/v1/*` 用 service token 或更强认证 + caller-domain allowlist；listener auth chain 必须显式声明。

迁移溯源（gocell）多处提及 SPIFFE + 跨 Cell mTLS（`spiffeid` sealed 身份），但 RSS 侧**仅声明、无实现**。

**待裁决**：现在就落 **SPIFFE/SPIRE + 内部 mTLS**（PKI 证明的工作负载身份），还是**保持 service-token+MAC** 并把 mTLS 作为 `AuthScheme::Mtls` 接缝预留、按需再上 SPIFFE。这是 deep-research（Feature #1131）识别的零信任底座 Phase-0 决策。

---

## 2. 决策

> **内部 svc-to-svc 现阶段用 service-token + MAC；`AuthScheme::Mtls` 作接缝预留；SPIFFE/SPIRE + 内部 mTLS 推迟到「多集群 / 跨 trust domain / P4 设备 fleet」。**

裁决要点：

1. **service-token 是选定的服务认证方案（形状预留，非"已可用"）**：`from_verified_service_token` 解码路径维持，Internal listener 经 caller-domain allowlist 守边界；**生产 MAC verifier 随 #1109 落地——#1109 前 httpserve `Require` 一律 fail-closed 401**（`crates/httpserve/src/auth.rs`：finalize_auth 冻结签名无 verifier 参，需认证路由现状全 401）。
2. **`AuthScheme::Mtls` 仅作类型层接缝预留**：不引 SPIRE Server/Agent、不引 X.509-SVID rotation 基建。
3. **SPIFFE-ID 语义保留为未来形状**：`spiffe://<trust-domain>/<path>`（如 `spiffe://rss/svc/authn`、设备 `spiffe://rss/ns/device/id/{device-id}`）作为切换后的身份命名，不在本阶段落地。

### 2.1 对标依据（SPIFFE/SPIRE 代价面）

`rust-spiffe` Workload API 形态：

```rust
let client = WorkloadApiClient::connect_env().await?;          // 依赖 SPIRE Agent Unix socket
let ctx: X509Context = client.fetch_x509_context().await?;     // SVID chain + trust bundle
let mut stream = client.stream_x509_contexts().await?;         // gRPC 流：SVID rotation（默认 ~1h）常驻消费
let source = X509Source::new().await?;                         // 后台 spawn watch loop（always-on）
```

完整部署 = **SPIRE Server**（workload attestation + 签发 SVID）+ **per-node SPIRE Agent**（暴露 Workload API）+ **k8s / 进程 attestor 插件**。`X509Source` 封装一个常驻 task 消费 `stream_x509_contexts()` 做证书轮转；服务身份 `spiffe://trust-domain/path` 编码进 X.509 SAN，mTLS 握手双向验证 SPIFFE-ID。

**偏离理由**：RSS 当前单集群（或有限副本）、无节点级 agent 部署，引入 SPIRE 控制面 + 常驻 rotation watch 是过早基建；service-token（HMAC 设计）在单集群内**设计上**区分 caller domain（满足 Internal listener allowlist）——**该能力随 #1109 MAC verifier 落地后才生效，现状 Require fail-closed 401**；对称密钥分发在单集群内不构成 key distribution 问题。`diport` DI port 范式（ADR-003）保证未来换 mTLS verifier（独立 port 或 `diport::Pdp` 扩展）只在 port 边界换 impl，authplan / 域零改动。

---

## 3. 范式（落地代码 / 接缝形状）

```rust
// 现状：service-token 解码路径（结构化解码已实装；MAC 验签随 #1109，httpserve Require 现状 fail-closed 401）
// crates/authn/src/lib.rs
impl Principal {
    pub fn from_verified_service_token(token: &AccessToken) -> Result<Self, AuthnError> { /* funnel → Service */ }
}

// crates/primitives/src/authplan.rs —— Mtls 接缝已在类型层（无 verifier）
pub enum AuthScheme { NoAuth, Jwt, Mtls, ServiceToken, JwtFromAssembly }
// require_scheme: AuthScheme::Mtls => Some(RequiredScheme::Mtls)

// 未来（推迟，非本 PR）：mTLS verifier 经 DI port 注入，消费 SVID → Principal
//   组合根注入 Box<DynMtlsVerifier>（prod = SPIRE X509Source 客户端；test = mock）
//   authplan 侧不变：listener 声明 AuthScheme::Mtls，verifier 校验对端 SPIFFE-ID
```

listener auth chain 必须显式声明（runtime-api.md）：单 listener 单 scheme；无认证用 `AuthScheme::NoAuth`（显式 `AuthNone`，非 `Option::None`）；Internal/Admin 上 `NoAuth` 被构造器 fail-closed 拒。切换到 mTLS 时，Internal listener 的 `AuthPlan` scheme 由 `ServiceToken` 改 `Mtls`，verifier 由组合根注入——**不动 authplan 类型、不动域**。

---

## 4. 后果

- **正**：服务认证零新增基建（service-token 解码形状已实装；生产 MAC verifier 随 #1109，#1109 前 Require fail-closed 401）；`AuthScheme::Mtls` 类型层接缝 + `diport` 注入范式使未来上 SPIFFE/mTLS 是「加一个 verifier impl + 改 listener scheme」的局部变更；与 ADR-002（tenant 只在已认证通道派生）一致。
- **负 / 代价**：当前服务身份是对称密钥（service-token MAC）而非 PKI 证明，跨集群分发会成 key distribution 问题——但单集群下不暴露；由 §4.1 切换判据兜住升级。
- **负 / 运维**：service-token 密钥的分发与轮转是**手动运维操作**（无 SPIRE `X509Source` 的常驻 SVID rotation 自动机制）；密钥变更须协调所有 Internal listener consumer 同步更新——此为单集群内可接受的运维代价，多集群即触发 §4.1 切换判据 1。
- **负 / 迁移路径**：runtime-api.md「单 listener 单 scheme」⇒ Internal listener 从 `ServiceToken` 切 `Mtls` 不可原地并存；切换时须**双 listener 过渡**（一个 `ServiceToken`、一个 `Mtls`，组合根同时装配），再逐步下线 service-token listener。评估切换判据成本时须计入此过渡窗口。
- **下游**：W 阶段 Internal listener 经 service-token + caller allowlist 守边界；deviceloop L4（P4）需设备工作负载身份时按 §4.1 引 SPIFFE。推迟 SPIFFE 期间，**设备请求 Internal API 的目标是未来 deviceidentity 契约（X.509/OIDC 路径），而非 service-token**（service-token 仅限 svc-to-svc）——注意 **deviceidentity 契约当前尚不存在**（`contracts/` 仅 `_seed`/`identity`；`/api/v1/deviceidentity/...` 仅为 `api-versioning.md` 的路径形状示例，非已落地契约）；此边界 + 契约须在设备 fleet 接入前由 deviceloop/deviceidentity 落地 PBI 显式声明（见 §8 Follow-up）。

### 4.1 切换判据（service-token → SPIFFE/mTLS，登记备查）

任一成立即重评引入 SPIFFE/SPIRE + 内部 mTLS：

1. **跨 trust domain / 多集群**：service-token 对称密钥跨集群分发变成 key distribution 问题，PKI（X.509-SVID）更优。
2. **外部（非 in-process）服务调 RSS Internal API**：需 workload 级、非人工分发的凭据。
3. **合规要求 PKI 证明身份**：服务身份须由 X.509-SVID 证明，而非预共享对称密钥。
4. **deviceloop L4（P4）设备 fleet**：设备 agent 需独立 SPIFFE-ID（`spiffe://rss/ns/device/id/{device-id}`）参与 mTLS，此时 SPIRE 节点 attestor 有明确收益。
5. **service-token 密钥泄露或需强制轮转，且对称密钥分发的爆炸半径已超出可接受范围**：此时 SPIFFE/SPIRE 的 PKI（短生命周期 X.509-SVID + 自动轮转）比重新分发对称密钥更能缩减攻击面，优先触发迁移（应急响应路径）。

迁移成本可控：`AuthScheme::Mtls` 已预留，引 SPIFFE 即新增 `SpiffeMtlsVerifier` impl + 组合根注入 + SPIRE 基建，authplan / 域零改动（迁移窗口期按 §4「负 / 迁移路径」双 listener 过渡）。

---

## 5. 威胁矩阵 / amendment 声明

**amendment 声明**：本 ADR **不 amend** 既有 ADR；不改变 `AuthScheme` 闭值集、不改 listener auth chain 强制（既有 Hard 守卫不退化）。新增 / 显式化威胁如下：

| 威胁 | 暴露条件 | 缓解 | enforcement 档位 |
|------|---------|------|-----------------|
| **service-token 验签空窗**（同 ADR-006） | #1109 未落地，`from_verified_service_token` 仅结构化解码、不验 MAC；若 Internal listener 接线到生产可达端点，caller-domain allowlist 实际形同虚设 | Internal 认证挂载与 #1109 同批上线；`finalize_auth` 默认拒兜底 | 当前 **Soft** → #1109 落地后 **Hard**（MAC 验签经 verifier port） |
| 对称密钥泄露 / 爆炸半径 | service-token HMAC 密钥泄露或跨集群分发 | 单集群假设为前提（跨集群即失效）；§4.1 判据 5 触发升 SPIFFE PKI | 决策记录（切换判据兜底） |
| replay 攻击（Internal endpoint） | 重放已截获的 service-token | runtime-api.md：`/internal/v1/*` nonce store 多实例 replay-safe（W 阶段接线） | **Medium**（nonce store，W 阶段守卫） |
| 控制面 listener 误降级为无认证 | Internal/Admin 上误配 `NoAuth` 或 route opt-out | `AuthPlan::new` fail-closed（`NoAuthOnControlPlane`）；控制面拒 route-level Public/Exempt | **Hard（类型 / 构造器，既有）** |

---

## 6. AI-robust 分级（本 ADR 引入 / 修改的 enforcement）

| 约束 | 评级 | 载体 |
|------|------|------|
| 本 ADR 为纯决策记录，**当前不新增 enforcement** | —（N/A） | 决策方向 + 切换判据成文；`AuthScheme::Mtls` 接缝已在类型层（既有） |
| listener auth chain 显式声明、`NoAuth` ≠ 缺省、控制面拒 `NoAuth` | **Hard（类型 / 构造器）** | `AuthPlan::new` fail-closed（`NoAuthOnControlPlane`）+ 闭值集 `AuthScheme`（既有，本 ADR 不改） |
| 未来 mTLS verifier 必填注入 | **Hard（类型 / 构造器）** | `Box<DynMtlsVerifier>` 构造器必填位置参（继承 ADR-004 C5） |

无 Soft 新增 enforcement。

---

## 7. 备选（为何不取）

- **现在就上 SPIFFE/SPIRE + 内部 mTLS**：最彻底的零信任工作负载身份。**否决**——单集群拓扑无节点级 agent，SPIRE Server/Agent + attestor + 常驻 SVID rotation watch 在当前阶段是过早基建，收益（跨 trust domain 互信）尚未触发。由 §4.1 触发时引入（接缝已留）。
- **service-token only，删 `AuthScheme::Mtls` 接缝**：彻底简化。**否决**——与零信任 MDM 跨集群 / 设备 fleet 愿景冲突；删接缝后重补需改 `AuthScheme` 闭值集 + 所有匹配点，爆炸半径大。预留 variant 近零成本，保留更优。

---

## 8. Follow-up

- **mTLS verifier / SPIFFE adapter 落地**：未来 P4 / 多集群触发（§4.1）时，新增 `diport` 侧 mTLS verifier port + SPIRE `X509Source` 客户端 adapter + SPIRE 基建（Server/Agent/attestor），Internal listener scheme 切 `Mtls`。本 ADR 为其方向依据，**本 PR 不实现**。
- **设备身份命名**：deviceloop L4 引 SPIFFE 时复用 `spiffe://rss/ns/device/id/{device-id}` 形状（与未来 deviceidentity 契约/路径对齐，当前未落地）。
- **deviceidentity 契约 + 设备 Internal API 边界（当前不存在，待 PBI）**：deviceloop/deviceidentity 落地 PBI 须建立 deviceidentity 契约（X.509/OIDC）并显式声明「设备请求 Internal API 不走 service-token」规则；本 ADR 的 §4「下游」对设备认证的引用以该 PBI 落地为准，在此之前为目标方向而非既有事实。

## 对标证据（ref）

- `ref: maxlambrecht/rust-spiffe spiffe/README.md@main` — Workload API `WorkloadApiClient::connect_env` / `stream_x509_contexts` / `X509Source`，抽取 SPIRE Agent socket 依赖 + 常驻 SVID rotation watch 代价面（偏离不取）。
- `ref: spiffe/spiffe standards/SPIFFE_Workload_API.md@main` — SPIFFE-ID（`spiffe://trust-domain/path`）+ X.509-SVID + Workload API 标准，未来切换后的身份语义来源。
