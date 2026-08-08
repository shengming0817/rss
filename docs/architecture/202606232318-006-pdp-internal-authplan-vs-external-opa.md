# ADR-006：内置 typed authplan + 预留 `diport::Pdp` port（不引外置 OPA）

- **状态**：Accepted（裁决 Feature #1131 deep-research 缺口之零信任授权选型；解锁 W 阶段域 body 硬化前置）
- **日期**：2026-06-23
- **关联**：issue #1138 [ADR 外置 PDP(OPA/Rego) vs 内置 authplan/PDP] · epic #991 / Feature #1131 · `diport::Pdp` / `VerifiedClaims` impl 跟踪 issue **#1109**
- **依赖 ADR**：**ADR-003**（DI trait async+dyn 派发 = dynosaur；本 ADR 复用其 provider-agnostic port 范式）· **ADR-005**（DI port 归属 category line，§2.1）
- **归属**：framework（授权决策接缝归属，provider-agnostic 基础设施治理）
- **AI-robust 评级**：见 §6

> **Closeout addendum（#1584 / #1586）**：`diport::Pdp`、`RawCredential`、`VerifiedClaims`、
> `PdpError`、`authn::VerifiedJwt` / `VerifiedServiceToken` 以及 authn-owned
> `verify_rss_access` / `verify_federated_access` / `verify_service_token` verify→mint bridge
> 已落地；`rss_pdp_impl_adapter_only`
> 已注册为 dylint gate。下文把 `Pdp` port / verified newtype 描述为 future 的段落保留为
> 2026-06-23 历史裁决背景，不再代表当前 AuthZ closeout 状态。是否引外置 OPA 的切换判据仍有效。
> 开源授权对标边界由
> `docs/architecture/202607021958-014-authz-open-source-parity-boundary.md` 统一解释：RSS 追求安全目标等价，
> 不承诺外部 PDP 产品、API 或策略语言运行时兼容。

---

## 1. 背景

RSS 当前授权侧分两段：

- **`primitives::authplan`（引擎层，纯值类型）**：`AuthScheme`（`NoAuth`/`RssAccessToken`/`FederatedAccessToken`/`Mtls`/`ServiceToken` 闭值集）+ `ListenerKind` + `AuthPlan` + `RequiredScheme` + `AuthRequirement`，经 `resolve_requirement` 纯函数按优先级（route opt-out → listener plan → fail-fast deny）算最终裁决。**仅纯数据 + 纯决策计算，无 I/O、无网络**（`crates/primitives/src/authplan.rs` 头注释明示）。
- **`authn`（服务层）**：承载会话、Principal 与 profile-specific 认证 funnel。签名 / MAC / lifetime / claims 校验由 typed `diport::Pdp` provider 完成；`authn` 只接受带可信 profile 的 `RawCredential`，再把验证结果投影为 Principal。RSS/Federated/Service 三种 credential 构造入口与 verifier 路径互斥，不存在 generic JWT 入口。

`diport` 现有 provider-agnostic infra port 包含 `Pdp`；具体 OIDC adapter 仍通过 sealed profile marker 与 typed provider 绑定信任域，不把策略退化为自由字符串或可混用 provider。

**历史裁决问题（已决）**：RSS 是引入**外置 PDP**（OPA + Rego sidecar，策略当数据、运行期可换），还是**保持内置 typed authplan** 并按 DI 范式提供 `diport::Pdp` 接缝按需再外置。该问题已由本 ADR 选择后者；下文保留当时的决策依据。

---

## 2. 决策

> **保持内置 typed authplan；按 ADR-003 provider-agnostic 范式「定义但本 PR 不实现」`diport::Pdp` 接缝（impl = #1109）；现阶段不引入 OPA + Rego sidecar。**

裁决要点：

1. **授权决策留在进程内、编译期 typed**：`authplan` 纯值类型 + `resolve_requirement` 维持；后续验签 / claims 派生由 `diport::Pdp` port 承载（动态注入，prod/test 可换）。
2. **`Pdp` 是 port 接缝、不是本 PR 交付物**：本 ADR 只裁决「内置 + 预留 port」方向并固定 port 形状判据；trait 落地、`VerifiedClaims` mint funnel、httpserve↔authn 验签接线随 **#1109**。
3. **不引外置 OPA**：不引入 OPA server/sidecar、不引入 Rego 语言面、不引入每决策网络 hop。

### 2.1 对标依据

| 维度 | OPA（外置 PDP） | Cedar / Biscuit（嵌入式 PDP） | RSS 当前 |
|------|----------------|------------------------------|----------|
| 决策路径 | Rego → policy bundle → OPA sidecar/server → 每决策 HTTP `POST /v1/data/{path}` | `Authorizer::is_authorized(&self, r, p, e) -> Response`（进程内同步、无网络） | `resolve_requirement(plan, opt_out) -> AuthRequirement`（进程内同步、无网络） |
| 策略作者 | 可非 Rust 工程师，写 Rego | Rust / DSL（编译期 typed） | Rust 工程师（编译期 typed） |
| 运行期换策略 | ✅ bundle 热加载、免重启 | ❌ 需重编译 / 重部署 | ❌ 需重部署 |
| 代价 | sidecar/server 基建 + 网络 hop + Rego 语言面 | 进程内、零基建 | 进程内、零基建 |

Cedar 的 `Authorizer::is_authorized(&self, r: &Request, p: &PolicySet, e: &Entities) -> Response`（同步、进程内、无网络）与 RSS `resolve_requirement` **同形**——印证「内置 typed PDP 是成熟工业形态，编译期能静态守住策略错误」。Biscuit（能力令牌，token facts + policy 均进程内评估、无网络 hop）为第二旁证。OPA 的核心价值（运行期热更新 + 非 Rust 作者）在 RSS 当前**单进程 pre-GA、策略唯一作者是 Rust 工程师、无 hot-swap 需求**下不成立——引 sidecar 是纯基建税。

### 2.2 一致性声明（`diport::Pdp` 归属，防误判缺 amendment）

`diport::Pdp` 的 trait 签名只引用**基础层 / `generated` wire / port 自身定义的类型**（如 port-own 的 `RawCredential` / `VerifiedClaims` / `PdpError`，仿 `AuditSink::record(AuditEvent)` 中 `AuditEvent` 为 diport 自定义扁平类型的既有范式）——**不引用任何域内实体**。按 **ADR-005 §2.1 category line**（「port 签名只引基础/wire/port-own → 归 `diport`；引域实体 → 归域 crate」），`Pdp` 是 **provider-agnostic infra port**，正确归 `diport`，与 ADR-003「provider-agnostic port 收敛 diport」**完全一致**。故本 ADR **不 amend** ADR-003 / ADR-005，仅在其既定范式内新增一个 port 接缝判定。

---

## 3. 范式（落地代码）

> **形状草稿**：以下为接缝形状示意，**以 ADR-003 落地结论 + `crates/diport/src/` 既有 port 写法为准**（dynosaur exact-pin；PDP 自 #1828 起显式 `Send + Sync`）；#1109 实施前须对照既有 port 校对宏参数形式，防止复制偏差。

```rust
// crates/diport/src/pdp.rs —— 预留接缝（本 PR 不交付，形状随 #1109 细化）
// 派发范式继承 ADR-003：native AFIT + Send 变体 + dynosaur dyn wrapper + 构造器 Box<DynX> 注入。
use dynosaur::dynosaur;

/// 入站原始凭据（port-own 扁平类型；不引 authn::Jwt/AccessToken，保 category line）。
pub struct RawCredential { /* token bytes / scheme tag，#1109 细化 */ }
/// 验签后裁定的 claims（port-own；authn 侧据此 mint Principal）。
pub struct VerifiedClaims { /* subject / tenant / scopes，#1109 细化 */ }

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PdpError { /* InvalidSignature / Expired / Untrusted，#1109 细化 */ }

#[trait_variant::make(Pdp: Send)]
#[dynosaur(pub DynPdp = dyn(box) Pdp, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait PdpLocal: Send + Sync {
    /// 验签 + claims 派生（I/O：可能查 JWKS / 调外置引擎）。
    async fn verify(&self, raw: &RawCredential) -> Result<VerifiedClaims, PdpError>;
}
```

**Async-serving addendum（#1828）**：验签实现可能等待远程 I/O，middleware 必须直接 await verifier；
`PdpLocal` / `Pdp` 的 `Send + Sync` 是共享 serving state 的类型约束，不得用同步首轮 poll 代替。bridge
不拥有局部 verifier timeout；终止性由 mandatory `ServerRequestBudget` 在唯一 HTTP bindable funnel 包住完整
request future，耗尽 drop verifier + handler 且经共享 503 `ERR_CORE_UNAVAILABLE` envelope 表达。

**authplan 侧不变**：`resolve_requirement` 仍是纯函数，PDP 消费其输出（`AuthRequirement::Require(scheme)`）+ `RequestCtx`，**不反向耦合**——authplan 决定「这条 route 要不要认证、要哪种 scheme」，`Pdp` 决定「这份凭据是否有效、派生谁」。组合根经构造器必填位置参注入 `Arc<P>`，其中 `P: Pdp + Send + Sync + 'static`（prod = 内置验签器 / 未来 OPA 客户端；test = mock）；authn funnel 内借为 `&DynPdp`。

---

## 4. 后果

- **正**：授权决策进程内、编译期 typed（最小基建、零网络 hop）；`diport::Pdp` 接缝按 ADR-003 既定范式预留，未来换外置 OPA 只在 port 边界换 impl、不动 authplan / 域；符合「先内置简单 impl、port 预留、按需换外置」的分阶段节奏；与 #1109（验签接线）天然衔接。
- **负 / 代价**：现阶段策略作者锁定为 Rust 工程师、策略变更需重部署（无运行期热更新）——这是 pre-GA 单进程下可接受的取舍，由 §4.1 切换判据兜住升级路径。
- **负 / 安全空窗（见 §5 威胁矩阵）**：历史窗口曾把签名 / MAC / exp 校验停在 **Soft** 约定（rustdoc + 本 ADR）；#1109 / Closeout addendum（#1584 / #1586）后已收口为 Hard `VerifiedClaims` mint——httpserve 认证挂载不得在 verifier 未就绪时接线生产可达的认证路径。
- **负 / 可观测**：内置授权决策须显式埋点——httpserve middleware / `resolve_requirement` 调用点埋 tracing span（`authz.decision = allow|deny`、`authz.scheme`、`authz.route`），保留与外置 OPA decision log 等价的可观测颗粒度（对齐 `tenancy.md` 的「gRPC 与 HTTP 同一 PDP 决策指标 family」），随 #1109 落地交付。
- **下游**：#1109 落地 `diport::Pdp` trait + `VerifiedClaims` mint funnel + httpserve↔authn 验签接线；W 阶段域行为消费 `AuthRequirement`，不感知 PDP 是内置还是外置。

### 4.1 切换判据（内置 → 外置 OPA，登记备查）

任一成立即重评引入外置 OPA：

1. **策略作者不再只是 Rust 工程师**：需要非 Rust 角色（安全 / 合规）用 Rego 编写、且运行期免重启推送。
2. **复杂 ABAC 超出 Rust enum-match 可维护范围**：跨多域规则图，需 OPA partial evaluation / bundle + data API。
3. **跨 trust domain / 跨集群**：策略需分布式同步（OPA bundle）。
4. **合规要求策略变更有独立审计且与代码部署解耦**。

迁移成本低（这是现在就选内置的关键理由）：`Pdp` port 已预留，外置 OPA 即新增一个 `OpaPdp: Pdp` impl 在组合根注入，authplan / 域零改动。

---

## 5. 威胁矩阵 / amendment 声明

**amendment 声明**：本 ADR **不 amend** ADR-003 / ADR-005（§2.2 已论证 `diport::Pdp` 按 category line 正确归 `diport`）；既有安全守卫（dynosaur 宏收敛 `DIPORT-MACRO-CONFINE-01′`、impl-allowlist `DIPORT-IMPL-ALLOWLIST-01`（#1060）、dynosaur unsafe def-site hygiene）**不退化**——本 ADR 仅在既定范式内新增一个 port 接缝判定，威胁面无既有项变化。新增威胁如下：

| 威胁 | 暴露条件 | 缓解 | enforcement 档位 |
|------|---------|------|-----------------|
| **未验签认证绕过** | 历史窗口中 `authn` 曾仅结构化解码、不验签名/MAC/exp；若把 httpserve 认证路径接线到生产可达端点，等价零验签放行 | httpserve 认证挂载与 verifier 必须同批上线；`finalize_auth` 默认拒兜底；verifier 未就绪时不得接线生产认证 matcher | Closeout 后 **Hard**（`VerifiedClaims` 仅 Pdp mint + 构造器必填注入） |
| 内置 PDP 误判放行 | `resolve_requirement` 逻辑错误 | 纯函数 + 表驱动单测（引擎 ≥90% 覆盖）；`AuthRequirement::Deny` 为无 plan / 非法 opt-out 的 fail-closed 默认 | **Hard**（类型：`AuthRequirement::Require` 不含 `NoAuth`，杜绝「要求无认证」自相矛盾） |
| 推迟外置 OPA 后策略变更无独立审计 | 合规要求策略审计与部署解耦 | §4.1 切换判据 4 触发引外置 OPA（decision log） | 决策记录（切换判据兜底） |

---

## 6. AI-robust 分级（本 ADR 引入 / 修改的 enforcement）

| 约束 | 评级 | 载体 |
|------|------|------|
| 本 ADR 为纯决策记录，**当前不新增 enforcement** | —（N/A） | 决策方向 + 切换判据成文；无机器守卫新增 |
| typed `diport::Pdp` 定义面只在 `diport`（上游） + impl 面仅 adapter/组合根（下游） | **Medium（cargo-deny + dylint）** | 上游定义面：dynosaur/trait-variant 宏收敛白名单（`DIPORT-MACRO-CONFINE-01′`，cargo-deny + xtask，Medium）；下游 impl 面：AST 级 impl-site allowlist（`DIPORT-IMPL-ALLOWLIST-01`，dylint #1060，Medium——sealed-trait 无法对独立 adapter crate 跨 crate Hard 封闭，dylint 为最强可用载体）。**非 Hard**（与 ADR-005 §6 同源评级） |
| 未来 PDP 必填注入 + `VerifiedClaims` 仅 Pdp mint + `from_verified_*` 入参 newtype | **Hard（类型 / 可见性 / 构造器）** | `Arc<P>` 构造器必填位置参且 `P: Pdp + Send + Sync + 'static`（缺失或 provider 不可跨 serving task 共享即编译错误，继承 ADR-004 C5）；`VerifiedClaims` 私有构造 funnel + `from_verified_*` 仅收 newtype 而非裸 token（类型层杜绝旁路 mint）——这是本接缝**真正 Hard** 的部分（与上行 Medium 的 define/impl 守卫互补） |
| 异步 PDP 永久 Pending 占用 request task | **Hard + Medium** | 非零 `ServerRequestBudget` 必填参数 + 不实现 axum make-service 的私有字段 `ServerService` capability + httpd 双 transport 同一入参，使无预算 bind 不可表达（Hard）；`server_budget_structure` 锁 runtime snapshot 注入、httpserve timeout 层与 httpd plaintext/mTLS 单路径，且 `auth_bridge_structure` 拒绝局部 timeout（Medium，均有 synthetic-red + anti-vacuity） |

无 Soft 新增 enforcement。

---

## 7. 备选（为何不取）

- **现在就引入外置 OPA + Rego**：获得运行期热更新 + 非 Rust 作者。**否决**——RSS pre-GA 单进程、策略唯一作者是 Rust 工程师、无 hot-swap 需求；sidecar/server + 每决策网络 hop + Rego 语言面是过早基建税。其价值场景由 §4.1 切换判据触发时再引入（port 已预留，低成本）。
- **内置但放弃 `Pdp` port 接缝（YAGNI）**：现在连 port 都不留。**否决**——authn 已显式依赖 typed `diport::Pdp` 做验签（#1109），W 域 body 硬化后再补接缝爆炸半径大；ADR-003 provider-agnostic port 范式使预留几乎零成本，放弃反而割裂既有设计。

---

## 8. Follow-up

- **`diport::Pdp` 落地（#1109）**：定义 `Pdp` trait（按 §3 范式）+ port-own `RawCredential` / `VerifiedClaims` / `PdpError` 扁平类型 + `VerifiedJwt`/`VerifiedClaims` mint funnel（仅 Pdp 验签后 mint）+ httpserve↔authn 验签接线 + dynosaur 白名单 / impl-allowlist 同步。本 ADR 为其方向依据。**#1109 最低验收门槛（可机器判定，防只交付 trait 骨架不接验签）**：① `VerifiedClaims` 类型仅在 `diport::pdp` 模块定义、无旁路 mint 路径；② `authn::Principal::from_verified_*` 入参必须是 `VerifiedClaims`/`VerifiedJwt` newtype 而非裸 token bytes；③ httpserve↔authn 验签接线有集成测试覆盖（含拒绝路径）；④ dynosaur 宏依赖白名单（`DIPORT-MACRO-CONFINE-01′`）经 `cargo xtask verify` 无新增越界。
- **切换判据复核点**：趋近 GA / 出现跨集群部署时，按 §4.1 复核是否引外置 OPA。

## 对标证据（ref）

- `ref: cedar-policy/cedar cedar-policy/src/api.rs@main` — 嵌入式 typed authz `Authorizer::is_authorized(&self, r, p, e) -> Response`（进程内同步、无网络），印证内置 typed PDP 工业形态，对应 RSS `resolve_requirement`。
- `ref: open-policy-agent/opa v1/rego/rego.go@main` — 外置 PDP `rego.New` + `PreparedEvalQuery.Eval`，抽取「策略当数据 / bundle 热加载 / 每决策网络 hop」代价面（偏离不取）。
- `ref: eclipse-biscuit/biscuit-rust biscuit-auth/src/lib.rs@main` — 能力令牌进程内 facts+policy 评估、无网络 hop，内置授权第二旁证。
