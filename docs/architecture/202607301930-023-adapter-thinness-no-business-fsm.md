# ADR-023：Adapter 厚薄纪律 — 禁业务 FSM / 禁重写成熟协议

- **Status**：Accepted
- **Date**：2026-07-30
- **关联**：issue **#1494**（`[RW-W-hardening] adapter 厚薄纪律 ADR + dylint rss_adapter_no_business_fsm`）
- **出处**：`docs/analysis/202606271729-001-rss-implementation-resequence-six-role.md` §1 D3 / D11 · §4 未冻结边界
- **AI-robust 评级**：Medium（`deny.toml` ban）+ Medium（dylint）——**无 Soft**（cargo-deny / dylint 均为 Medium 载体，见 `docs/rules/ai-robust.md`）

---

## Context

GoCell 时期 S3 / OIDC adapter 经历 build→delete→thin 重建多轮，根因是 **thick/thin 纪律未先机判化**（分析 defer 根因 D3）：adapter 在 port 未冻结、厚薄未守的情况下长成业务状态机或手写成熟协议栈，随后整体推倒换成 SDK。

RSS 现有多个 thin adapter stub 待填 body。若不先立机器守卫，AI / 人工填 body 时极易：

1. 在 `adapters/` 内维护可推进的业务生命周期 FSM（本应落 domain / `consistency` / `deviceloop`）；
2. 手写第二套 JWKS / SigV4 / TLS 等成熟协议（D11），而非薄委托已 pin 的 SDK / RustCrypto。

既有 `deny.toml` 已对 JWT 供应链（`jsonwebtoken`）与 TLS 族做 Medium ban；OIDC / S3 的对标 pin 落在 [`docs/references/framework-comparison.md`](../references/framework-comparison.md)。缺的是 **adapter 业务 FSM** 面的双 Medium 保险，以及把 D11 升为「指向既有机器载体」而非 Soft commit 公约。

## Decision

**Adapter = 薄委托层**：把 `diport` / 域 port 调用映射到外部 SDK、broker、DB driver 或 RustCrypto；**不**承载业务生命周期状态机，**不**重写已有成熟协议实现。

| 允许（薄） | 禁止（厚） |
|------------|------------|
| 连接 / 健康 / readiness 探针映射 | 在 adapter 内维护可 `next`/`transition`/`advance`/`step` 推进的业务 `*State`/`*Phase`/`*Lifecycle` 过渡表 |
| JWKS refresh、lease/CAS、重试退避的**协议/基建**映射与持久化 | 引入 FSM 框架（如 `statig`）驱动业务态 |
| DB ↔ domain 翻译、错误码映射、wire DTO 边界 | 手写 SigV4 / JWKS 第二套 crypto / TLS 栈（须走 framework-comparison 已 pin SDK / RustCrypto） |
| 标签枚举（仅 `as_str` / 序列化，无过渡方法） | 把 domain 生命周期收敛逻辑下沉进 adapter |

业务生命周期 FSM 只属于 domain / 引擎（`consistency` / `deviceloop` / `identity` …）。Adapter 内允许**非过渡**的标签 / 结果枚举（如投递相位标签、结算结果变体），只要不同时提供推进方法。

**D11 协议薄委托**不另立 Soft「commit 必须写 `ref:`」公约；强制载体见下表「协议薄委托」行——既有 `deny.toml` JWT/OIDC ban + framework-comparison pins（及 adapter 对 `aws-sdk-s3` / RustCrypto 的依赖事实）。

## Enforcement

| 约束 | 级别 | 载体 | INVARIANT |
|------|------|------|-----------|
| adapters（及全仓）不得依赖 `statig` FSM 框架 | **Medium** | `deny.toml` `[bans].deny` `{ crate = "statig" }`（图外 no-op；一旦引入即 `deny check bans` 失败；cargo-deny = Medium，见 ai-robust.md） | ADAPTER-THIN-FSM-01 |
| `adapters/*` 不得 `use`/`path` 引用 `statig`；不得定义「`*State`/`*Phase`/`*Lifecycle` + `next`/`transition`/`advance`/`step`」过渡表形态 | **Medium** | dylint `rss_adapter_no_business_fsm`（`cargo dylint --all`，`DYLINT_RUSTFLAGS=-D warnings` fail-closed） | ADAPTER-NO-BUSINESS-FSM-01 |
| 协议薄委托（OIDC/S3/TLS）：禁回流 `jsonwebtoken` / native-tls 族；OIDC 走 RustCrypto；S3 走 `aws-sdk-s3` pin | **Medium** | 既有 `deny.toml` JWT/OIDC/TLS bans + [`framework-comparison.md`](../references/framework-comparison.md) pins（不新增 Soft commit 公约） | （既有 OIDC-ALG-KEYPATH-01 等；本 ADR 不重挂 Soft） |

Hard-化评估（业务 vs 基建过渡表）：跨 crate「业务语义」无法用类型系统封闭；依赖图 ban 只能挡住具名 FSM crate。AST 形态守卫是最强可用 Medium 载体（同 `rss_pdp_impl_adapter_only` 范式）。误报以**改名 / 上移 domain** 消除，禁止批量 `#[allow]` 债；单项 `#[allow(rss_adapter_no_business_fsm)] // reason:` 仅作审查级逃生门。

## Consequences

- 填 adapter body 前即有机器门：引入 `statig` 或过渡表形态会在 deny / dylint 失败，避免 GoCell 式厚实现再推倒。
- 现有标签枚举（如 `PublishPhase` / `SameIdDeliveryPhase`，仅标签方法）不触发；若将来加上推进方法须先重构命名或上移。
- D11 不再靠 Soft 散文；新协议栈若绕开已 pin SDK，须先改 deny / 对标表并论证（显式决策，非默认可合入）。
- 与 #1495 ready-signal 纪律同属 RW-W-hardening，共享 `lints/` 注册面，但本 ADR 范围仅 adapter 厚薄。
