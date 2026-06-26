# ADR-002：context 控制流值传播（tenant / principal）

> 状态：Accepted · 日期：2026-06-21 · 架构决策序列：**决策 #2** · spike：RW-G0.4（#994）· epic：#991
>
> 上游冻结：`docs/migration-from-gocell/gocell-rust-crate-mapping.md` §二.1 ·
> `docs/migration-from-gocell/gocell-rewrite-sequence.md` §P1.5
>
> 约束源（本 ADR 引用、不复述）：`docs/rules/architecture.md` §分层 · `docs/rules/tenancy.md` ·
> `docs/rules/observability.md` · `CLAUDE.md`
>
> 落地：`crates/runctx`（reference seam）
>
> 本文同时确立 RSS 的 **ADR 模板**：背景 / 决策 / 范式 / 后果 / 威胁矩阵 / 备选。

---

## 1. 背景（Context）

GoCell（Go）用单一 `context.Context` 同时承载两类语义完全不同的东西：

- **可观测 ID**：trace / correlation / request / cell —— 诊断信号，喂 slog + otel + 关联。
- **控制流值**：tenant / principal —— 授权判定的输入（RLS tenant 边界、`RowScope` 派生、PDP 决策）。

外加取消（cancel）与 deadline。Rust **没有 ambient context**，三条直译路都更差（`gocell-rust-tradeoff.md` §1）：
显式传参污染几乎每个函数签名；纯 `tokio::task_local` 对这套丰富 ID 集很别扭；自建 Context struct 到处传又回到显式传参。

而 P2 组合根（装配骨架 + listener）会重度依赖「ctx 全程穿透」。若不先冻结传播接缝，P2 之后到处返工
（`gocell-rewrite-sequence.md` §P1.5：「**必须在动 P2 之前先定**」）。本 ADR 即该接缝冻结的形式化记录。

关键事实：诊断信号与授权控制流**本质不同**——span 字段可被采样丢弃、可被任意层改写、是字符串擦除的；
而 tenant/principal 是 row-scope 授权闸门的输入，必须精确、不可丢、不可被下游伪造。二者混在一个载体里
是 GoCell 的历史包袱，Rust 重写**必须拆开**。

## 2. 决策（Decision）

### D1 — 可观测 ID 与控制流值二分

- **可观测 ID**（trace / correlation / request / cell）→ `tracing` span 字段，自动传播，同时喂日志与 otel。
- **控制流值**（tenant / principal）→ 显式 `runctx::RequestCtx`，**不进 tracing**。

举证：`docs/rules/tenancy.md` 已规定跨租户访问「**必须写持久 audit ledger**……tracing span 仅作关联信号、
不替代持久审计」。即诊断载体在本仓本就**不可作授权 load-bearing**。span 字段可丢弃 / 可改写 / 字符串擦除，
不配做 row-scope 闸门。

### D1-bis — 可读诊断 context 信道（diagctx，#1160 amendment）

§D1 把诊断 ID 路由进 `tracing` span 喂日志 / otel；但 `tracing` **无 span 字段读回 API**，而 outbox metadata
需在 emit 点**读回** correlation 盖章（#1296）。故新增一条**与 span 平行的可读诊断信道** `diagctx`（base 层
独立 crate）：

- **归属与隔离**：`diagctx` 与 `runctx` **物理隔离**（不同 crate / 不同 task_local / 不同类型）。授权码
  `use runctx`、诊断码 `use diagctx`，「诊断信道被误读为授权源」是一处可被 review 一眼抓的跨 import。
  `diagctx` 刻意**不依赖 `tracing`**（不给 §D1 的 runctx↛tracing Hard 边界开口）、不依赖 `vocab` / `serde`。
- **失败语义刻意相反**：`diagctx::correlation()` 缺失返回 `None`（**fail-open** 省略），与 §D6 `runctx` 的
  fail-closed deny 相反——诊断信号丢失只损可观测关联，**不损正确性 / 安全**，**不被任何授权闸门读取**。
- **写 / 读接缝**：httpserve correlation middleware 经 `CorrelationId::parse`（注入防护）解析入站
  `X-Correlation-ID` → `diagctx::scope` 每请求绑定一次；outbox emit adapter 经 `diagctx::correlation()`
  读回。span 字段仍是喂日志 / otel 的载体，diagctx 是「读回」载体，二者 **middleware 单源解析、双载体派生**。

§D1 钉死的是「诊断信号**不得进授权用的** `RequestCtx`」+「runctx↛tracing 依赖图不可互通」——本决策**都不违反**：
diagctx 是另一个 crate / 另一个 task_local，没有任何授权闸门读它，也没给 runctx 加任何边。§D1 未禁止「存在一条
可读诊断信道」；D1-bis 是 §D1 二分在「诊断需读回」维度上的细化扩展。

### D2 — RequestCtx = 显式 sealed struct + task_local! 传播（混合范式）

`RequestCtx` 是显式、不可变、sealed 的授权快照；经 `tokio::task_local!` 传播：

- 框架信任边界（httpserve middleware / authn）用 `runctx::scope(ctx, fut)` **绑定一次**；
- 深层代码用 `runctx::try_with(|c| …)`（免 clone）/ `runctx::try_current()`（clone）**取用**；
- 需要把 ctx 喂 PDP / repo 的地方仍**显式传 `&RequestCtx`**（类型安全），不靠到处隐式读。

非纯隐式（避免「魔法 ambient」难追踪），非纯显式穿透（避免污染 P2 后每个签名）。

### D3 — base 层 payload 归属与 layering

- `TenantId` 归 `vocab::tenant`；`Principal` 归 `authn`（service 层，`Principal::row_visibility` 在此派生）。
- **`runctx → authn` 被 cargo 禁止**：`authn` 已依赖 `runctx`，反向即闭环。故 **principal 永不可被 runctx
  按具体类型持有**，必须 trait / 泛型擦除——这是 layering 的硬结论，与下面选哪个无关。
- base 层规则（`architecture.md` §分层 / `CLAUDE.md`）：基础 crate 不依赖上层；基础层**内部**按 enumerated
  intra-base DAG `vocab ◁ ids ◁ secure ◁ support ◁ runctx`（右可依赖左、反向禁止）单向依赖。`RequestCtx<T, P>`
  保持双泛型（把 runctx 对具体 payload 的耦合收敛到 `AppCtx` 单一别名点），principal 仍 trait/泛型擦除。
- **intra-base sub-DAG —— 本 PR（#1032）已落地**：sanctioned 边 `runctx → vocab`；`AppCtx` 的 tenant 收敛为
  具体 `vocab::tenant::TenantId`（带「空 / nil / 非 canonical 非法」fail-closed 校验），`TenantSlot` 占位删除；
  principal 仍 `PrincipalSlot` 占位（W 阶段由 authn principal facet 取代——`runctx → authn` 闭环禁止，principal
  永不可被 runctx 按具体类型持有）。base 规则措辞 + 决策 #2 回填同 PR 落（`INVARIANT: BASE-INTRADAG-01`）。备选见 §6。

### D4 — 取消 / deadline 不进 RequestCtx

取消与 deadline 走 `tokio_util::sync::CancellationToken`（显式传给后台环 / 被 await 的 future），
**不**放进 `RequestCtx`。理由：取消是带不同生命周期与所有权的 capability handle（可 clone、可 select、
可派生 child token），与「`RequestCtx` 是不可变授权快照」的不变式正交；混入会迫使 ctx 携带共享可变状态。
本 spike 不引入 `tokio-util`（仅记边界）。

### D5 — 构造边界：仅已认证通道

`RequestCtx` **只**能从已认证通道构造：JWT tenant claim（验签后）或 service-token-MAC 的 `X-Tenant-ID`
header（`docs/rules/tenancy.md` §Tenant source）。**HTTP request body 不得携带 tenantId**——body 是未认证维度。

类型层强制分两条，强度不同，须如实区分：

- **body 反序列化构造不可表达（Hard）**：`RequestCtx` 私有字段 + **不 derive `Deserialize`** ⇒ 「从 body
  反序列化出一个 RequestCtx」在类型上不可表达。上游另由契约 codegen 拒绝声明 `tenantId` 的 request schema（`tenancy.md`，Hard）。
- **下游 crate 直接 `new` 伪造不可表达（Hard，具体 `AppCtx`）**：`AppCtx = RequestCtx<vocab::tenant::TenantId, PrincipalSlot>`
  的 principal payload（`PrincipalSlot`）构造器是 `#[cfg(test)] pub(crate)` + 字段私有 ⇒ 外部 crate **无构造路径**，无法
  mint 一个 `AppCtx`（crate 可见性，Hard）——伪造门收敛到 principal 接缝。tenant 虽是公有可解析的 `TenantId`，但其 `parse`
  fail-closed 拒空 / nil / 非 canonical，无法 mint 非法 tenant。`RequestCtx::Debug` 手写 redacted（不打印 tenant/principal
  payload），杜绝 `?ctx` 泄露授权 PII；`TenantId` 自身 `Debug` 有意可见（UUID 是可观测标识、非凭据）。
- **泛型 `RequestCtx::new` 的 trusted-caller 门（W 阶段）**：泛型构造对任意 `T/P` 开放——「只在已认证通道构造」
  这一条对泛型入口当前仍是**约定**（rustdoc/ADR），其类型化（sealed capability，由 authn 验签后持有并传入）随 authn 落
  W 阶段；届时具体实例化已收敛为受信 `vocab::TenantId` + authn principal facet，trusted-caller 成 Hard。

### D6 — fail-closed：ctx 缺失即 deny

读访问器返回 `Result<_, MissingCtx>`；当前任务不在任何 `scope` 内时返回 `Err(MissingCtx)`，
**绝不**伪造 anonymous / default-tenant，**绝不** panic（注意 tokio `LocalKey::with`/`get` 未绑定时会
panic，故 runctx 只封装 `try_with`；且 workspace `panic`/`unwrap_used`/`expect_used` 均 deny）。
调用方据此 fail-closed（deny / 401 / 403）。对齐 `tenancy.md` PDP「缺租户 → deny」、
`row_visibility` 的 service / anonymous / unknown → fail-closed。

## 3. 范式（Pattern）

落地于 `crates/runctx`（`ref: tokio tokio/src/task/task_local.rs` 的 `LocalKey::scope` / `try_with`）：

```rust
// ctx.rs —— 不可变授权快照，sealed 私有字段，无 Deserialize。
pub struct RequestCtx<T, P> { /* tenant: T, principal: P（私有） */ }
impl<T, P> RequestCtx<T, P> {
    pub fn new(tenant: T, principal: P) -> Self;   // 唯一构造入口（须在已认证通道）
    pub fn tenant(&self) -> &T;
    pub fn principal(&self) -> &P;
}
pub type AppCtx = RequestCtx<vocab::tenant::TenantId, PrincipalSlot>; // #1032：tenant 已收敛为 TenantId；principal 仍占位

// local.rs —— task_local! 传播 + fail-closed 访问器。
pub fn scope<F: Future>(ctx: AppCtx, fut: F) -> TaskLocalFuture<AppCtx, F>; // 边界绑定一次
pub fn try_with<R>(f: impl FnOnce(&AppCtx) -> R) -> Result<R, MissingCtx>;  // 免 clone 取用
pub fn try_current() -> Result<AppCtx, MissingCtx>;                        // clone 取用
pub struct MissingCtx; // thiserror；ctx 缺失 = deny
```

**spawn 传播范式（必须遵守）**：`tokio::spawn` / `spawn_blocking` / `std::thread` **不继承** task_local。
跨任务时：

```rust
// ✗ 错：子任务 fail-closed（看不到父 ctx）
tokio::spawn(async { try_current() /* Err(MissingCtx) */ });

// ✓ 对：spawn 前捕获，子任务内重绑
let ctx = try_with(Clone::clone)?;          // 在父任务内捕获
tokio::spawn(scope(ctx, async { /* try_current() => Ok */ }));
```

**consumer 侧 span 注入约定**：trace / correlation / cell 由 httpserve middleware / observ 写成 `tracing`
span 字段（这些 crate 依赖 tracing）；runctx **不依赖 tracing**，二者在依赖图上不可互通（D1 的 Hard 载体）。

## 4. 后果（Consequences）

**正向**：
- 授权输入与诊断信号在**类型 + 依赖图**层分离，误用不可表达（D1/D5 是 Hard）。
- P2 组合根可直接采纳 `scope`/`try_with`，签名不被 ctx 污染。
- 一个进程一套 auth 模型 ⇒ `task_local!` 单实例足够，无需 box。

**负向 / 摩擦**：
- 泛型 `RequestCtx<T, P>` 的类型参数会出现在 consumer 签名；用 `AppCtx` 别名收口，consumer 名别名而非裸泛型，
  (b) 迁移时改一处。
- spawn / blocking / std::thread 不继承 ctx 是 footgun（R2）。**运行时**已 fail-closed（子任务读到 `Err`，
  测试锁定 `tokio::spawn` / `spawn_blocking`）；**静态防误用**（拦截「忘记重绑」的 callsite）原为 Soft，
  现由 dylint `rss_spawn_missing_scope`（#1031）承载，**对其覆盖的 spawn 入口升到 Medium**（见 §威胁矩阵 + follow-up 4）。
  - **生产 consumer 接入前置门——按覆盖入口部分解除（勿过度宣称）**：#1031 落地前曾要求**生产 crate（httpserve /
    authn / eventexec / reconcile 等）不得采用 spawn-跨任务-ctx 传播**（避免以 Accepted ADR 合入 Soft，spike 期仅
    runctx 自测演示）。lint **只覆盖自由函数 `tokio::spawn` / `tokio::task::spawn_blocking`** 形式，对其而言静态防误用
    已到 Medium——**这两类形式的前置门解除**：生产 crate 可采用「捕获-重绑」范式，漏重绑由 lint 在 `cargo xtask verify`
    中 fail-closed 拦截。
  - **lint 不覆盖的 spawn 入口前置门仍在（Soft，人工 review gate）**：方法形式 spawn（`JoinSet::spawn` / `spawn_on`、
    `LocalSet::spawn_local`，parent 为 impl 被排除）、`std::thread::spawn`、以及被 wrapper fn 包装的 `tokio::spawn`
    （callsite crate 名非 `tokio`）——这些入口同样不继承 task_local，但 lint **不报**，故承载 ctx 传播仍属 Soft，
    必须人工 review gate（不得无守采用）。完整盲区（含 intraprocedural、`#[cfg(test)]` 默认不扫）见
    `lints/rss_spawn_missing_scope/` rustdoc `### Known problems`。

**下游影响**：httpserve middleware（绑 `scope`）、authn（构造 `RequestCtx` + 派生 `Principal`/`row_visibility`）、
后台环 crate（`eventexec` / reconcile 扇出必须捕获-重绑 ctx）——均为后续 W 阶段 feature。

**follow-up 状态**：
1. ~~base 层规则措辞改为 enumerated intra-base DAG（`architecture.md` §分层 + `CLAUDE.md`），sanction
   `runctx → vocab/ids` 边并加 `INVARIANT`~~ **已落地（#1032）**：base 规则改为 enumerated intra-base DAG（`INVARIANT: BASE-INTRADAG-01`）；
2. ~~`architecture.md` 决策表内联回填「决策 #2 → 本 ADR」（仿决策 #1 体例）~~ **已落地（#1032）**：核心载体表加 context 控制流值行，回填「决策 #2 → ADR-002」；
3. ~~随引入 `vocab::tenant::TenantId` 的 feature 把 `AppCtx` 的 tenant 换成具体类型~~ **已落地（#1032）**：实现 `TenantId::parse`（fail-closed 校验）、`AppCtx` tenant 换成 `vocab::tenant::TenantId`、删 `TenantSlot`；
4. ~~dylint `rss_spawn_missing_scope`：静态拦截「子任务内读 ctx 却未在外层重绑」的 callsite，
   把 spawn footgun 的静态防误用从 Soft 升到 Medium（见 §威胁矩阵）。~~ **已落地（#1031）**：见 §威胁矩阵
   该行——**自由函数 `tokio::spawn`/`spawn_blocking` 形式**已改 Medium、其前置门解除；未覆盖入口（JoinSet 方法 /
   spawn_local / std::thread / wrapper-fn）仍 Soft（§后果 R2）。lint 在 `lints/rss_spawn_missing_scope/`（INVARIANT
   SPAWN-CTX-REBIND-01）。**后续**：扩 lint 覆盖未覆盖入口、或 `CtxBound` 类型 Hard 化（§6）——按需另立 issue。

## 5. 威胁矩阵（Threat Model）

| 威胁 | 后果 | 缓解 | enforcement 档位 |
|------|------|------|------------------|
| request body 携带 `tenantId` 冒充租户 | 跨租户写 | `RequestCtx` 私有字段 + 无 `Deserialize`（body 构造不可表达）；契约 codegen 拒绝 `tenantId` request schema | **Hard**（类型 + codegen funnel） |
| 下游 crate 直接 `RequestCtx::new` 伪造 `AppCtx` | 伪造 tenant/principal 越权 | `AppCtx` 的 `PrincipalSlot` 构造器 `#[cfg(test)] pub(crate)` + 字段私有 ⇒ 外部无构造路径（伪造门收敛到 principal 接缝）；tenant 虽公有可解析，但 `TenantId::parse` fail-closed 拒空/nil/非 canonical，无法 mint 非法 tenant；泛型 `new` 的 trusted-caller capability 随 authn 落 W 阶段 | **Hard**（具体 `AppCtx`，crate 可见性 + `TenantId` fail-closed 解析）+ 约定→W 阶段 Hard（泛型入口） |
| `?ctx` / 断言 / 日志泄露 tenant/principal 原值 | 授权 PII 入日志 | `RequestCtx` 手写 redacted `Debug`（不打印 payload、不要求 `T/P: Debug`）；`PrincipalSlot` Debug 同样 redacted（`TenantId` Debug 有意可见——UUID 是可观测标识、非凭据） | **Hard**（类型，payload 在 Debug 通道不可达） |
| ctx 缺失被当作 anonymous / default-tenant 放行 | fail-open 越权 | 读访问器返回 `Result`，缺失 = `Err(MissingCtx)`，无 panicking / 伪造路径；PDP 缺租户 deny | **Hard**（类型）+ **Medium**（fail-closed 行为测试） |
| tenant / principal 被塞进 tracing span 后被下游误当授权源 | 授权基于可丢弃 / 可改写信号 | runctx **不依赖 tracing**，API 面无「ctx→span」通道 | **Hard**（crate 依赖图） |
| spawn / blocking 出的任务**运行时**丢 ctx → 子任务读到空 | 后台越权 / fail-open | 子任务无 ctx 即 `Err(MissingCtx)`，调用方 fail-closed | **Medium**（fail-closed 运行时行为 + 测试锁定 `tokio::spawn` / `spawn_blocking` 不继承） |
| consumer **静态忘记**在子任务「捕获-重绑」ctx | 同上 | dylint `rss_spawn_missing_scope`（#1031 已落）：AST 级拦截 **自由函数 `tokio::spawn`/`tokio::task::spawn_blocking`** 子任务体内读 `runctx::try_*` 而未在外层 `runctx::scope(...)` 重绑的 callsite；经 `cargo xtask verify` 的 `DYLINT_RUSTFLAGS=-D warnings` fail-closed。符号/红例/盲区见 `lints/rss_spawn_missing_scope/` rustdoc（INVARIANT SPAWN-CTX-REBIND-01） | **Medium（仅覆盖入口）**：自由函数 `tokio::spawn`/`spawn_blocking` = dylint AST lint，CI fail-closed，其前置门已解除。**未覆盖入口仍 Soft**：方法形式（`JoinSet::spawn`/`spawn_on`、`LocalSet::spawn_local`）、`std::thread::spawn`、wrapper-fn 包装的 spawn lint 不报，承载 ctx 传播须人工 review gate（见 §后果 R2）。Hard 化须 `CtxBound` 类型（覆盖全部入口、侵入 consumer 签名，见 §6，未立项） |
| `RowScope::All` 经非 super-admin 路径泄漏 | 全租户读 | runctx 不构造 RowScope；派生在 authn super-admin 路径 + 强制 audit ledger（`tenancy.md`） | 引用 `tenancy.md`（非本 ADR 新增） |
| 诊断 `diagctx` correlation 被误当授权源（D1-bis，#1160） | 授权基于可丢弃 / 可改写诊断信号 | `diagctx` 独立 base crate（crate 图与 runctx 物理隔离，授权码 `use runctx`、诊断码 `use diagctx`）+ 失败语义 `Option`/省略（非 `Result`/deny）+ **无授权闸门读 diagctx**；correlation 不进 `RequestCtx`、不被 PDP / RLS 读 | **Medium**（crate 图分离 + review gate）。Hard 化路径：dylint 禁 authz crate（authn / PDP）import diagctx——登记 follow-up |
| `diagctx` correlation 经 spawn 子任务丢失（D1-bis，#1160） | 该事件 `outbox.metadata` 缺 correlation | fail-open 省略（benign，**非安全面**——丢关联不越权）；`rss_spawn_missing_scope` lint 只覆盖 `runctx::try_*`、**不覆盖 diagctx**（无需覆盖） | benign（无 enforcement 需求；文档化 footgun） |
| 业务伪造 reserved envelope key（含 correlation）进 outbox（#1160） | 伪造关联 / 注入诊断 | producer `OutboxMetadata::try_insert` + wire `EnvelopeMetadata::try_insert` 均 fail-closed 拒 reserved；reserved 只经 adapter sealed setter 注入；emit 层 `OutboxEnvelopeParts` 无 reserved 槽（域永不构造 wire envelope） | **Hard**（类型层 funnel，OUTBOX-METADATA-FUNNEL-01 + emit 层 input-struct-field-exclusion）+ Medium（wire `insert_wire_pair` 站点 dylint DIPORT-ENVELOPE-WIRE-WRITER-01） |

## 6. 备选方案（Alternatives Considered）

**传播机制**：
- *全 `task_local` 隐式（无显式 struct）*：拒——授权输入变「魔法 ambient」，难追踪、难类型化喂 PDP。
- *全显式参数穿透（无 task_local）*：拒——污染 P2 后几乎每个签名，迁移体感最差。
- *复用 `tracing` span 装 tenant/principal*：拒——见 D1，诊断载体可丢弃 / 可改写，不配做授权闸门。

**layering（payload 归属）**：

| 选项 | 机制 | 取舍 | 裁决 |
|------|------|------|------|
| (a) 泛型 `RequestCtx<T,P>` | runctx 不持有 identity 类型，payload 为类型参 | runctx 纯 std+tokio、零内部边、本 spike 即可编译可测；泛型参漏进 consumer 签名（用 `AppCtx` 别名收口） | **spike 采用**；#1032 后保留泛型 `RequestCtx<T,P>`，但 `AppCtx` 的 tenant 已具体化（收口点仍是别名） |
| (b) intra-base sub-DAG | 改 base 规则措辞，runctx 依赖 vocab，tenant 收敛为具体 `vocab::tenant::TenantId` | 更具体 / 更顺手、单一 `TenantId`；需改 `architecture.md`+`CLAUDE.md` 措辞，principal 仍须 trait 擦除 | **已落地（#1032）**：sanctioned `runctx → vocab` 边 + tenant=`TenantId`；principal 仍 trait 擦除 |
| (c) runctx 自持最小 identity core | 在 runctx 复制一份 `TenantId` | 无内部边；但与 vocab 的 `TenantId` 重复、双真源、漂移 | **拒** |

> ADR amendment（如未来 (b) 落地改本 ADR）须同步重评本节威胁矩阵（`ai-robust.md` §审查要求）。
>
> **Amendment（#1032，2026-06-23）**：备选 (b) intra-base sub-DAG 已落地（sanctioned `runctx → vocab` 边、
> `AppCtx` tenant=`vocab::tenant::TenantId`、删 `TenantSlot`、base 规则改 enumerated DAG + 决策 #2 回填）。
> 已按本要求重评威胁矩阵：①「直接 `RequestCtx::new` 伪造」行——伪造门由「两 slot 皆 pub(crate)」收敛到 **principal
> 接缝单点**，并新增 `TenantId::parse` fail-closed（拒空/nil/非 canonical）杜绝非法 tenant mint，整体仍 Hard；
> ②「`?ctx` 泄露」行——`TenantId` 自身 `Debug` 改为有意可见（UUID 是可观测标识、非凭据），`RequestCtx`/`PrincipalSlot`
> 仍 redacted，PII 泄露面不变。无新增越权面、无降档。principal 仍 trait/泛型擦除（`runctx → authn` 闭环禁止不变）。
>
> **Amendment（#1160，2026-06-26）**：新增 **§D1-bis 可读诊断 context 信道 `diagctx`**（correlation 经
> 独立 fail-open ambient 信道在 outbox emit 点读回，#1296 一条源链路落地；trace 经 #1224 接线（`tracewire` W3C traceparent capture/restore）、principal 仍待
> 安全决策）。已按 `ai-robust.md` §审查要求重评威胁矩阵，**新增三行**：①「诊断 correlation 被误当授权源」——缓解
> = `diagctx` 独立 crate（图隔离）+ `Option`/fail-open（非 deny）+ 无授权闸门读取，**Medium**（Hard 化 = dylint 禁
> authz crate import diagctx，已登记 follow-up）；②「correlation 经 spawn 丢失」——fail-open 省略，benign 非安全面
> （`rss_spawn_missing_scope` 刻意不覆盖 diagctx）；③「业务伪造 reserved envelope key」——producer + wire 两侧
> `try_insert` fail-closed 拒 + emit 层无 reserved 槽，维持 **Hard**（+ wire 站点 dylint Medium）。**§D1 的两条 Hard
> 边界（诊断不进授权 `RequestCtx`、runctx↛tracing）原封不动，无降档、无新增越权面**；diagctx 不被任何授权闸门读取。
