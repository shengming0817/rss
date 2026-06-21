# ADR-001：context 控制流值传播（tenant / principal）

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
> 本文同时确立 RSS 的 **ADR 模板**（首份 ADR）：背景 / 决策 / 范式 / 后果 / 威胁矩阵 / 备选。

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
- 当前 base 层规则（`architecture.md` §分层 / `CLAUDE.md`）：基础 crate「仅 std + 外部 crate，不依赖内部其它分组」。
  本 spike **遵守现状**：`RequestCtx<T, P>` 对 tenant、principal **双泛型**，runctx 保持**零内部依赖**
  （依赖图见 §范式）。
- **目标方向（intra-base sub-DAG，本 PR 不落）**：base 层引入显式内部 DAG
  `vocab ◁ ids ◁ secure ◁ support ◁ runctx`（runctx 作 base 顶点，可依赖 `vocab`/`ids`），
  使 `RequestCtx` 的 tenant 收敛为具体 `vocab::tenant::TenantId`。届时只改 `AppCtx` 别名一处
  （principal 仍泛型/trait）。该规则措辞修订 + 本决策的 `architecture.md` 内联回填，随引入
  `vocab::tenant::TenantId` 的 W 阶段 feature 一并落（见 §后果·follow-up）。备选见 §6。

### D4 — 取消 / deadline 不进 RequestCtx

取消与 deadline 走 `tokio_util::sync::CancellationToken`（显式传给后台环 / 被 await 的 future），
**不**放进 `RequestCtx`。理由：取消是带不同生命周期与所有权的 capability handle（可 clone、可 select、
可派生 child token），与「`RequestCtx` 是不可变授权快照」的不变式正交；混入会迫使 ctx 携带共享可变状态。
本 spike 不引入 `tokio-util`（仅记边界）。

### D5 — 构造边界：仅已认证通道

`RequestCtx` **只**能从已认证通道构造：JWT tenant claim（验签后）或 service-token-MAC 的 `X-Tenant-ID`
header（`docs/rules/tenancy.md` §Tenant source）。**HTTP request body 不得携带 tenantId**——body 是未认证维度。

类型层强制：`RequestCtx` 私有字段（sealed 构造，唯一入口 `new`）+ **不 derive `Deserialize`**
⇒ 「从 body 反序列化出一个 RequestCtx」在类型上**不可表达**。上游另由契约 codegen 拒绝声明 `tenantId`
的 request schema（`tenancy.md`，Hard）。

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
pub type AppCtx = RequestCtx<TenantSlot, PrincipalSlot>; // 进程级实例化（W 阶段单点迁移）

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
  测试锁定 `tokio::spawn` / `spawn_blocking`）；但**静态防误用**（拦截「忘记重绑」的 callsite）当前是 Soft，
  升级到 Medium 须落 dylint，已登记 follow-up 4。

**下游影响**：httpserve middleware（绑 `scope`）、authn（构造 `RequestCtx` + 派生 `Principal`/`row_visibility`）、
后台环 crate（`eventexec` / reconcile 扇出必须捕获-重绑 ctx）——均为后续 W 阶段 feature。

**follow-up（本 PR 不落，登记 backlog）**：
1. base 层规则措辞改为 enumerated intra-base DAG（`architecture.md` §分层 + `CLAUDE.md`），sanction
   `runctx → vocab/ids` 边并加 `INVARIANT`；
2. `architecture.md` 决策表内联回填「决策 #2 → 本 ADR」（仿决策 #1 体例）；
3. 随引入 `vocab::tenant::TenantId` 的 feature 把 `AppCtx` 的 tenant 换成具体类型；
4. dylint `rss_spawn_missing_scope`：静态拦截「子任务内读 ctx 却未在外层重绑」的 callsite，
   把 spawn footgun 的静态防误用从 Soft 升到 Medium（见 §威胁矩阵）。

## 5. 威胁矩阵（Threat Model）

| 威胁 | 后果 | 缓解 | enforcement 档位 |
|------|------|------|------------------|
| request body 携带 `tenantId` 冒充租户 | 跨租户写 | `RequestCtx` 私有字段 + 无 `Deserialize`（body 构造不可表达）；契约 codegen 拒绝 `tenantId` request schema | **Hard**（类型 + codegen funnel） |
| ctx 缺失被当作 anonymous / default-tenant 放行 | fail-open 越权 | 读访问器返回 `Result`，缺失 = `Err(MissingCtx)`，无 panicking / 伪造路径；PDP 缺租户 deny | **Hard**（类型）+ **Medium**（fail-closed 行为测试） |
| tenant / principal 被塞进 tracing span 后被下游误当授权源 | 授权基于可丢弃 / 可改写信号 | runctx **不依赖 tracing**，API 面无「ctx→span」通道 | **Hard**（crate 依赖图） |
| spawn / blocking 出的任务**运行时**丢 ctx → 子任务读到空 | 后台越权 / fail-open | 子任务无 ctx 即 `Err(MissingCtx)`，调用方 fail-closed | **Medium**（fail-closed 运行时行为 + 测试锁定 `tokio::spawn` / `spawn_blocking` 不继承） |
| consumer **静态忘记**在子任务「捕获-重绑」ctx | 同上 | 当前仅范式文档 + 测试演示（不拦截误用 callsite） | **Soft**（不达标）→ 升级路径：dylint `rss_spawn_missing_scope`，登记 backlog（见 §后果 follow-up 4） |
| `RowScope::All` 经非 super-admin 路径泄漏 | 全租户读 | runctx 不构造 RowScope；派生在 authn super-admin 路径 + 强制 audit ledger（`tenancy.md`） | 引用 `tenancy.md`（非本 ADR 新增） |

## 6. 备选方案（Alternatives Considered）

**传播机制**：
- *全 `task_local` 隐式（无显式 struct）*：拒——授权输入变「魔法 ambient」，难追踪、难类型化喂 PDP。
- *全显式参数穿透（无 task_local）*：拒——污染 P2 后几乎每个签名，迁移体感最差。
- *复用 `tracing` span 装 tenant/principal*：拒——见 D1，诊断载体可丢弃 / 可改写，不配做授权闸门。

**layering（payload 归属）**：

| 选项 | 机制 | 取舍 | 裁决 |
|------|------|------|------|
| (a) 泛型 `RequestCtx<T,P>` | runctx 不持有 identity 类型，payload 为类型参 | runctx 纯 std+tokio、零内部边、本 spike 即可编译可测；泛型参漏进 consumer 签名（用 `AppCtx` 别名收口） | **本 spike 采用** |
| (b) intra-base sub-DAG | 改 base 规则措辞，runctx 依赖 vocab，tenant 收敛为具体 `vocab::tenant::TenantId` | 更具体 / 更顺手、单一 `TenantId`；需改 `architecture.md`+`CLAUDE.md` 措辞，principal 仍须 trait 擦除 | **目标方向**（随 vocab::TenantId feature 落） |
| (c) runctx 自持最小 identity core | 在 runctx 复制一份 `TenantId` | 无内部边；但与 vocab 的 `TenantId` 重复、双真源、漂移 | **拒** |

> ADR amendment（如未来 (b) 落地改本 ADR）须同步重评本节威胁矩阵（`ai-robust.md` §审查要求）。
