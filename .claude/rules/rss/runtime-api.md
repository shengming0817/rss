# Runtime API

## Auth crate

auth plan 类型来自 `primitives` 的 `authplan` 模块（`primitives::authplan`）；PDP / 会话 / Principal / jwt
在 `authn` crate。二者分属不同 crate、import 各自路径，无需别名消歧。

`Registrar` 与生命周期 trait（域 crate 实现的 `Domain` 生命周期 trait）位于 `bootstrap`；listener 常量与
route group 类型位于 `httpserve`。

## RouteGroup

域 crate 在 `init(&self, reg: &mut Registry)` 中通过 **`reg.route_group::<L>(prefix, register)`** 声明路由组——
**listener 由类型参数 `L` 携带**（`httpserve::{Primary, Internal, Admin, Health}` marker，#1103 typed per-listener
route-group，ROUTE-LISTENER-TYPED-01）。register 闭包签名 `FnOnce(httpserve::ListenerRouter<L>) ->
Result<httpserve::ListenerRouter<L>, KernelError>`，错误必须冒泡到 bootstrap；禁止 `expect` / `unwrap` 风格 panic。

业务路由经传入的 listener-typed builder `rb: ListenerRouter<L>` 二选一挂载（**`mount`/`mount_primary` 是
`ListenerRouter<L>` 的方法**，非自由函数；裸 `axum::Router` 不出 httpserve，ADR-009），均承载 method、path、contract ID：

- 非-`Primary` listener（`Internal` / `Admin` / `Health`）：`rb.mount(httpserve::Route { method, path, contract_id }, handler)`——`Route` 类型层**无** opt-out 字段；`mount` 仅 `L: NonPrimaryListener` 可用。
- `Primary` listener：`rb.mount_primary(httpserve::PrimaryRoute { .., opt_out }, handler)`——`PrimaryRoute` 是**唯一**可携 opt-out 的 route 类型；`mount_primary` 仅 `ListenerRouter<Primary>` 可用。

示例（域 crate `Domain::init`）：
```rust
reg.route_group::<httpserve::Primary>("/api/v1/identity", |rb| {
    Ok(rb.mount_primary(
        httpserve::PrimaryRoute { method: Method::POST, path: "/login",
            contract_id: "identity.login", opt_out: Some(RouteAuthOptOut::Public) },
        post(login_handler),
    ))
})?;
```

Public 和 password-reset-exempt 只能经 `PrimaryRoute.opt_out`（`Some(RouteAuthOptOut::Public | PasswordResetExempt)`）在 `Primary` listener 上声明；plain `Route` 类型层无此字段，且非-Primary listener 拿不到 `mount_primary`（input-struct-field-exclusion + typed function choice，Hard，INVARIANT AUTH-OPTOUT-PRIMARYONLY-01 / ROUTE-LISTENER-TYPED-01）。

`finalize_routes` 产出 per-listener `httpserve::UnfinalizedRoutes`（**无 public bindable 出口**）；组合根经 `httpserve::finalize_auth` 换 `AuthenticatedRoutes` 后才可 `into_make_service` bind——未跑 auth 装配的 router 类型层不可 bind（#1113 funnel，ROUTE-AUTH-FUNNEL-01/02）。

## Listener

标准 listener：

- `PrimaryListener`：业务 API。
- `InternalListener`：服务间控制面。
- `HealthListener`：health、ready、metrics。
- `AdminListener`：operator 或管理面。

listener auth chain 必须显式声明。无认证使用 `AuthNone`，`None` 是配置错误（构造器必填参数）。
单 listener 只能有一个 auth scheme；不同 scheme 通过不同 listener 表达。

## Internal endpoint

`/internal/v1/*` 必须满足：

- 挂在 internal listener。
- 使用 service token 或更强认证。
- 声明 caller-domain allowlist。
- nonce store 在多实例部署中必须 replay-safe。

`finalize_auth` 在所有 route 注册完成后运行；业务不得绕过最终 matcher。

## Auth plan 优先级

认证来源优先级：

1. route 显式 Public / PasswordResetExempt。
2. listener auth plan。
3. bootstrap fail-fast 默认拒绝。

> 例外（fail-closed）：`InternalListener` / `AdminListener` 不接受 route-level `Public` / `PasswordResetExempt` 降级——内部 / 管理面 listener 上的 route opt-out 必须被拒。优先级 1 的 route opt-out 仅适用于 `PrimaryListener` 等对外面 listener。

域 crate 禁止构造 AuthPlan；组合根（assembly / bin crate）组装后通过 bootstrap option 注入。

## Edge 防护中间件（#1106）

`httpserve` 边缘防护层（tower Layer），层序（外→内）固定为：

```
request_id → correlation → security-headers → body-limit → rate-limit → 验签桥 → trace → panic_recovery → Extension(plan) → 路由匹配 → enforce → handler
```

Health listener 例外：`finalize_auth` 从 `AuthPlan::listener()` 派生 trace policy，Health listener 不挂 `trace`
（`/healthz` / `/readyz` / `/metrics` probe/scrape 不产生 `http.request` span）；未知未来 listener fail-closed
为启用 trace。

- **body-limit + security-headers**：由 `AuthenticatedRoutes::sealed_router`（唯一 bindable funnel）**无条件叠默认**——
  每个 bind / 测试出口的 router 都带且不可遗漏（can't-forget funnel，同 `request_id`，Hard）。策略经 typed
  `httpserve::EdgeHardening { body_limit: BodyLimit, headers: SecurityHeaders }`（两字段非 `Option`、必有值），
  默认 body-limit = 1 MiB、security-headers = 零信任头集（`X-Content-Type-Options`/`X-Frame-Options`/`Referrer-Policy`/
  CSP `default-src 'none'`/`Cross-Origin-Resource-Policy`/`Cache-Control`/HSTS）。组合根可经
  `AuthenticatedRoutes::with_edge_hardening(EdgeHardening)` 覆盖（owner=httpserve 定默认，组合根可调；`without_hsts()`
  关 HSTS）。
- **BODYLIMIT-BEFORE-AUTH-01**（精确语义，两路径）：body-limit **层**（CL 闸 + Limited wrap）outer 于 auth：
  · **CL-declared 超限 → before-auth clean 413（`ERR_CORE_PAYLOAD_TOO_LARGE`）**：CL fast-reject 在验签桥前拒，
    无 auth 开销（auth 计算 + body 读取双重开销可避免，gocell 史 commit 248dbdd12）。
  · **无声明/chunked → `http_body_util::Limited` 字节硬顶（read-time，内存有界）**；未认证请求经 enforce 401
    时 body 从不被读 ⇒ 无 pre-auth buffer（DoS 优姿态——不选 option (a) 主动 buffer，auth 前 buffer 未认证请求
    回归 unauth DoS 姿态；安全目标[内存有界]已由 Limited 达成）。非 before-auth 413（无 CL 路径 cap 在 read-time）。
  结构性保证（baked 在 `sealed_router` 唯一 bindable 出口）+ 行为 tripwire 测试（CL 超大 + 无凭据 → 413 而非 401）。
- **rate-limit**：opt-in 注入式（provider 不可在服务层 default）。组合根经
  `.layer(from_fn_with_state(Arc<S>, httpserve::rate_limit::<S>))` 在 **验签桥之后**叠（⇒ outer 于桥 = before-auth，
  **RATELIMIT-BEFORE-AUTH-01**）；`S: diport::RateLimiter + Send + Sync`（泛型静态分发——`DynRateLimiter` 非 Sync 不可
  作 axum state，同 `JwtIssuer<S>` 范式）。key = **peer IP**（`ConnectInfo<SocketAddr>`，故唯一 bindable 出口
  `into_make_service` 改 `into_make_service_with_connect_info::<SocketAddr>`；httpd adapter serve 形参配套改）。超限 →
  `vocab::CoreErrorKind::TooManyRequests`（429 + `Retry-After` ceil 整数秒）。限流器故障 **fail-open**（不拒服务、记
  `tracing::error`）。provider 注入经 `assembly.toml [[diportProviders]] port="diport::RateLimiter"`（active）+
  `cargo xtask assembly validate`。
  > **已知限制（RealIP follow-up）**：peer IP 在反向代理后退化为代理 IP（全局桶）。正确 per-client IP 须可信
  > `X-Forwarded-For` 解析（RealIP 中间件，本轮 defer）。

## Option 范式

- 强依赖 option 必须 fail-fast，不静默 noop。
- 累加式 builder 可忽略空输入，但最终 build 必须 validate。
- 删除旧 shim，不保留兼容别名。
- 新 runtime option 必须有明确 owner、默认值、安全失败路径和测试。
