# Runtime API

## Auth crate

Kernel auth plan 类型来自 `rss-kernel` 的 `auth` 模块（`rss_kernel::auth`）。当同一文件也 `use`
`rss-runtime` 的 `auth` 模块时，kernel auth 用 `use rss_kernel::auth as kauth;` 别名消歧。

`cell::Registrar`、listener 常量和 route group 类型位于 `rss_kernel::cell`。

## RouteGroup

Cell 在 `init(&self, reg: &mut Registry)` 中通过 `reg.route_group(...)` 声明 listener、prefix、register
闭包。闭包返回 `Result<(), _>`，错误必须冒泡到 bootstrap；禁止 `expect` / `unwrap` 风格 panic。

业务路由使用 `rss_runtime::auth::mount(router, auth::Route { .. })`（router 为 axum `Router`）。
`auth::Route.contract` 承载 method、path、contract ID。Public 和 password-reset-exempt 只能通过
route 字段显式声明。

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
- 声明 caller-cell allowlist。
- nonce store 在多实例部署中必须 replay-safe。

`finalize_auth` 在所有 route 注册完成后运行；业务不得绕过最终 matcher。

## Auth plan 优先级

认证来源优先级：

1. route 显式 Public / PasswordResetExempt。
2. listener auth plan。
3. bootstrap fail-fast 默认拒绝。

Cell 禁止构造 AuthPlan；组合根（assembly / bin crate）组装后通过 bootstrap option 注入。

## Option 范式

- 强依赖 option 必须 fail-fast，不静默 noop。
- 累加式 builder 可忽略空输入，但最终 build 必须 validate。
- 删除旧 shim，不保留兼容别名。
- 新 runtime option 必须有明确 owner、默认值、安全失败路径和测试。
