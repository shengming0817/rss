# Runtime API

只列硬约束。类型签名与用法 walkthrough 见 `httpserve` / `bootstrap` / `generated` 的 rustdoc。

## Crate 归属

- auth plan 类型在 `primitives::authplan`；PDP / 会话 / Principal / jwt 在 `authn`。二者分属不同 crate，不做别名消歧。
- `Registrar` 与域生命周期 trait 在 `bootstrap`；listener 常量与 route group 类型在 `httpserve`。

## RouteGroup

- 路由组必须经 `reg.route_group::<L>(prefix, register)` 声明，**listener 由类型参数 `L` 携带**
  （`Primary` / `Internal` / `Admin` / `Health` marker）。载体：`ROUTE-LISTENER-TYPED-01`（Hard）。
- register 闭包的错误必须冒泡到 bootstrap；禁止 `expect` / `unwrap` 风格 panic。
- 业务路由必须先把 generated evidence 与 handler **原子绑定**成 endpoint，再交给 listener-typed builder。
  不存在从 path / method / auth 字段拼装 route 的公开入口。
- `ConsistencyMarker` 由 codegen 从 manifest `consistencyLevel` 单源选择，调用方不得替换。
  handler 首 extractor 必须是同一契约的 marker。
- `OutboxFact` producer 必须使用 producer 专用构造入口，**不能**走普通 endpoint 构造：
  producer binding 原子携带 route evidence 与精确 emitted-fact 集，endpoint 从它安装私有 route-bound witness；
  witness 缺失时提取 fail-closed，handler 只能从 move-only marker 铸造 receipt，不能替换 binding。
- active producer 的 event entry 必须由 typed generated payload 构造，不能从独立 topic/bytes 拼装。
- active producer 的持久化只允许经受控 producer transaction 入口：业务 closure 只拿 crate-private capability，
  并返回字段封闭的 emitted / no-mutation outcome；只有 funnel 能在校验 authorization、envelope contract 与
  typed fact 三者后执行 canonical outbox append。**禁止**普通写入口、direct append、publisher 或 emitter。
- method/path/auth/resource scope 全由 binding 内的同一 route evidence 推导。
  `SPEC.route` 仅供元数据查询，**不是** production endpoint 构造入口。
- 非 L0 stateful handler 用 `.with_state`；L0 只能 stateless 或 `.with_classified_state`
  （owner-sealed `ReadEffect`/`AuthEffect` + `LocalPrivilege`），L0 类型上不存在普通 `.with_state`。
- `mount` 只接受 state 已闭合的 endpoint。
- `Health` 不接受业务 mount；组合根只能取固定的 `/health/v1/{healthz,readyz,metrics}`。
- Public 只能由 route evidence 推导，没有公开的 opt-out 拼装 API；非-Primary listener 在类型层无法接收
  Primary endpoint。载体：`AUTH-OPTOUT-PRIMARYONLY-01` / `ROUTE-LISTENER-TYPED-01`（Hard）。
- `finalize_routes` 产出的 per-listener routes **无 public bindable 出口**；必须经 `finalize_auth`
  换取可 bind 的类型。未跑 auth 装配的 router 在类型层不可 bind。
  载体：`ROUTE-AUTH-FUNNEL-01/02`（Hard）。

## Listener

- 标准 listener 四类：业务 API（Primary）、服务间控制面（Internal）、health/ready/metrics（Health）、
  operator 管理面（Admin）。
- listener auth chain 必须显式声明。无认证使用 `AuthNone`；`None` 是配置错误（构造器必填参数）。
- 单 listener 只能有一个 auth scheme；不同 scheme 通过不同 listener 表达。

## Internal endpoint

`/internal/v1/*` 必须同时满足：挂在 internal listener、使用 service token 或更强认证、
声明 caller-domain allowlist、nonce store 在多实例部署中 replay-safe。

`finalize_auth` 在所有 route 注册完成后运行；业务不得绕过最终 matcher。

## Auth plan 优先级

1. route 显式 Public / PasswordResetExempt
2. listener auth plan
3. bootstrap fail-fast 默认拒绝

例外（fail-closed）：`InternalListener` / `AdminListener` **不接受** route-level 降级，
优先级 1 只适用于对外 listener。

域 crate 禁止构造 AuthPlan；组合根组装后经 bootstrap option 注入。

## Edge 防护中间件

层序（外→内）固定：

```
security-headers → request_id → correlation → server-request-budget → body-limit → rate-limit
  → 验签桥 → trace → panic_recovery → Extension(plan) → 路由匹配 → enforce → handler
```

- Health listener 不挂 `trace`（probe/scrape 不产生请求 span）；trace policy 从 auth plan 派生，
  未知未来 listener fail-closed 为启用 trace。
- **body-limit + security-headers 由唯一 bindable funnel 无条件叠默认**，每个 bind / 测试出口都带且不可遗漏
  （can't-forget funnel，Hard）。策略经 typed 结构传入，两字段均非 `Option`。
  默认零信任头集 + 有界 body limit；组合根可覆盖，但不能取消该层。CORP 默认以 overriding
  `same-origin` 注入；只有显式 `SecurityHeaders::without_corp()` 会让 handler 自行持有该策略，
  不提供任意 CORP 值的公共配置面。
- **HSTS 的最终 owner 是持有真实 scheme 的 `httpd` transport seam**：plaintext 构造路径对所有响应
  （包括 413/503 synthetic response）无条件删除 `Strict-Transport-Security`，并在 listener 启动时
  记录一次闭值告警；TLS/mTLS 构造路径保留 `httpserve` 的内层默认 HSTS。不得使用
  `X-Forwarded-Proto` 或其他请求头裁决。外部 TLS 终结部署由真实 terminator 添加 HSTS；同一个
  `ServerService` 被 plaintext 与 mTLS listener 复用时仍分别得到正确策略。
- **`SERVER-REQUEST-BUDGET-01`**：请求预算是必填、非零的进程快照配置，在任何 listener bind 前解析。
  唯一生产出口返回字段私有的 make-service capability，传输 adapter 只接受该 capability，
  故无法绑定无预算 raw router（Hard）。预算覆盖 body、验签、授权、handler 及其下游 future；
  耗尽时 drop 整条 request future，返回统一 503 envelope（outcome 未知，`retryable=false`），
  仍带 requestId/correlation/security headers。日志只记闭值 decision/reason/budget_ms/request_id。
  验签桥**禁止**再加局部 verifier timeout。跨 crate 结构由 synthetic red + anti-vacuity 守（Medium）。
- **`BODYLIMIT-BEFORE-AUTH-01`**：body-limit 层必须 outer 于 auth，两条路径语义不同——
  声明了 Content-Length 且超限的请求在验签桥前 clean 413，避免 auth 计算与 body 读取双重开销；
  无声明或 chunked 的请求由 read-time 字节硬顶保证内存有界，未认证请求的 body 从不被读取。
  **不得**为了统一成 before-auth 413 而在 auth 前主动 buffer 未认证请求——那会回归 unauth DoS 姿态。
  保证由唯一 bindable 出口的结构 + 行为 tripwire 测试共同承担。
- **`RATELIMIT-BEFORE-AUTH-01`**：限流是 opt-in 注入式，服务层不得提供默认 provider。
  组合根必须叠在验签桥之后（⇒ outer 于桥 = before-auth），使用泛型静态分发而非 dyn state。
  key 是 peer IP。超限返回 429 + `Retry-After` 整数秒。限流器**故障 fail-open**（不拒服务，记 error 日志）。
  provider 经 assembly manifest 声明并由 `cargo xtask assembly validate` 校验。

  已知边界：peer IP 在反向代理后退化为代理 IP（全局桶）。真正的 per-client 限流需要可信
  `X-Forwarded-For` 解析，在该能力落地前不得把当前实现描述为 per-client。

## Option 范式

- 强依赖 option 必须 fail-fast，不静默 noop。
- 累加式 builder 可忽略空输入，但最终 build 必须 validate。
- 删除旧 shim，不保留兼容别名。
- 新 runtime option 必须有明确 owner、默认值、安全失败路径和测试。
