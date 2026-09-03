# 错误处理规范

## Wire 格式

统一错误响应：

```json
{"error":{"code":"ERR_...","message":"...","retryable":false,"details":[],"requestId":"..."}}
```

`requestId` 由框架注入。wire 字段 camelCase，日志字段 snake_case。

`vocab::CoreError` → wire envelope 经 `httpserve::core_error_response(&CoreError, request_id)`：
**4xx 下发 `public_details`、5xx 强制 strip**；`internal_attrs` 永不进 wire。`details` 为单键对象数组，
typed 值形固定（golden 锁）：`Duration`→毫秒 `u64`、`Time`→epoch 秒 `i64`。kind→status 单源
`status_for`（与 `code` 同出 `kind`，杜绝 code/status 错配；未知 `#[non_exhaustive]` kind fail-closed 映射 5xx）。
`retryable` 同样只由 kind 单源派生：仅明确可安全重试的 `VersionConflict`、`TooManyRequests` 与
`ProviderUnavailable` 为 `true`；请求 outcome 未知的 budget `Unavailable` 与事实冲突
`OutboxFactConflict` 固定为 `false`。

## errcode

- 对外错误使用 `vocab`（库错误枚举 `thiserror`，错误码经 `vocab` 命名空间）；
  应用边界可 `anyhow`。
- exported crate-scope 裸 `pub static ERR_*` / `pub const ERR_*` 哨兵错误禁止；
  库错误用 `thiserror` 枚举表达。
- domain 层不返回 HTTP 状态码。
- handler 层把领域错误映射为 contract 声明的状态码。
- codegen handler 用 typed response envelope（闭合 framework failure + typed error carrier）表达业务 4xx/5xx；声明业务错误响应的 route marker 只能经 declared constructor 挂载，handler future 的精确输出类型由 rustc 校验。固定 `code/message/retryable/details` 的 error schema 只生成 request-id factory，业务无法注入违背 schema 的值；outer `Err` 也不能从 raw `Response` 转换。

## Message 与 PII

`vocab` 错误的 message 必须是 `&'static str` const literal，不能用 `format!` 拼
runtime 数据。runtime 数据进入两条 typed 通道：

- `with_details(PublicString/PublicInt/PublicBool/PublicDuration/PublicTime)`：
  4xx 可下发，5xx 强制 strip（由 `httpserve::core_error_response` 按 status class 落地）。
- `with_internal(InternalAttr)`：只进服务端日志，永不进 wire。

由 const literal 检查（编译期 `&'static str` 类型约束，Hard）与 sealed 字段冻结（类型系统，Hard）守。
typed 通道分流（`PublicDetail` vs `InternalAttr`）**本身即脱敏决策**——wire mapper 只读 `public_details()`、
不对其二次 `redact`（`PublicDetail` 已是 vetted 公开值）。字段级值进日志 / trace / wire 前经 `rss_redact::safe(value,
  scope)` 按 typed redaction policy 渲染。

## Panic

`rss` 默认错误走 `Result` + `thiserror`/`anyhow`，不用 panic 表达可恢复错误。生产 panic
仅限不可恢复的 programmer error，必须使用：

```rust
panic!("{}", panic_register::approved("reason", value));
```

`reason` 是 kebab-case literal。A/B 类 programmer error 使用 `vocab` 的 assertion 形态；
框架 rethrow 保留原 panic payload。其它 panic 形态由 clippy `panic` / `unwrap_used` deny（Medium）拦截。

## Carve-out

clippy `#[allow(...)]` / lint carve-out 只能 item-level（函数 / 类型），不能 module-level 或
crate-level。新增或删除 carve-out 必须同步修改 ADR registry 和 lint 配置映射；任一侧漂移即 CI 红。

## 错误码前缀

新增 `ERR_<SEG>_` namespace 或 whole-code entry 必须：

1. 注册到 `vocab` 前缀所有权集合或外部 crate 注册入口。
2. 更新 prefix golden。
3. 通过 `vocab` 的前缀所有权测试。

in-repo 域 crate mint 新前缀时，平台 registry 也必须更新；单靠域 crate 注册入口不满足静态扫描。
