# 错误处理规范

本文拥有组件错误、诊断与敏感信息边界。公共 API 和持久化格式的兼容规则见
[版本规则](api-versioning.md)，产品责任见[项目范围](project-scope.md)。

## 组件错误

- 每个能力核心拥有自己的错误类型与闭合分类，provider 将底层错误映射到该能力的接口。
- 公共库错误使用 `Result` 与 `thiserror`；产品组合边界和 internal 测试可使用 `anyhow`。
- 不建立跨组件的全局错误 registry、错误码前缀分配器或通用 wire envelope。
- 重试、冲突、结果未知与 terminal outcome 按组件的真实语义表达；不能仅凭底层错误字符串推导可安全重试。
- exported crate-scope 裸 `pub static ERR_*` / `pub const ERR_*` 哨兵错误禁止。

## HTTP 适配与产品 wire 边界

- 公共能力保留完整错误和恢复结果，先处理 CommitUnknown 等结果，再投影为 `rss-contract::SafeError`。
- 可选 `rss-axum::HttpError` 只映射 SafeError 的封闭类别，输出 `{"error":{"code":"…","message":"…"}}`，
  对应 400/401/403/404/409/429/503/500；不透传 source、内部诊断或自动重试授权，不兼容旧 envelope。
- 产品拥有认证 challenge、业务错误、编解码、最终响应和 request ID 注入；其它组件不依赖 HTTP host。
- 401 最终响应须由产品认证组件补充适用的 WWW-Authenticate，RSS 不选择认证方案。
- 已接纳的持久化或跨版本错误 identity 仍受版本规则保护，不能因删除内部库而原地改变。

## Message 与敏感信息

- 对外诊断不得泄露凭据、密钥、未脱敏 payload、provider 连接信息或不可信错误正文。
- 使用结构化、低基数字段表达可公开的错误分类；内部错误上下文不能自动进入产品 wire。
- 字段级值进入日志、trace 或产品输出前，按其类型和用途经 `rss_redact::safe(value, scope)` 渲染。
- `Debug`、`Display` 和错误链同样遵循上述边界；不得把敏感数据写入错误后仅靠最终日志文本替换保护。

## Panic 与 carve-out

- 可恢复错误走 `Result`，不能用 panic、unwrap 或 expect 表达。
- 不可恢复的 programmer error 须有明确不变量依据；默认由 workspace 的 clippy
  `panic` / `unwrap_used` / `expect_used` deny 拦截。
- 必要的 lint carve-out 仅限具体函数或类型，注明原因；不得新增 module-level 或 crate-level 豁免。
