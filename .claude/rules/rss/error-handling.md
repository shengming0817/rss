# 错误处理规范

## Wire 格式

统一错误响应：

```json
{"error":{"code":"ERR_...","message":"...","details":[],"requestId":"..."}}
```

`requestId` 由框架注入。wire 字段 camelCase，日志字段 snake_case。

## errcode

- 对外错误使用 `vocab`（库错误枚举 `thiserror`，错误码经 `vocab` 命名空间）；
  应用边界可 `anyhow`。
- exported crate-scope 裸 `pub static ERR_*` / `pub const ERR_*` 哨兵错误禁止；
  库错误用 `thiserror` 枚举表达。
- domain 层不返回 HTTP 状态码。
- handler 层把领域错误映射为 contract 声明的状态码。
- codegen handler 用 typed response envelope（`Result` + typed error enum）表达业务 4xx/5xx。

## Message 与 PII

`vocab` 错误的 message 必须是 `&'static str` const literal，不能用 `format!` 拼
runtime 数据。runtime 数据进入两条 typed 通道：

- `with_details(PublicString/PublicInt/PublicBool/PublicDuration/PublicTime)`：
  4xx 可下发，5xx 强制 strip。
- `with_internal(InternalAttr)`：只进服务端日志，永不进 wire。

由 const literal 检查（编译期 `&'static str` 类型约束，Hard）与 sealed 字段冻结（类型系统，Hard）守。

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
3. 通过 `cargo xtask` 前缀所有权治理测试（Medium）。

in-repo 域 crate mint 新前缀时，平台 registry 也必须更新；单靠域 crate 注册入口不满足静态扫描。
