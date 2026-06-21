# Cell 实现模式

## 序列化边界

Handler 响应和事件 payload 使用 typed DTO + converter。禁止把 domain entity
直接序列化到 wire。JSON、query、path、event header 字段统一 camelCase。

## DTO 作用域

| 档 | 适用 | 位置 |
|----|------|------|
| A | 单 slice 自用 | `crates/cells/{cell}/slices/{slice}/`（slice crate 内 `pub(crate)` / 私有） |
| B | 同 cell 多 slice 共享 | `crates/cells/{cell}/internal/`（`cell-{id}-internal` crate 的 `dto` / `domain` 模块） |
| C | 跨 cell wire 类型 | 禁止手写共享 crate，使用 contract schema 或 generated contract |

禁止把跨 cell 事件 DTO 放到 framework 共享 crate（`crates/framework/*`）、
`crates/cells/{cell}/events/`、`crates/contracts/.../*.rs` 或 `crates/framework/runtime/`。
跨 cell 只通过 contract 通信。

同形 decode 在多个 consumer 中重复是架构成本，不用共享 Rust 类型消除。若同一 schema
被五个及以上 cell 消费，再走 codegen 路线（build.rs / proc-macro）生成 payload 类型。

## internal 模块

`internal/ports` 放仓储和服务 trait；`internal/mem` 放 in-memory 实现。其它 internal
子模块按真实功能增长，不预生成空目录。

## Init fail-fast

`Cell::init(&self, reg: &mut Registry) -> Result<(), KernelError>` 中必须：

- 调 `BaseCell::init`
- 注册 routes、subscribers、probes 时返回 `Err(...)` 而不是 `panic!`
- 对必填 handler / service 依赖 fail-fast（必填依赖优先走构造器必填参数，缺失即编译错误）
- 不在 init 中做外部 I/O 或 spawn tokio task

## Sealed marker wrapper

cell/slice public Option 不接收 raw infra trait。raw adapter 先在 cell 边界用 newtype 包成
sealed marker type，再注入 service。port trait 用 sealed-trait 模式封闭（编译器强制，外部 crate
无法实现），raw 类型保持 `pub(crate)`。

## Contract test

每个 served contract 必须有 contract-level 测试覆盖：

- 正常响应 schema
- 参数错误与错误码
- 鉴权边界
- path 参数校验

Path 参数按 contract schema 校验；UUID 等强类型标识不在 handler 中裸 `String` 传递（用 newtype）。

## serviceOwned

service-owned handler 必须声明 owner，并由 owner guard 规则保护（crate 依赖图 + governance
规则）。跨 owner 调用通过 contract，不通过直接 import 或共享 handler。

## active event subscriber

active event contract 必须至少有一个 subscriber；死事件是 warning 或 error 由
governance 规则定义，rules 只声明架构意图。

## Typed response envelope

codegen contract handler 使用 typed response envelope 表达业务状态码。`Err(...)`
只用于未声明的 framework 5xx。业务 4xx/5xx 返回生成的 typed error response。
