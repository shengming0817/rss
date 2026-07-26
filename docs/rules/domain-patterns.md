# 域 crate 实现模式

## 序列化边界

Handler 响应和事件 payload 使用 typed DTO + converter。禁止把 domain entity
直接序列化到 wire。JSON、query、path、event header 字段统一 camelCase。

## DTO 作用域

| 档 | 适用 | 位置 |
|----|------|------|
| 域内 | 域 crate 内自用 / 跨 feature 模块共享 | 域 crate 内 `dto` / `domain` 模块的 `pub(crate)` / 私有类型 |
| 跨域 | 跨域 wire 类型 | 禁止手写共享 crate，使用 contract（`contracts/` 声明 → `generated/`） |

禁止把跨域事件 DTO 放到基础 / 服务 crate（`vocab` / `support` / `runctx` 等）、域 crate 的 `events` 模块，
或手写进 `contracts/` 声明源 / `generated/` crate 之外的任何共享 crate。跨域只通过 contract 通信。

同形 decode 在多个 consumer 中重复是架构成本，不用共享 Rust 类型消除。若同一 schema
被五个及以上域 crate 消费，再走 codegen 路线（build.rs / proc-macro）生成 payload 类型。

## internal 模块

`internal/ports` 放仓储和服务 trait；`internal/mem` 放 in-memory 实现。其它 internal
子模块按真实功能增长，不预生成空目录。

> **例外：可替换 provider 的 DI port 按 category line 二分**（决策与理由见 ADR-003 + ADR-005 §2.1）。
> 判据只有一条：**此 port 签名能否在 `diport` 内编译而不让 diport 依赖域 crate？**
>
> - 能 → **provider-agnostic infra port**，收敛进 `diport`，不放域 crate `internal/ports`。
> - 不能 → **域形 repo / service port**（签名引用域内实体），归所属域 crate 的 `pub mod ports`
>   （必须 `pub`，供独立 adapter crate 跨 crate impl）；签名引用的最小实体集升 `pub`，
>   字段私有 + 构造器 funnel，保证外部可命名 / 可收发、不可伪造。
>
> 两类 port 使用同款 dyn wrapper 范式；相关宏依赖白名单 = `diport` + 定义自身 repo port 的域 crate，
> 由 `deny.toml` + `cargo xtask layer-deps` 强制（`DIPORT-MACRO-CONFINE`，Medium）。
> `adapter→域` 经 DIP 内向边 impl 域形 port；域 crate 只经构造器注入 dyn wrapper 消费。
> 纯域内（非可替换 provider）的仓储 / 服务 trait 仍留 `internal/ports`。

## Init fail-fast

`Domain::init(&self, reg: &mut Registry) -> Result<(), KernelError>` 中必须：

- 调 `BaseDomain::init`
- 注册 routes、subscribers、probes 时返回 `Err(...)` 而不是 `panic!`
- 对必填 handler / service 依赖 fail-fast（必填依赖优先走构造器必填参数，缺失即编译错误）
- 不在 init 中做外部 I/O 或 spawn tokio task

## Sealed marker wrapper

域 crate / 服务 public Option 不接收 raw infra trait。raw adapter 先在域 crate 边界用 newtype 包成
sealed marker type，再注入 service。port trait 用 sealed-trait 模式封闭（编译器强制，外部 crate
无法实现），raw 类型保持 `pub(crate)`。

> **例外：跨 crate DI port 不带 sealed supertrait**（ADR-003 §4.2 方案 ②）。sealed-trait 只在定义 crate 内封闭，
> 对独立 adapter crate 无效，因此定义面与 impl 面必须由两个不同载体分别守：
>
> - **定义面**：`deny.toml` 收敛 dyn-wrapper 宏依赖，保证 DI port 只在允许的 crate 定义。
>   注意 cargo-deny 限的是依赖不是 impl，域 crate 合法依赖 `diport`（消费端口）。
> - **impl 面**：production impl 只准出现在 adapter / 组合根，由 dylint `rss_diport_impl_allowlist`
>   （AST 级，Medium，`DIPORT-IMPL-ALLOWLIST-01`）承载。
>
> 同 crate 内的 port sealing 仍用 sealed-trait（Hard）。域形 repo port 同理：定义于域 crate `pub mod ports`、
> 不带 sealed supertrait，实现它的 adapter 须依赖该域 crate（DIP 内向边；反向「域→adapter」仍禁）。

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
