# LocalTx 规则

本文件记录 L1/LocalTx 的当前声明边界。机器真源仍是 `xtask` 的 typed manifest、R22 校验与
`::generated::http::LOCAL_TX_SPECS`；后续可执行覆盖率、runner、metrics 与 journey 见
`docs/spec/006-l0-l1-consistency-hardening/` 的 #1697+ 分解。

## Contract evidence

`consistencyLevel = "LocalTx"` 必须是 `kind = "http"`，并声明完整 `[capabilities.localTx]`：

```toml
[capabilities.localTx]
boundary = "single-domain"
txModel = "tenant-scoped-uow"
retry = "bounded-transient"
commitUnknown = "not-retryable"
```

旧的 boundary-only 形态不再接受。字段和取值均为闭集：

- `boundary = "single-domain"`：一个 LocalTx 只覆盖单一域 crate 拥有的本地持久化边界。
- `txModel = "tenant-scoped-uow"`：事务模型是租户作用域 Unit of Work，tenant scope 必须来自上下文/注入边界，
  不从 HTTP body 取得。
- `retry = "bounded-transient"`：只允许有界瞬态重试；每次重试必须重建完整 transaction scope，不复用失败事务。
- `commitUnknown = "not-retryable"`：commit outcome unknown 不能当普通 transient 自动重放副作用。

`serde` typed struct + closed enum + `deny_unknown_fields` 负责 Hard 化缺字段、未知字段和未知枚举；R22 负责
Medium 条件门：只有 L1 允许 localTx block，且 L1 必须声明上述完整证据。

## Runtime meaning

LocalTx 表示一次 HTTP handler 内的单域、租户作用域本地原子写。它不表示跨域事务，不表示 outbox 发布已兑现，
也不表示 saga/reconcile/workflow 已接线。

`audit.list-tenant-entries` 的 LocalTx UoW 只覆盖持久 `auth_audit_events` append。append 成功提交后才签发
`CrossTenantReadScope` 并执行专用 admin pool read；append 与 read 不在同一事务，系统也不自动重试整条
append+read 序列。

`commitUnknown = "not-retryable"` 的含义是：当提交结果未知时，不允许按普通 transient path 自动重放整个副作用序列。
后续 runtime/status/metrics 可以把该状态细分，但默认治理语义必须 fail-closed。

## Static coverage gate

`cargo xtask localtx-coverage` 以 active LocalTx HTTP manifest 为真源，逐条闭合 generated
`LOCAL_TX_SPECS`、owner domain、生产 typed route mount 与测试 marker。该检查是无需编译的静态门，进入
`cargo xtask verify --fast`；缺失、重复、孤儿或错误 owner 的证据均 fail-closed。

生产 route 证据只接受绝对 typed `impl ::bootstrap::Domain for ...` 的 `init` 方法：registry 参数必须写成
`&mut ::bootstrap::Registry`，且 `route_group` 必须是该参数在 `init` 顶层语句中的直接调用。endpoint 必须
inline 流入 closure router 参数的 `mount`，或经同 lexical scope 内唯一 local binding 单次流入。普通 helper、
未调用 closure、match/child block、同名自定义 `route_group`/`mount` 以及仅构造 endpoint 都不构成生产接线证据；
旧的 bare `Domain` / `Registry` 证据语法不兼容。
`bootstrap` 与 `generated` / `httpserve` 一样属于 protected workspace dependency：Cargo dependency key 必须指向
同名真实 workspace package，package rename、self-alias、local shadow 或宏注入均不能提供 route carrier 身份。

每条 active LocalTx contract 必须在 owner crate 的一个真实 `#[test]`、`#[tokio::test]` 或
`#[rstest::rstest]` 函数内声明且只声明一个 typed marker：

```rust
const _: ::vocab::HttpRouteBinding<
    ::generated::http::identity_v1::logout::RouteMarker,
    ::vocab::http::LocalTx,
> = ::generated::http::identity_v1::logout::ROUTE;
```

marker 只接受上述以 `::vocab` / `::generated` 开头的 extern-prelude absolute 语法；旧 bare path、alias、
注释、字符串、宏或集中 allowlist 均不兼容。`#[tokio::test]` / `#[rstest::rstest]` 还必须由 Cargo metadata
证明其 dependency key 指向真实 registry package，不接受本地 path 或 package rename 替身。

marker 所在 lexical block 及其全部 enclosing lexical scopes 都必须没有 item/statement-position macro
invocation：这类宏可以展开 `use`、`extern crate` 或 item，静态门无法证明其不会重绑定 carrier
namespace，因此该 scope 及其 children 都会被视为 opaque。
例如独立语句 `assert_eq!(actual, expected);` 在 AST 中属于 `Stmt::Macro`；需要与 marker 共处时，必须把
marker 与包含惯用 `assert_*!` 语句的测试体分别放入两个 sibling child blocks，确保共同父 scope 本身不含
macro invocation。不要把断言改写成需要 lint carve-out 的 unit-value binding。仅给 marker 套一层 child
block 无效，因为父 scope 的 opaque 风险会向下传播。
`Expr::Macro` 只能在表达式位置展开，不能向外层注入 item namespace，因此可接受。若违反该边界，门会
按 fail-closed 报 marker 缺失。

`HttpRouteBinding<RouteMarker, LocalTx>` 与 generated `ROUTE`
的身份对应由 rustc 编译期强制（`LOCALTX-TEST-MARKER-TYPED-01`，Hard）；active manifest 到
generated/owner/route/test 的跨文件存在性由 `localtx-coverage` 在 verify/CI 阻断
（`LOCALTX-COVERAGE-CLOSURE-01`，Medium）。该 marker 只锚定至少一个现有 route/domain 测试，不表示完整
rollback、conflict 或 backend conformance 已兑现。

## Follow-up boundary

#1687 的边界是 manifest authoring：

- 补齐 LocalTx 三个新增字段。
- 迁移真实 L1 HTTP `contract.toml`。
- R22 守住 L1 完整证据与 stray capability。

#1688 的边界是 generated metadata：

- `::generated::http` 暴露 `LocalTxSpec` 与 LocalTx 闭枚举。
- LocalTx active HTTP `SPEC` 必填 `local_tx: Some(...)`，非 LocalTx 为 `None`。
- `LOCAL_TX_SPECS` active-only 派生当前 L1 HTTP contract 子集。
- consistency/effect/auth/path/method 已由 #1690 收进 `SPEC.route: HttpRouteEvidence` 并随 endpoint/RouteMeta
  原样传播；`local_tx` 继续只表达 L1 专属 transaction capability，不复制 route proof。
- 不做 LocalTx runner、coverage gate、metrics label 或 domain proof。

#1697 建立上述 LocalTx coverage gate；#1698 收口 LocalTx vocabulary/closed labels；#1699 以后接 Postgres runner，
#1700+ 再补真实域路径、rollback/conflict 与 conformance 证明。
