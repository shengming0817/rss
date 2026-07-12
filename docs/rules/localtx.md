# LocalTx 规则

本文件记录 L1/LocalTx 的当前声明边界。机器真源是 `xtask` 的 typed manifest、R22 校验、
`vocab::LocalTx*` 闭值类型与 `::generated::http::LOCAL_TX_SPECS`；后续 metrics 与 journey 见
`docs/spec/006-l0-l1-consistency-hardening/` 的 #1697+ 分解。

## Contract evidence

`consistencyLevel = "LocalTx"` 必须是 `kind = "http"`，并声明完整 `[capabilities.localTx]`：

显式 UoW 模型：

```toml
[capabilities.localTx]
boundary = "single-domain"
txModel = "tenant-scoped-uow"
retry = "bounded-transient"
commitUnknown = "not-retryable"
```

repository 原子 CAS 模型：

```toml
[capabilities.localTx]
boundary = "single-domain"
txModel = "repo-atomic-cas"
retry = "bounded-transient"
commitUnknown = "not-retryable"
```

旧的 boundary-only 形态不再接受。字段和取值均为闭集：

- `boundary = "single-domain"`：一个 LocalTx 只覆盖单一域 crate 拥有的本地持久化边界。
- `txModel` 是闭合执行模型：
  - `tenant-scoped-uow`：显式 Unit of Work 承载事务生命周期，tenant scope 必须来自上下文/注入边界。
  - `repo-atomic-cas`：单次 repository mutation 以原子 compare-and-set 完成；冲突不得写入，handler 不自动重试。
  两种模型的 tenant scope 均不得从 HTTP body 取得。
- `retry = "bounded-transient"` 按模型解释：
  - `tenant-scoped-uow` 只允许有界瞬态重试；每次重试必须重建完整 transaction scope，不复用失败事务。
  - `repo-atomic-cas` 的 handler 不自动重试 CAS 冲突；冲突返回调用方，由调用方基于新版本发起新的业务请求。
- `commitUnknown = "not-retryable"` 同样按模型解释：UoW commit outcome unknown 不得自动重放整个事务；
  repository CAS 返回的写入结果未知时也不得重放同一条件写，因为第一次调用可能已经提交。

`serde` typed struct + closed enum + `deny_unknown_fields` 负责 Hard 化缺字段、未知字段和未知枚举；R22 负责
Medium 条件门：只有 L1 允许 localTx block，且 L1 必须声明上述完整证据。

运行期 evidence 的四个闭值只在基础层 `vocab` 定义一次；`generated::http::LocalTxSpec` 直接持有这些类型，
`consistency::localtx` 也复用同一类型身份，不各自维护镜像 enum。变体、完整 `ALL` 集合和低基数 label 由同一个
私有宏声明生成（`single_domain` / `tenant_scoped_uow` / `repo_atomic_cas` / `bounded_transient` /
`not_retryable`），新增或改名必须
同时通过 Rust 穷举编译、codegen committed golden 与 public-api 门。

## Runtime meaning

LocalTx 表示一次 HTTP handler 内的单域、租户作用域本地原子写。原子性可以由显式 UoW 生命周期承载，
也可以由 repository 的单次原子 CAS mutation 承载；contract 必须选择与执行体一致的 `txModel`。它不表示跨域事务，
不表示 outbox 发布已兑现，也不表示 saga/reconcile/workflow 已接线。

`settings.secret-publish` 使用 `repo-atomic-cas`：应用层先读最高版本并构造候选版本，最终正确性由
`SecretRepo::save` 的单次条件写保证；并发竞争失败映射为 `VersionConflict`，不得把两次 repo 调用描述成同一 UoW。

`identity.password-change` 同样使用 `repo-atomic-cas`：handler 路径为 find credential → 校验旧密码 →
`rotate` 构造下一版本 → 单次 `CredentialRepo::bump_version` CAS；业务正确性由该次条件写保证。
`VersionConflict` / 写入结果未知不得由 handler 自动重试；调用方须基于新版本发起新的业务请求。
不得把 find 与 CAS 描述成同一显式 UoW。

`audit.list-tenant-entries` 的 LocalTx UoW 只覆盖持久 `auth_audit_events` append。append 成功提交后才签发
`CrossTenantReadScope` 并执行专用 admin pool read；append 与 read 不在同一事务，系统也不自动重试整条
append+read 序列。

`LocalTxFinalStatus`、`cotx` 与 handler 级 UoW settlement 语义只描述 `tenant-scoped-uow`，不可外推为
`repo-atomic-cas` 的业务模型（handler 不持有显式 UoW，也不按 UoW 语义重放整条 find→mutate 序列）。
Postgres `run_pg_tx_retry` / `LocalTxAttempt` 仍可作为 **repo 内** 单次 CAS mutation 的底层事务承载：仅对
已确认 rollback 的 transient attempt 有界重试；`VersionConflict` 与 `CommitUnknown` 不重试。

`commitUnknown = "not-retryable"` 对 `tenant-scoped-uow` 的含义是：当提交结果未知时，不允许按普通 transient path
自动重放整个副作用序列。对 `repo-atomic-cas` 同理：写入结果未知时不得重放同一条件写。
`consistency::LocalTxFinalStatus` 将一次 UoW 的结算闭合为 `committed` / `rolled_back` / `rollback_failed` /
`commit_unknown`。只有显式 rollback 成功才能报告 `rolled_back`；retry class/final status 与事务结算正交，不能据
`TxRetryFinalStatus` 猜测 rollback 或 commit outcome。

## Backend conformance profiles

启用 `testkit/containers` 的 adapter 集成测试应按 `txModel` 组合 provider-agnostic conformance；
`testkit` 只接受调用方注入的泛型闭包和快照，不依赖 production adapter、domain crate 或 LocalTx canonical
enum。真实 backend marker 直接复用 `HttpRouteBinding<RouteMarker, LocalTx> = generated::ROUTE` 的 Hard 类型身份；
profile 模型与 required probes 始终由 contract manifest 的 canonical `LocalTxModel` 推导，adapter 不得用字符串、
第二套 enum 或 allowlist 重述。`localtx-coverage` 将每个 active contract 注册到 `adapters/*` 的真实 provider tests，并按 provider 聚合 probe；
缺 enrollment、错用较小 profile、缺 probe、伪造 dependency 或孤儿 marker 均阻断 verify。类型签名承担 Hard 的
route 身份约束，跨 manifest/source/test 的完整闭环评级为 Medium。

`tenant-scoped-uow` profile 必须组合：

- `localtx::assert_commit`：成功后状态符合预期且 durable write 恰好一次。
- `localtx::assert_rollback`：预期错误分类正确且 rollback 后 snapshot 等于 baseline。
- `localtx::assert_rejected_no_write`：validation 与 authorization 拒绝分别证明 snapshot 不变且 mutation count 为零。
- `tenant_conformance::assert_tenant_isolation`：同租 round-trip、跨租不可见且互不干扰；provider 错误只记录调用方
  注入的低敏静态类别与 typed stage。
- `repo_conformance::assert_retry_boundary_policy`：由 `TransientSuccessPath`、`ConflictPath`、`PermanentPath`、
  `TransientExhaustionPath` 四个 nominal path 组成；transient 在预算内成功且 action-local attempts 符合预期、logical
  durable write 恰好一次；conflict/permanent attempts 恰好一次且零写；transient exhaustion 达到非零预算、返回
  transient 类错误且零写。成功路径 expected attempts 与 exhaustion budget 都必须至少为 2，非法 threshold 在执行
  任一 action 前 fail-fast。
- `localtx::assert_commit_unknown_no_replay` 与 `assert_rollback_failed_no_replay`：错误类别正确且 attempt
  恰好一次。

`repo-atomic-cas` profile 必须组合 commit、validation/authorization no-write、tenant isolation、CAS conflict、
单次 CAS 内部 transient retry 与 unknown-result no replay。它不运行 handler-level rollback settlement，也不得把
整条 find→mutate 序列包装成 UoW retry。既有 tenant/retry helper 是唯一实现；LocalTx conformance 不复制
`LocalTxModel`、`LocalTxFinalStatus`、`TxRetryClass` 或其断言逻辑。

`CommitUnknownCase` 与 `RollbackFailedCase` 是两个不可交叉传入公开断言的类型；二者都只接受 action、预期静态
错误类别与 attempt probe，不接受 snapshot/write-count。commit outcome unknown 或 rollback failed 时第一次 attempt
可能已经 durable，故只能断言 attempt = 1，禁止伪断言 no-write。所有 case 字段均私有且只能经构造器建立；
action 是 `FnOnce`，防止 harness 自身重放。action 后才按 snapshot → count 顺序采样；count 必须是 fixture 隔离的
action-local delta，不能使用并发测试可改写的进程全局累计值。

`testkit::ConformanceErrorCategory` 是 LocalTx、tenant 与 retry profile 共享的 `#[non_exhaustive]` 闭值分类；
`localtx::ClassifiedError` 只携带该闭值与 opaque provider error，不接受自由字符串分类。三类 profile 的安全路径均
不要求 provider error 实现 `Debug`/`Display`，也不格式化 credential、secret、tenant/device payload。
`RepoConformanceError` 的既有通用 helper 仍保留 raw `Debug` 诊断；retry 路径只产生 typed
`ClassifiedProvider` / `WrongErrorCategory`。LocalTx 错误同时使用 `LocalTxStage` typed stage，避免仅有
“provider failed”而不可行动。

`testkit::localtx` 的 fake happy/anti-vacuity tests 与 workspace layer dependency guard 进入 verify/CI lane；fake
只证明 helper 非恒真与 testkit 零内部依赖。真实 provider enrollment 必须同时位于 `adapters/*`、携带具名 typed
`HttpRouteBinding<RouteMarker, LocalTx>` 并执行完整 helper set。Postgres profile test 使用真实事务表证明 commit、rollback、
validation/authorization no-write、tenant isolation 与 bounded retry；unknown settlement helpers 仍只断言一次 attempt，
不伪造 snapshot/no-write 结论。#1703/#1704 可继续扩展 SecretRepo/Identity 的领域专用矩阵，但不再承担 registry
闭环前置。

ref: sqlx sqlx-core/src/transaction.rs@v0.8.6

Postgres runner 以 `cotx::settlement` 私有模块持有的 crate-private `LocalTxAttempt<T, E>` opaque 和式
状态承载 `Committed` / `Unsettled` / `RolledBack` / `RollbackFailed` / `CommitUnknown`，非法的
result/status 组合在类型层不可表达（Hard）。生产 mint 构造器为 `pub(super)`，仅 `cotx` settlement
funnel 可铸造；兄弟模块与 `tx_retry` 只能消费。`PgTenantPool` 仍是 tenant scope 与 transaction
capability 的唯一入口；`cotx` 在每次 attempt 内重新 begin、注入 `SET LOCAL`，并经单一 settlement
funnel commit 或显式 rollback。显式 rollback 失败时经 `map_storage` 收口为独立 Storage settlement
错误（保留 primary+rollback 因果链），不再把可重试领域冲突（如 `VersionConflict`）冒泡到 HTTP。
`run_pg_tx_retry` 的 operation 签名只接受 `LocalTxAttempt`：`Unsettled` / `RolledBack` 仅在分类为
transient 时有界重试，`RollbackFailed` / `CommitUnknown` 强制不可重试。该 runner 既服务
`tenant-scoped-uow` 准入路径，也可被 `repo-atomic-cas` adapter 用于单次 CAS 的底层 settlement；
业务层 CAS 冲突仍按 `repo-atomic-cas` 规则上抛，不经 handler 自动重试。retry engine 与两个准入 UoW
的放置继续由 `pg-tenant-tx-guard`（Medium）守住。#1705 在该 closed carrier 上补 metrics/trace，不改变
settlement 语义。

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
（`LOCALTX-COVERAGE-CLOSURE-01`，Medium）。该 marker 只锚定至少一个现有 route/domain 测试，不表示
rollback、conflict 或 backend conformance 已兑现。真实 provider 另以绝对路径 typed marker：

```rust
const LOCALTX_BACKEND_PROFILE_IDENTITY_LOGOUT: ::vocab::HttpRouteBinding<
    ::generated::http::identity_v1::logout::RouteMarker,
    ::vocab::http::LocalTx,
> = ::generated::http::identity_v1::logout::ROUTE;
```

该 marker 必须是 `LOCALTX_BACKEND_PROFILE_*` 具名 const、处于真实 test function，并由同一 adapter provider 的
测试合计提供 manifest-derived required probes；helper 只有作为 test body 顶层且实际 `.await?` 才计入，未轮询
future、分支内符号或别名调用都不构成 evidence。
`tenant-scoped-uow` 额外要求 rollback 与 rollback-failed-no-replay，两个 profile 都要求 validation 与 authorization
各一次 no-write（因此 `assert_rejected_no_write` 至少出现两次）。该闭环由
`LOCALTX-BACKEND-PROFILE-CLOSURE-01` 的 synthetic red 与真实 workspace anti-vacuity 承载（Medium）。

## Follow-up boundary

#1687 的边界是 manifest authoring：

- 补齐 LocalTx 三个新增字段。
- 迁移真实 L1 HTTP `contract.toml`。
- R22 守住 L1 完整证据与 stray capability。

#1688 的边界是 generated metadata；#1698 将其中 LocalTx evidence enum 上移为共享 vocab 类型：

- `::generated::http` 暴露 `LocalTxSpec`，四个字段直接使用 `vocab::LocalTx*`，不保留 generated 镜像 enum。
- LocalTx active HTTP `SPEC` 必填 `local_tx: Some(...)`，非 LocalTx 为 `None`。
- `LOCAL_TX_SPECS` active-only 派生当前 L1 HTTP contract 子集。
- consistency/effect/auth/path/method 已由 #1690 收进 `SPEC.route: HttpRouteEvidence` 并随 endpoint/RouteMeta
  原样传播；`local_tx` 继续只表达 L1 专属 transaction capability，不复制 route proof。
- 不做 LocalTx runner、coverage gate、metrics label 或 domain proof。

#1697 建立上述 LocalTx coverage gate；#1698 以共享类型身份收口 LocalTx vocabulary/closed labels；#1699 已接入
Postgres runner；#1700+ 再补真实域路径、rollback/conflict 与 conformance 证明。
