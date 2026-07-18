# LocalTx 规则

本文件记录 L1/LocalTx 已落地的声明、执行与验证边界。机器真源是 `xtask` typed manifest/R22、
`vocab::LocalTx*` 闭值、generated `LOCAL_TX_SPECS`、typed route/provider marker、conformance、Postgres
runner、metrics 和 active journey；本文不维护平行 gate inventory。

## Proof chain and validation levels

采用顺序是 contract LocalTx evidence → generated registry → owner/production route → domain conformance →
typed backend profile/provider probes → Postgres runner settlement/telemetry → active journey。任一层缺失、重复、
未知、孤立、伪造或 route/provider 身份不一致都 fail-closed。

- `verify --fast` 的 inner typed plan 执行 contract/codegen 漂移和 `localtx-coverage` 静态闭环；不包含
  workspace build/test 编译门，也不运行 conformance 或连接 Postgres；冷缓存或 xtask 变更时，外层 Cargo
  仍会构建 xtask 启动器。
- 完整 `verify` 额外执行 workspace/default conformance 和 integration-target compile-only；编译成功不等于
  真实事务矩阵已执行。
- `cargo xtask ci run --job integration/postgres-domain` 执行真实 SecretRepo/Identity matrices 与 active LocalTx 5/5 journey，
  required tooling、服务启动和编译后测试 inventory 均 fail-closed，closeout 不使用 `--allow-missing-tools`。
- CI 为该唯一 owner 显式传 `--required-evidence-output`；只有 typed batches 全部成功且 canonical inventory
  得到 active/journey/backend-profile = 5/5/5 时，私有成功令牌与计数令牌才能铸造 v1 receipt。`ci-gate`
  对 receipt 的 artifact、HEAD、plan digest、run/attempt 做 exact match；缺失、重复、失败、旧 schema、错
  identity 或任一 4/6 漂移均 fail-closed。静态 proof/report 不进入该真实后端证据槽位。

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

`settings.secret-publish` 使用 `repo-atomic-cas`：应用层先经只读 `SecretRepo` 读取最高版本并构造候选
`SecretEntry`，最终正确性由 `SecretUnitOfWork::publish` 的单次条件写保证；并发竞争失败映射为
`VersionConflict`，不得把两次 port 调用描述成同一显式 UoW。HTTP command 同时携带 settings 域从 generated
route 铸造的 LocalTx observation；内部 publish 与 rollback republish 使用互不可换且不携带 HTTP evidence 的
command。Postgres adapter 在同一 transaction attempt 内先获取 `(tenant, secret_key)` advisory lock，再经私有
`LockedSecretKey` capability 执行 CAS INSERT；同一写 port 的 delete 经该 capability 追加 tombstone，因此
publish/publish、publish/delete 与 delete/delete 均按同一 key 线性化，不能用未锁定连接直接写 `secret_refs`。

`identity.password-change` 同样使用 `repo-atomic-cas`：handler 路径为 find credential → 校验旧密码 →
`rotate` 构造下一版本 → `PasswordChangeMutation` → 单次 `CredentialRepo::apply_password_change` CAS；业务正确性由该次条件写保证。
`VersionConflict` / 写入结果未知不得由 handler 自动重试；调用方须基于新版本发起新的业务请求。
不得把 find 与 CAS 描述成同一显式 UoW。

`audit.list-tenant-entries` 的 LocalTx UoW 只覆盖持久 `auth_audit_events` append。append 成功提交后才签发
`CrossTenantReadScope` 并执行专用 admin pool read；append 与 read 不在同一事务，系统也不自动重试整条
append+read 序列。应用层只能构造 `AuditListTenantAppend`，将 target-derived `TenantRepoScope`、规范化事件与
`LocalTxObservation<AuditListTenantRouteMarker>` 同源封装；`AuditListTenantAppender` 只消费该 route-specific
typed command，adapter 不能把其它 route 的 observation、裸 tenant 或 generic append 接到该事务边界。

`identity.refresh` 通过 `RefreshRotationMutation` 将 sealed rotation 与
`LocalTxObservation<RefreshRotationRouteMarker>` 同源封装，adapter 只能消费该 typed mutation。durable journey 的
`commit-unknown` case 返回 500 / `ERR_CORE_INTERNAL`，`retryable = false` 且 `attempts = 1`；fixture 特意省略
`commits`，因为首次提交可能已经 durable，unknown outcome 既不能伪断言提交数，也不能自动 replay 轮换。

`LocalTxFinalStatus`、`cotx` 与 handler 级 UoW settlement 语义只描述 `tenant-scoped-uow`，不可外推为
`repo-atomic-cas` 的业务模型（handler 不持有显式 UoW，也不按 UoW 语义重放整条 find→mutate 序列）。
Postgres `run_pg_tx_retry` / `LocalTxAttempt` 仍可作为 **mutation port 内** 单次 CAS 的底层事务承载：仅对
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
第二套 enum 或 allowlist 重述。`localtx-coverage` 将每个 active contract 注册到 `adapters/*` 的真实 provider
tests；每个测试函数只能声明一个 `LOCALTX_BACKEND_PROFILE_*` marker，禁止多个 contract 共用同组 probes。
同一 contract 可拆成多个 contract-specific shard，required probes 只在 route + provider 二元组完全一致时合计。
每个 shard 还必须声明匹配的 `LOCALTX_BACKEND_PROVIDER_*: PhantomData<(RouteMarker, ProviderFixture)>`，并在
测试体中通过 `ProviderFixture::new(...)` 构造真实 provider；`run_global_transaction` 与
`localtx_profile_probe` toy table 明确禁止作为 backend evidence。缺 enrollment、错用较小 profile、缺 probe、
缺 provider binding、单测试多 marker、伪造 dependency 或孤儿 marker 均阻断 verify。对于
`audit.list-tenant-entries`，provider binding 进一步闭合为 `crate::PgAuthAuditSink`；五个 shard 均经 sealed
`AuditListTenantAppend::for_test` 驱动真实 `auth_audit_events` append，并由 route-local fault seam 验证 retry 与
unsafe settlement。正确 route marker 配错 `PgAuditRepo` 等 provider 仍 fail-closed。
类型签名承担 Hard 的 route 身份约束，跨 manifest/source/test 的完整闭环评级为 Medium。

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
不伪造 snapshot/no-write 结论。`settings.secret-publish` 的 marker 与 commit/rollback、tenant isolation、CAS conflict、
tombstone monotonicity 证明位于真实 `PgSecretRepo` + `PgSecretUnitOfWork` / `secret_refs` backend matrix；通用
toy transaction table 不作为该 contract 的仓储语义证据。

ref: sqlx sqlx-core/src/transaction.rs@bab1b022bd56a64f9a08b46b36b97c5cff19d77e
ref: sqlx sqlx-core/src/pool/connection.rs@bab1b022bd56a64f9a08b46b36b97c5cff19d77e

Postgres runner 以 `cotx::settlement` 私有模块持有的 crate-private `LocalTxAttempt<T, E>` opaque 和式
状态承载 `Committed` / `Unsettled` / `RolledBack` / `RollbackFailed` / `CommitUnknown`，非法的
result/status 组合在类型层不可表达（Hard）。生产 mint 构造器为 `pub(super)`，仅 `cotx` settlement
funnel 可铸造；兄弟模块与 `tx_retry` 只能消费。`PgTenantWritePool` 是 tenant scope 与 write transaction
capability 的唯一入口；`cotx` 在每次 attempt 内先显式 acquire pooled connection 并立即装入默认 armed 的
`LocalTxConnectionLease`。lease begin 时把 transaction 与同一 lease 的 closed armed stage 分字段独占借入私有
`LocalTxTransaction`；调用方不能构造 wrapper、取得 pooled connection 或跨 attempt 复用授权。wrapper 经
`SET LOCAL` 与事务体后被单一 settlement funnel 消费；只有其自身 commit/rollback 收到明确 ACK，消费式方法才
直接把原 lease stage 置空。stage 仅为 `begin` / `body` / `commit` / `rollback`，armed Drop 在发射同一闭标签的
quarantine counter/WARN 后 `close_on_drop()`；它不携租户/SQL/错误文本，也不伪造 settlement。`LocalTxAttempt`
只承载结果/重试证据，不再参与连接复用授权；
`Unsettled`（acquire 后 begin 失败）、`RollbackFailed`、`CommitUnknown` 以及 begin/body/settlement future 被取消
或 timeout 均保持 armed，Drop 时 `close_on_drop`，不得依赖 SQLx queued rollback + release ping 恢复后复用。
取消路径没有结算证据，不得伪造 final status。显式 rollback 失败时经 `map_storage` 收口为独立 Storage settlement
错误（保留 primary+rollback 因果链），不再把领域冲突（如 `VersionConflict`）误分类为 transient retry。
Postgres retry operation 只接受 `LocalTxAttempt`：`Unsettled` / `RolledBack` 仅在分类为 transient 时有界
重试，`RollbackFailed` / `CommitUnknown` 强制不可重试。通用 `run_pg_tx_retry` 保留 adapter operation
boundary 的 retry-loop 指标；LocalTx contract 必须改用 `run_pg_localtx_retry`，并传 opaque
`LocalTxObservation<M>`。每个 LocalTx generated module 暴露非可选 `LOCAL_TX`，并令 `SPEC.local_tx =
Some(LOCAL_TX)`；非 LocalTx module 不生成该常量。observation 由 typed
`HttpRouteBinding<Marker, LocalTx>` 构造并用私有 `PhantomData<M>` 保留 route marker。identity 应用层分别把
generated logout/password-change `ROUTE + LOCAL_TX.boundary` 封装进私有字段 `SessionLogoutMutation` /
`PasswordChangeMutation`；settings 同样封装进 `SecretPublishCommand`。生产 adapter 只能消费
`command.into_parts()`，不得调用 domain factory、替换 observation 或手制 evidence；Postgres 不建立被分层禁止的
production generated 依赖，而是消费 domain port 暴露的 marker alias。`PgSecretUnitOfWork::publish`、
`PgCredentialRepo::apply_password_change` 与 `PgSessionLifecycle::logout` 使用 `run_pg_localtx_retry` 发射 HTTP
contract telemetry；`publish_internal` 与 rollback `republish` 不携带该 command，
只经 `run_pg_tx_retry` 发射 generic `settings.secret` retry telemetry，不能冒充 HTTP 调用。non-retry
outbox producer 则必须消费 move-only `ProducerTxAttempt`，在压平为领域 `Result` 前与 generic runner 共用唯一
settlement router 发射闭值 `tx_settlement_final_total`。该 signal 不携带 domain / contract id，
unsafe 终态仍可独立告警。两个 retry runner
复用同一个私有 retry core，不以 `Option` context
或 bool 在运行期区分语义。该 core 既服务 `tenant-scoped-uow` 准入路径，也可被
`repo-atomic-cas` adapter 用于单次 CAS 的底层 settlement；
业务层 CAS 冲突仍按 `repo-atomic-cas` 规则上抛，不经 handler 自动重试。retry engine 与两个准入 UoW
以及三个准入 HTTP mutation 的精确放置由 `LOCALTX-PG-RETRY-PLACEMENT-01`（`pg-tenant-tx-guard`，
Medium）守住：HTTP 路径只接受 typed command 解包出的 marker-preserving observation、无 boundary 参数的
`run_pg_localtx_retry` 与 `retry_write` 同址 AST 形状。crate-private `PgLocalTxOperation` 仅为三个已知 domain
route marker 实现，并从 marker 派生唯一 `PgTxRetryBoundary`；错误 route/boundary 配对不可编译。旧
`SecretRepo::save`、identity 旧 port、adapter factory、generic/legacy `write`、手制 observation 或手工 boundary
均阻断 verify。internal publish / republish 只接受 generic runner，
三条 publish 语义最终共享唯一 keyed CAS attempt funnel；delete 共享同一 lock capability 并只追加 tombstone。

所有 Postgres LocalTx retry invocation 使用 `LocalTxExecutionBudget` 的单一默认值：10s total、2s settlement
reserve、8s operation。budget 只保存 `Duration`，零值、零 reserve 或 `reserve >= total` 无法构造；runner 在
invocation 起点只 mint 一组 absolute monotonic deadline，并把同一 opaque `LocalTxDeadline` 复制给所有
attempt。token 字段与构造器私有，caller closure 必须接收 `(attempt, deadline)` 并把 deadline 立即传给
`retry_write` / `retry_producer_tx`；不能重置 budget、读取 raw `Instant`、跨 helper 转发或手制 token。
operation deadline 分别约束 `acquire` / `begin` / `setup` / `operation` / `backoff`；到达 reserve 后不再 poll
operation 或启动下一 attempt。setup 从 operation 剩余量设置 `statement_timeout`（client deadline 前至少 1ms）
与 `lock_timeout = min(statement_timeout, 5s)`；client monotonic deadline 始终为最终约束。

deadline evidence 只由 transaction/settlement funnel 以闭合 `Acquire` / `Begin` / `Setup` / `Operation` /
`Backoff` / `Commit` / `Rollback` mint，并直接进入 opaque `LocalTxAttempt` 失败变体，不从错误字符串或共享 stage
tracker 推断。operation timeout + rollback ACK 为 `RolledBack(Operation)`；rollback timeout 为
`RollbackFailed(primary?, Rollback)`；commit timeout 为 `CommitUnknown(Commit)`；acquire/begin timeout 为
`Unsettled(stage)`，armed lease 继续负责 quarantine。`run_tx_retry` 的 backoff 返回 typed
`Continue` / `Exhausted`；Exhausted 保留最后错误且不启动新 attempt。`LocalTxObservation` 只发射闭标签
`localtx_deadline_exceeded_total{domain,contract_id,boundary,stage}`，禁止 tenant、SQL、错误文本和 duration，也不
新增 paging alert。唯一 mint、九处 caller dataflow、五个 typed observation owner、必填 mutation token 与
唯一 settlement funnel 继续由现有 `LOCALTX-PG-RETRY-PLACEMENT-01` / `PG-LOCALTX-QUARANTINE-FUNNEL-01`
守卫及 synthetic-red/anti-vacuity 阻断，不建立 v2 descriptor 或平行 proof artifact。

连接复用权限由 `PG-LOCALTX-QUARANTINE-TYPE-01` 的私有 armed lease + borrow-bound transaction wrapper 在类型
边界封闭；两个生产 write funnel 必须有一条符号绑定一致的 acquire→begin→consuming finish 顶层必经数据流，且
finish 必须为 tail expression，由
`PG-LOCALTX-QUARANTINE-FUNNEL-01`（`pg-tenant-tx-guard`，Medium，含 synthetic red）阻断 direct
`pool.begin()`、helper transaction、shadow/reassign/drop、条件/closure/未 await async/提前 return、跨文件 impl、
自由函数 disarm/raw connection escape 与 fail-open Drop；变量改名或等价字段解构顺序不构成源码协议。

`observ::LocalTxObservation<M>` 从 typed generated route 私有提取 domain / contract id、在类型中保留 marker，并以
`LocalTxBoundary` / `TxRetryClass` / `LocalTxFinalStatus` 的闭标签发射 metrics 与 trace。每个 failed attempt
记录 settlement-safe retry class；invocation 结束只在本轮曾存在真实 settlement 时发 final 指标，并保留最后
一个 `Some(LocalTxFinalStatus)`，后续 begin 前 `Unsettled` 不得擦除已观测 settlement。全程只有 `Unsettled`
则没有 transaction outcome，不得映射为 rolled-back 或 commit-unknown。`commit_unknown` / `rollback_failed` /
retry exhausted 在 metrics 与 warn trace 中显式可见，且不改变 #1699 已闭合的 no-retry settlement 语义。

## Static coverage gate

`cargo xtask localtx-coverage` 以 active LocalTx HTTP manifest 为真源，逐条闭合 generated
`LOCAL_TX_SPECS`、owner domain、生产 typed route mount 与测试 marker。该检查的 inner gate 不调用
workspace build/test 编译，并进入 `cargo xtask verify --fast`；缺失、重复、孤儿或错误 owner 的证据均
fail-closed。

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
const LOCALTX_BACKEND_PROVIDER_IDENTITY_LOGOUT: ::std::marker::PhantomData<(
    ::generated::http::identity_v1::logout::RouteMarker,
    crate::PgSessionLifecycle,
)> = ::std::marker::PhantomData;
```

该 marker 必须是 `LOCALTX_BACKEND_PROFILE_*` 具名 const、处于真实 test function，并由同一 adapter provider 的
typed shards 合计提供 manifest-derived required probes；provider binding 名必须与 profile suffix 一致，route marker
必须一致。profile test 自身及所有祖先 scope 都不得带 `#[ignore]` 或 `#[should_panic]`；required receipt 只统计
绑定到 `postgres-domain` typed `postgres:postgres` lib execution unit 的完整 profile，并按不同 contract id
计数，重复 profile 不能掩盖缺失 contract。每个 probe 的 provider action 都必须把一个以 canonical `Provider::new(...)` 为 initializer dataflow root
的绑定直接传入 method receiver/实参，并让该 method call 经 `?`、显式 `return` 或 action 尾表达式决定结果；普通
free function、裸引用、丢弃 call 结果、aggregate result binding/projection、同名 shadow constructor、
block/tuple/dead-branch bait、observer-only 引用和 `.synthetic()` outcome 都不计。若需先观测数据库状态再返回 provider
错误，只允许把 provider method 的透明 `await`/`?`/receiver-method chain 直接绑定为结果，不允许经 tuple/struct/array 包装。
helper 只有作为 test body 顶层且实际 `.await?` 才计入，未轮询 future、分支内符号或别名调用都不构成 evidence。
`tenant-scoped-uow` 额外要求 rollback 与 rollback-failed-no-replay。HTTP validation、unauthenticated 和 route
authorization rejection 若发生在 provider 之前，只由真实 journey 证明零写，禁止登记成手造 backend outcome；
`rejected-no-write` 仅在 action 真调用绑定 provider 时可计。该闭环由
`LOCALTX-BACKEND-PROFILE-CLOSURE-01` 的 missing-binding、toy-transaction、multiple-marker、missing-probe
synthetic red 与真实 workspace anti-vacuity 承载（Medium）。

active L1 journey 由 `scope = "active-localtx"` 的 v1 status board 将全部五条 active LocalTx HTTP contract
（`audit.list-tenant-entries`、`identity.logout`、`identity.password-change`、`identity.refresh`、
`settings.secret-publish`）与 spec、fixture、各自唯一的 contract-specific runner 做 1:1 闭合。board contract
集合直接等于 active manifest discovery；新增、遗漏、重复或非 active entry 均 fail-closed，不维护 issue allowlist。
Runner 中具名
`LOCALTX_JOURNEY_*: HttpRouteBinding<RouteMarker, LocalTx> = generated::ROUTE` 由 rustc 固定 route 与一致性级
身份（Hard）；跨 TOML、manifest 与 runner 的完整性由 `LOCALTX-JOURNEY-CLOSURE-01` 接入 verify 阻断
（Medium，含 synthetic red 与真实 workspace anti-vacuity）。该 Medium 闭环同时拒绝祖先 `cfg/cfg_attr`
禁用的 runner，要求每个 fixture case 唯一流入已执行的 `drive_*` / `observe_*` consumer，并把 target 固定为
`postgres-domain` 的唯一 Serial batch；该 batch 显式 `--no-tests=fail`，因此编译后的测试清单为空会失败。
durable runner 逐请求隔离采集 `localtx_retry_attempts_total`、`localtx_final_total` 与 `localtx_attempts`，并在
测试结束时确认每个 case 的 HTTP response 与 LocalTx accounting 均已被观测，拒绝用请求数字面量自证。
`identity.logout` 不伪造业务 conflict：其
tenant-scoped-UoW matrix 必须把 conflict 声明为不适用并给出原因，实际第四路径验证并发与重复请求幂等收敛。
`audit.list-tenant-entries` 与 `identity.refresh` 同样把不暴露业务 CAS conflict 的原因显式声明为
`applicable = false`。`commit-unknown` 是 closed journey scenario，只在具备该可观测路径的 journey 中声明；仅该
scenario 的 fixture case 可省略 `commits`，其它 case 必须提供精确 attempts/commits accounting。

## Failure and adoption semantics

LocalTx adoption 的 planning entry 是
`.specify/templates/overrides/localtx-tasks-template.md`。它必须恰好列出以下七项 canonical checklist，不允许缺失、
重复、未知项或 command/path 漂移：

1. contract evidence
2. generated check
3. typed route marker
4. backend profile/probes
5. active journey
6. metrics/alerts
7. runbook/report consumption

manifest 的闭值、codegen registry 与 typed route marker 是 Hard carrier；manifest/source/test、backend/journey、
template 和 operations 的跨文件闭合由 `localtx-coverage` 与 observ contract test 作为 Medium carrier 阻断。模板
本身只是 planning entry，not an enforcement carrier，不能把勾选状态当作实现证据，也不修改 Spec Kit resolver、
skills 或 hooks。七项结果仍必须分别落在对应的 typed/compiled/static gate carrier 中。

静态 proof report 的 canonical 入口是：

```bash
cargo xtask localtx report --format json
cargo xtask localtx report --format markdown
```

生成、policy/structural failure 区分、原子发布和真实 backend 边界见
[`docs/ops/localtx-proof-report.md`](../ops/localtx-proof-report.md)。报告与 `localtx-coverage` 共享 typed static
inventory，但 report 不是新的 enforcement carrier，也不替代 required real-backend evidence。

新建或修改 LocalTx contract 时，先选择与实现一致的 `txModel` 并补齐全部闭值 evidence，再生成 registry、绑定
唯一 owner/production route、为真实域路径补 conformance，并在需要 Postgres 事务语义时注册一对一的 typed
backend profile/provider probes。每条 active LocalTx HTTP contract 都必须进入 active journey；metrics/traces 必须
复用闭值 label，不能用自由字符串、第二套 enum、toy transaction 或文档声明替代证据。

静态门会拒绝 manifest/generated/owner/route/test、backend profile/provider/probe、journey board/spec/fixture/
runner/lane 的缺失、重复、未知或孤立关系。前置 validation 与 unauthenticated 路径必须证明 no-write；已认证
authorization deny 若契约要求 durable denial audit，只允许写该目标绑定的拒绝审计，业务读/写仍必须为零且
fixture 必须精确声明 attempts/commits。CAS conflict 与 permanent error 恰好一次且零写；transient 只在确认 rollback
后按预算重建 transaction scope。`commit_unknown`
和 `rollback_failed` 都只能断言 attempt = 1：第一次 attempt 可能已经 durable，禁止 replay，也禁止伪造 snapshot
或 no-write 结论。

durable journeys 对五条 active LocalTx contract 做 5/5 穷尽闭合；`identity.logout` 的第四路径验证并发/重复请求
幂等收敛，不能为满足矩阵而伪造业务 conflict。refresh 的 unknown settlement 只证明一次 attempt 与不可重放，
不能把 outcome unknown 降格成 confirmed rollback 或零提交。

历史交付链 #1687/#1688/#1697–#1706 与 #1775 已完成 manifest、共享 vocab/generated metadata、coverage、runner、
domain/adapters、conformance、metrics 和 journey。旧 boundary-only evidence、generated 镜像 enum、bare marker、
legacy runner 和手制 observation 均已删除，不提供兼容入口。
