# 本地一致性（L0/L1）规则

本文统一拥有 LocalOnly（L0）与 LocalTx（L1）的 contract、effect、failure 与证明边界。

## L0 LocalOnly

LocalOnly 不产生业务持久化、outbox、publish、workflow 或外部 side effect；允许 provider-owned read transaction、
鉴权、校验、投影读取与观测。

- contract/effect 使用闭值 typed metadata；未知 effect 与未分类 port 默认拒绝。
- route 不得取得 write transaction、publisher、command emitter、workflow/reconcile capability。
- auth/audit 若要求 durable write，必须拆为独立非 L0 route/contract；不得把写入隐藏在 middleware。
- runtime conformance 必须证明 success、validation error 与 authorization deny 都没有业务 write/publish。
- carrier：closed effect model、generated route capability、source semantic guard 与 LocalOnly conformance。

## L1 LocalTx

LocalTx 是单域、tenant-scoped 的本地原子写；不表示跨域事务、outbox fact、saga 或 reconcile 已兑现。

contract 必须声明完整闭值 evidence：single-domain boundary、`tenant-scoped-uow | repo-atomic-cas`、
bounded-transient retry 与 commit-unknown non-retryable。

- UoW 每次 transient retry 重建完整 transaction；只有确认 rollback 后可重试。
- CAS conflict 不由 handler 自动重放，调用方基于新版本重新发起。
- commit unknown、rollback failed 均不可自动重放，第一次 attempt 可能已 durable。
- tenant scope 来自 verified context/typed command，禁止 HTTP body、ambient string 或 raw pool。
- 多次 port 调用不得宣称同一 transaction；正确性只由真实 transaction/CAS boundary 提供。

## Transaction outcome

结算是闭值 committed、rolled-back、rollback-failed、commit-unknown；retry class 与 settlement outcome 正交。

- ConsumerTx 复用私有 opaque `LocalTxAttempt`，只通过穷尽 fold 投影到
  `ConsumerTxOutcome<PgConsumerTxCommitProof>`。commit ACK 铸造 proof；缺失 commit ACK 为
  commit-unknown，缺失 rollback ACK 为 rollback-failed 并覆盖原错误分类，确认 rollback 后的 lease lost
  才是 fenced，其余 storage failure 是 infrastructure-transient。
- 明确 commit/rollback ACK 才可释放 connection lease；取消、timeout、未结算或结算失败必须 quarantine/close。
- validation/unauthenticated 路径 no-write；授权拒绝只允许契约明确要求的 durable denial audit。
- conflict/permanent error 恰好一次且零业务写；unknown outcome 只能断言 attempt=1，禁止伪造 no-write。
- execution budget 使用一次 mint 的 monotonic absolute deadline，跨 attempt 不得重置。

## Proof closure

proof chain：contract metadata → generated spec → production route → component/conformance → provider profile →
真实 backend → active journey。缺失、重复、孤儿、错 owner/provider 或空 inventory 均 fail-closed。

- static gate 只证明声明/route/test closure，不冒充真实 transaction execution。
- real backend receipt 只在 canonical typed batches 全绿时产生；report/Markdown 不是 evidence。
- `CONSISTENCY-EFFECT-BREAKING-REVIEW-01`：effect/consistency fingerprint 与 breaking policy 由 closed types
  和 base/current deterministic review 承载；未知变化默认 breaking。

## Carrier

- Hard：closed consistency/effect enums、generated capabilities、typed transaction/lane/outcome 与 private constructors。
- Medium：contract validation、LocalOnly/LocalTx closure gates、provider conformance、真实 PostgreSQL fault tests。
- GA/T3 不由 L0/L1 自动授权，必须独立获得 production acceptance。
