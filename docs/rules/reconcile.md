# Reconcile 控制环规则

本文拥有 L4 desired/actual convergence、durable state、admission、fencing 与 leader semantics。

## 适用边界

- Reconcile 用于可重复观察且可收敛的 desired/actual resource；一次性业务事务使用 LocalTx/Outbox/Saga。
- framework 拥有调度、lease、fencing、retry 与状态；domain policy 拥有 observe/diff/converge 语义。
- 外部资源管理面仍属 External；RSS 只拥有 contract、adapter 与收敛正确性。

## Contract 与模型

- contract 声明 resource identity、tenant、desired generation、trigger 与 L4 consistency。
- `Desired`、`Actual`、`Diff`、`ConvergeOutcome` 为 typed boundary；禁止 map/string DSL 或 raw provider result。
- no-diff 必须 no-op；same generation/different desired fingerprint 是冲突。
- command/receipt identity 包含 tenant/resource/generation，保证 retry/restart 幂等。

## Durable state

- durable owner 保存 desired generation/fingerprint、claim/lease epoch、attempt、next wake、terminal condition 与 receipt。
- state transition 使用 transaction/CAS；stale epoch/generation writer 必须拒绝。
- wake/lease/retry deadline 是 absolute persisted value，restart 不重置预算。
- history/receipt append-only；serving role 不 UPDATE/DELETE，maintenance 使用独立 capability。

## Admission 与并发

`INVARIANT: RECONCILE-MAX-IN-FLIGHT-01`：typed config/constructor 必须拒绝零值与无界 admission。

`INVARIANT: RECONCILE-BOUNDED-ADMISSION-01`：scheduler 只在 permit、lease、deadline 与 current generation
同时有效时 dispatch；队列/permit 不得绕过。

- 同 resource 只有一个 current writer；不同 resource 可按有界公平策略并发。
- tenant/resource hot key 不得无限饿死其它 ready item。
- cancellation/drop 不等于 durable completion；未结算 item 由 lease expiry/restart 恢复。

## Fencing 与 leader

- leader lease 只控制调度资格，最终写入仍由 per-resource monotonic epoch/CAS fencing 保护。
- lease lost 立即停止 admission并取消可取消 dispatch；在途 stale writer 的后续写必须被 store/target 拒绝。
- 不能用 process mutex、Redis lock 或 current leader observation替代 durable fencing。
- leader/config/provider unavailable 时 not-ready/fail-closed，不降级多 writer。

## Command 与 provider

- converge side effect 经 typed adapter 或 durable command seam；不得直接 raw publish。
- provider error 分类为 closed transient/permanent/conflict/unknown；unknown 不自动重放不可幂等 effect。
- retry 只在确认无 durable side effect或有 idem/fence 时进行；exhaustion 产生 durable terminal/next-action state。
- operator resume/resolve 必须绑定 tenant/resource/generation、caller、reason 与 durable audit。

## Carrier

- Hard：typed model/state、private lease/epoch/permit、required builder inputs 与 fenced writer。
- Medium：store/provider conformance、scheduler synthetic-red、real backend concurrency/restart/operator proof。
- production journey 只有经正式 acceptance 才进入 T3。
