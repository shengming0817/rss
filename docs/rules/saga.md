# Saga 规则

本文拥有 Saga definition identity、typed step、durable intent/effect/receipt、activation 与 worker recovery。

## Definition 与 identity

- saga contract/definition 使用稳定 typed ID、version、tenant scope 与 ordered step catalog。
- persisted instance 固定 definition fingerprint；resume 必须解析原 exact definition，不能静默升级到 latest。
- 删除仍有 non-terminal instance 的 definition/version 必须被 breaking/retention proof 拒绝。
- 同 instance/sequence 不同 content 是冲突；同 content 重投幂等。

## Typed start 与 step

- start 必须消费 generated typed input、verified tenant/auth context 与 stable idem key。
- step wrapper 闭合 action、retry/timeout、compensation、input/output schema 与 effect identity。
- domain code 不取得 raw store、lease、journal cursor 或 transport；worker 只执行 validated typed definition。
- unknown action/step/version、缺 capability 或 schema mismatch fail-closed。

## Durable protocol

- intent 在 effect 前 durable；effect completion/unknown 与 protected receipt 在同一 fenced journal protocol 记录。
- external effect 必须使用 stable idem key/fencing；commit/transport unknown 不得自动执行 compensation。
- compensation 是独立 typed effect，只在原 effect outcome 已知且 policy 允许时运行。
- receipt 绑定 tenant、saga、instance、step、attempt、effect fingerprint 与 key purpose；缺失/篡改不可 hydrate。
- journal append-only，instance/lease/journal/receipt 由单一 durable store 原子视图拥有，不拆第二 owner。

## Lease 与 worker

- claim/renew/finish CAS 匹配 lease token、epoch、expiry 与 definition identity。
- lease lost 立即 hard-fence 后续 journal/effect；stale worker 不得 finish/compensate。
- retry 使用 persisted absolute deadline/backoff；restart 不重置 attempt 或预算。
- worker admission 有界；drop/cancel 不表示 durable completion。

## Activation

- definition lifecycle 与 deployment activation 正交。只有 validated RuntimePlan activation 可构造 store、worker、
  route、probe 与 operator surface。
- resolver/provider available 不代表 saga active；omitted/disabled 不得产生任何 runtime side effect。
- active requirement 必须同时闭合 definition、durable store、dead-letter/operator capability、probe 与 worker。

## Failure 与 operator

- tenant/definition/lease mismatch、store unavailable、receipt invalid 或 journal conflict 返回 typed interrupted outcome，
  不触发猜测式 compensation/DLQ。
- resume/redrive/resolve 消费 tenant/action/caller/audit 绑定的 move-only authorization；mutation 与 finish audit 原子。
- retention/maintenance 使用独立 capability，不给 serving role raw UPDATE/DELETE。

## Carrier

- Hard：generated definition/action types、private lease/receipt/authorization、closed outcome与 required activation view。
- Medium：contract/activation closure、store/provider conformance、fault/restart/operator proof。
- Saga/L3 不自动授权 production T3。
