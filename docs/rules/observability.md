# 可观测性规则

本文拥有日志、redaction、HTTP observation、readiness 与低基数 telemetry 原则。精确字段、metric/label 闭集
由 typed schema/enum 与 emitting code 持有，文档不复制目录。

## Logging 与 context

- 使用 structured tracing；event name、severity、stage/outcome/reason 是 typed/closed value。
- request/trace/correlation 只用于关联，不是 tenant、principal、authorization 或 transaction authority。
- credential、token、private key、raw payload、SQL、自由错误文本和 tenant/device PII 不得进入日志/label。
- error 保留 opaque cause chain 与闭值 stage；对外/跨 trust boundary 先脱敏。

## Redaction

- sensitive type 通过 private representation/Redact 派生或中央 scrubber 输出；禁止调用点自制 allowlist。
- 结构化字段按 data classification 决定可见性；unknown field 默认 redact/drop。
- free-form provider error 只能进入受控 debug cause，不进入 response、metric label 或 audit public detail。
- redaction failure 必须丢弃敏感 value，不以可观测性失败阻断业务正确性，除非审计是事务要求。

## HTTP observation

`INVARIANT: HTTP-SERVER-OBSERVATION-POLICY-01`：final router 必须携带 non-optional closed listener policy；
health listener 不产生普通 server span/RED metric，其余 listener 默认启用。Hard carrier 为 sealed metadata 与
adapter-private emitter。

`INVARIANT: HTTP-SERVER-OBSERVATION-ORDER-01`：唯一 adapter seam 覆盖 budget、body limit、auth、panic recovery、
enforcement、handler 与 response-body polling；Medium carrier 为真实 transport test。

`INVARIANT: HTTP-SERVER-TRANSPORT-SCHEME-01`：scheme 只能由实际 bind branch 私有铸造；URI、forwarded header、
assembly 或 public lowering API 不能伪造。Hard carrier 为 adapter-private emitter。

## Readiness

- liveness 只证明进程可运行；readiness 表示当前 RuntimePlan 的 required provider/worker 可接受新工作。
- degraded/unknown required capability 必须 not-ready；optional capability 不得劫持全局 readiness。
- readiness 不暴露 endpoint、credential、tenant、payload 或 provider error text。
- startup 未闭合、drain 已开始或 config/provider revision 不一致时不得报告 ready。

## 告警准入

- transient degradation 不得为了摘流伪报 `Unhealthy`；degraded、stopped 与 terminal failure 使用既有 closed
  health/lifecycle state，不以自由文本合并。
- 只有需要人工核实真实数据库终态的 terminal event 才允许 paging；诊断计数器保持 dashboard/trace 信号，
  不因 hardening 或 closeout 自动新增 page。

## Metrics 与 labels

- metric/label identity 由代码闭值持有；unknown value 映射到显式 bounded bucket 或拒绝，不使用自由字符串。
- 禁止 tenant、user/device/message ID、topic、path raw value、SQL、payload-derived value 和错误文本作 label。
- duration/size 使用 histogram/number，不离散化为无限 label。
- retry、settlement、transaction、transport、projection 与 security failure 使用各 owner 的 typed outcome/reason。
- 新 metric 不自动授权 dashboard、alert、SLO 或 T3。

## Cross-domain transport 与 envelope

- trace propagation fail-open，不改变 auth/tenant/schema validation。
- persisted envelope 的 canonical writer 独占 reserved metadata；业务不得覆盖。
- `INVARIANT: OUTBOX-METADATA-FUNNEL-01` / `DIPORT-ENVELOPE-WIRE-WRITER-01` 的生产 carrier 位于 typed
  envelope/writer 与对应 gates；本文只拥有 telemetry/redaction 边界。

## Audit boundary

- audit 是安全/合规事实，不是普通日志；需要 durable audit 的 mutation 必须按事务规则提交。
- logging failure 不得伪造 audit success；audit payload 仍遵守最小化、classification 与 key rotation。
