# RSS 规则目录

规则单源：`docs/rules/`。写作与审阅约定见下文；enforcement 机制本身（Hard / Medium / Soft、载体优先级、Hard 范本）见 [`ai-robust.md`](ai-robust.md)。

## 规则文档的形状

规则文档只写规则。每节压成：

```markdown
## <主题>
- MUST / MUST NOT ...
- 失败语义：...
- 载体：`INVARIANT: <ID>` -> `crates/x/src/y.rs` / `cargo xtask <cmd>`
```

不写进规则文档的内容及其去处：

| 内容 | 去处 |
|------|------|
| 交付流水账、「已完成 / 历史交付链」 | 删；需要溯源进 ADR 或已关闭 issue |
| 「当前事实」清单 | 生成物或 ADR 现状节 |
| API / 类型 walkthrough | 对应 crate rustdoc，规则只留禁止项 |
| metric / label 目录 | `observ` / `secure` rustdoc，规则只留命名与 PII 原则 |
| AST / 门实现教学 | xtask 与 lint 模块 rustdoc，规则只写「什么算证据、什么不算」 |
| issue 编号 | 正文禁止当目录；溯源放 `INVARIANT:` rustdoc |

这一条没有机器门，也不该有——为了管 Markdown 再写几百行 Rust 正是下方「门预算」要拦的事。
规则文件瘦到 100–200 行后，多出一段实现解说在 review 时肉眼可见。

## 红线一：门只能锁代码，不能锁文档

任何 enforcement 的 carrier 必须是 **crate rustdoc、lint、类型或测试**。

- **禁止新增**「要求某个 Markdown 文件必须包含某句话 / 某个符号 / 某个小节」的检查——
  正向 doc anchor 不增加任何 enforcement 强度，它只是把已有约束再记一遍账，
  代价是逼规则文档复述实现细节，而实现一漂移文档就过期，于是再加门锁住，形成膨胀反馈环。
- PR CI 不扫描人工维护的 Markdown 内容，包括正向锚点、标题/数量、历史台账和负向措辞。
  如需发现已删除术语或错误语义，只能使用周期性、非阻塞的 advisory grep，由 review 判断是否需要修正；
  不得让文档措辞成为每次提交的合并条件。
- 既有的正向 doc anchor 一律删除。若某条约束找不到代码 carrier，说明它本来就不是可强制约束，
  从文档降级为普通说明，**不得**为它补一个新门。
- 生成物例外：由 `cargo xtask ... --write` 单向写入文档的派生内容不是 doc anchor，
  它的事实源仍在代码里。

## 红线二：门预算

新增 enforcement 机制时，必须在 PR 里声明**它替换或删除了哪个既有门**。只加不减需要显式理由。

理由必须说明为什么被覆盖的失效模式无法并入任何既有门，而不是「多一道保险」。

涉及 enforcement 的 PR review 须核对两条红线：carrier 是代码而非 Markdown（正向 doc anchor 直接 reject）；声明本次替换或删除了哪个既有门。

## 索引

| 文件 | 主题 |
|------|------|
| [`architecture.md`](architecture.md) | 扁平 workspace、分层、Rust 原生强制 |
| [`ai-robust.md`](ai-robust.md) | Hard / Medium / Soft 与载体选择 |
| [`rust-standards.md`](rust-standards.md) | Rust 编码与 API 惯例 |
| [`error-handling.md`](error-handling.md) | 错误码与三层详情 |
| [`api-versioning.md`](api-versioning.md) | API / contract 版本与破坏性变更 |
| [`contract-fanout.md`](contract-fanout.md) | 契约归属与扇出 |
| [`domain-patterns.md`](domain-patterns.md) | 域 crate 模式 |
| [`runtime-api.md`](runtime-api.md) | Runtime HTTP / route 硬约束 |
| [`runtime-wiring.md`](runtime-wiring.md) | 运行时接线与 SharedRuntimeDeps |
| [`runtime-assembly-plan.md`](runtime-assembly-plan.md) | runtime assembly 系列补充规则 |
| [`runtime-deployment-plan.md`](runtime-deployment-plan.md) | RuntimePlan 到 DeploymentPlan 的身份与 secret 边界 |
| [`eventbus.md`](eventbus.md) | EventBus / outbox |
| [`localtx.md`](localtx.md) | LocalTx |
| [`consistency-l0.md`](consistency-l0.md) | L0 LocalOnly |
| [`tenancy.md`](tenancy.md) | 多租户 / ABAC / RLS |
| [`observability.md`](observability.md) | 可观测 |
| [`reconcile.md`](reconcile.md) | Reconcile |
| [`saga.md`](saga.md) | Saga |
| [`security.md`](security.md) | 安全边界 |
| [`audit-ledger.md`](audit-ledger.md) | 审计账本 |
