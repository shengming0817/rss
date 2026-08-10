# Research: Standalone Component 候选边界

## 当前事实

- 产品面与候选/激活语义由 [`ADR-024`](../../architecture/202608012034-024-enterprise-framework-product-surface.md)
  拥有；公共消费和发布范围由 [`project-scope.md`](../../rules/project-scope.md) 拥有。
- [`Spec 010`](../010-release-surface-convergence/research.md) 已决定未进入正向发布集合的 package 默认 internal。
- `rss-diag-context` 与 `rss-trace-context` 已完成最终窄腰，并以 crates.io-only eligibility 进入 Release Surface；
  candidate eligibility 不构成 RC、published 或支持承诺。
- `diagctx` 已有仓内真实 consumer，并与授权 context 分离；`tracewire` 的仓内 HTTP、outbox 与 consumer 调用方已
  迁移到候选 typed API，不保留旧 raw-string 入口。
- 独立 Plain Rust consumer 的稳定源码链接是
  [`shengming0817/rss-standalone-consumer`](https://github.com/shengming0817/rss-standalone-consumer)，repository
  custody 为 `ghbvf`、maintenance 为 `github:shengming0817:rss-maintainers`；RSS 只保存 reviewed gitlink 和消费契约，
  不复制外仓源码、lockfile、CI、动态 digest 或 receipt。

本规格不复制 package inventory、代码行数或 API 符号快照。实现 PBI 必须重新从当前 Cargo metadata 与源码读取事实。

## NW-003 设计依据

- 当前 `diagctx` 同时公开 `ctx/local` 模块与根级 re-export，internal public-api snapshot 因而有双路径；这不是
  候选应继承的 SemVer 面。其 parse、ambient `Option` 与 opaque future 已证明输入拒绝和传播 fail-open 可行。
- `tracewire` 已由 owned `TraceParent` 收口严格 W3C 验证，restore 只接受 typed parent 并返回闭值 outcome；HTTP
  与 broker 边界不再维护平行 validator，OpenTelemetry parser/error/context 只留在私有桥中。
- 两个 candidate 的历史 `public-api/*.txt` 已被破坏式移除，唯一 owner 是各自双 profile
  `release-api/*.txt`。两类 baseline 互斥，不能互相冒充。#2047/#2048 分别拥有 baseline 分离与
  release-selected leakage gate。
- Tokio task-local 采用 `try_with` 而非缺值 panic 的 `with`；RSS 将缺诊断稳定为 `None`。OTel 0.32 propagator的
  SDK parser/error/context 在私有 adapter 层结束；候选只承诺 W3C 1.1 线语义和无原始输入的闭值分类。
- #1400 已由 `rss_diagctx_auth_source` 吸收：授权 owner 的真实 `diagctx` path 由 HIR `DefId` 门约束，HTTP audit
  enrichment 物理移出决策模块。精确 API 与预算只以 [`spec.md`](spec.md#nw-003-规范性窄腰契约) 为准。

## 候选选择

首批只选择两个低依赖、框架中立的候选，以验证两类独立价值：

- diag-context：请求/任务范围内的 correlation 与诊断上下文；不参与身份、租户或授权决策。
- trace-context：W3C traceparent 的稳定线语义；具体 telemetry SDK 保持实现细节。

候选名称仅表达能力后缀。公开品牌、前缀、registry 可用性和最终 package 名由 #2046 的维护者决策拥有。

## 发布闭环决策

```text
governance owner
      |
public naming decision
      |
candidate Cargo closure
      |
shared packaging mechanics
      |
diag candidate + final artifact proof || trace candidate + final artifact proof
      |
independent Plain Rust consumer
      |
manual RC closeout
```

临时 workspace 外目录只证明 packaging mechanics，不能替代最终 API 产生后的 artifact proof。每个候选必须从其最终
revision 生成 `.crate` 并在 workspace 外完成 canonical proof；真实 consumer 只能消费这些已证明的 artifact，也不能
替代最终人工发布批准。

## 失败与信任边界

- 诊断和 trace propagation 是可观测信道，缺失或畸形输入 fail-open；它们不能 mint Principal、Tenant 或授权 receipt。
- TraceParent 必须先验证再暴露；成功恢复和各类拒绝结果产生闭值、无原始输入的诊断 outcome，不得把裸 SDK 类型
  变成公共 wire 语义。
- package tarball 必须是验证输入，workspace/path build 不能冒充发布证明。
- 单包 archive fixture 只闭合 package 自身 hazard；真实 consumer 必须从 pinned 外仓 commit 同时消费本次 RSS HEAD
  生成的两个 archive。gitlink、selected/artifact/resolved/executed exact-set 与 lock checksum 任一漂移都必须失败。
- package digest 与 same-revision 结果只进入 closeout evidence，不形成 committed receipt database；早于最终 API 的
  mechanics 结果不得晋升为该证据。

## AI-HARD 判定

| 风险 | Owner | 载体 |
|---|---|---|
| 候选依赖 internal crate | Cargo dependency/publish closure | Hard graph + Medium package check |
| SDK/test-util 泄漏 | visibility、public signature、release API baseline | Hard/Medium T1 |
| malformed trace 静默丢失 | 闭值诊断 outcome + tarball consumer | Medium T1 |
| 诊断输入影响授权 | 独立 crate/type/task-local + `rss_diagctx_auth_source` | 类型/crate 隔离 Hard + resolved-`DefId` 模块/path Dylint Medium |
| workspace build 掩盖 tarball 缺陷 | actual `.crate` + external Cargo invocation | Medium T1/T2 接缝 |
| 未经批准宣称发布 | human-owned closeout + release documentation | 人工决策；不伪装为代码 gate |

Markdown 只描述 owner 和失效模式，不承担 enforcement。
