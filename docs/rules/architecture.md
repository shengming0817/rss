# RSS 架构规则

本文拥有稳定架构风格、命名与事实 owner 总图。目录职责、依赖方向和精确 runtime 组合由各自 typed carrier
承载；本文不维护 crate、gate、provider 或 package 当前清单。

## Domain-native

- 一个 bounded context 对应一个域 crate；feature 是域内模块，不创建横跨 owner 的共享业务层。
- 跨域只经 versioned contract；不得通过直接 import、共享 entity/repository 或数据库表绕过。
- composition root 选择 provider、构造依赖并拥有 lifecycle；domain 不读取环境或动态定位 adapter。
- external control plane 只经窄 contract/port/adapter 接入，RSS 不吸收其资源生命周期。

## 命名

- Rust package/crate 使用稳定、无组织前缀的内部 identity；发布 package 使用 Release Surface 中显式选择的
  `rss-` registry identity。内部 dependency rename 或 repository path 不是公开 package alias。
- 公开 package 的 registry owner、source repository、publish eligibility 与冲突检查由 package metadata、
  Release Surface 和 registry proof 持有；Markdown 不复制当前映射或名称可用性快照。
- contract ID、domain、route、event/command topic 与 error namespace 使用 typed canonical value，不从路径或显示名猜测。
- DB 使用 `snake_case`；JSON/query/path 使用 contract 派生的 `camelCase`。
- internal `pub`、public-api baseline、Markdown 或同名类型都不自动建立产品发布承诺。

## Owner 总图

| 事实 | Canonical machine owner |
|---|---|
| workspace member、package kind、依赖边 | Cargo manifest/metadata、typed layer catalog |
| wire identity 与 lifecycle | contract/schema、deterministic codegen |
| Foundation public primitive | owner package 的 private-representation/closed-value type、Release Surface、typed rustdoc projection |
| Release API 与 breaking | release catalog、public-api/breaking consumer proof |
| provider 与 runtime closure | assembly manifest、generated catalog、AssemblyLock/RuntimePlan |
| tenant/auth evidence | private typed evidence、verifier、RLS/ACL、conformance |
| consistency transition | closed state/outcome、transaction/provider proof |
| observability field/label | typed schema/enum 与 emitting code |

文档、generated report、Markdown matrix 和 issue 状态不得成为第二事实源。

## Contract 与 domain boundary

- contract 声明 wire schema、auth、consistency、owner 与 endpoint；generated 代码是唯一 runtime binding。
- domain entity 不直接序列化到 wire；handler 使用 generated/typed DTO 与 converter。
- active contract 必须有 production owner/mount；draft/deprecated 不得被隐式 serving。
- 跨域 validation/newtype 例外必须是纯计算且不携 provider I/O；LocalOnly 不扩大该例外。

## Composition 与 lifecycle

- provider selection 是 closed typed choice；缺 capability/config 时 startup fail-closed，不 fallback demo/memory。
- prepare/start/readiness/drain/shutdown 使用同一 plan identity；partial startup 逆序 rollback。
- config reload 原子切 validated snapshot，candidate 失败保留 last-good。
- domain init 不做外部 I/O、不 spawn 后台任务，失败返回 typed error 而非 panic。

## Public/internal

- 默认 private/`pub(crate)`；跨 crate 可命名仅在 port/adapter 或 generated binding 需要时开放。
- private field、newtype、sealed trait、typestate 和必填构造器优先使非法状态不可表达。
- official adapter 可实现内部 provider contract，但不因此建立外部 SDK 承诺。
- Foundation primitive 提升必须由 canonical owner 新建 private-representation/closed-value public type，consumer
  原子切换并删除重叠 internal generic type；禁止 alias、跨 owner re-export、shim、双路径与 convenience facade。
- 新 Release API 必须有真实独立 consumer、稳定 owner、SemVer/breaking proof 与同 revision artifact。

## Failure policy

- 未知 owner、无法分类依赖、缺 contract/provider、identity drift 与 ambiguous security/transaction outcome 默认拒绝。
- error 对外稳定且脱敏；内部保留结构化 cause/stage，不以自由字符串驱动控制流。
- 无 carrier 的技术愿望不进入 active rules；需要实施时先建立最低充分 Hard/Medium proof。
