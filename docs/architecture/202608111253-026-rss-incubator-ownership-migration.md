# ADR-026：rss-incubator Ownership 与 External Consumer Cutover

- **Status**：Accepted
- **Date**：2026-08-11
- **Tracking**：#2093

## Context

RSS 当前通过 `.gitmodules`、`consumers/standalone` gitlink、固定外仓 URL，以及 `package-proof` 对外仓
workspace、lock、metadata 和升级命令的校验，拥有 standalone external consumer 的源码拓扑。这曾为首批
Standalone Component 建立真实跨包消费证据，但也把下游产品 workspace 的构建与安全责任反向纳入 RSS。

[`ADR-024`](202608012034-024-enterprise-framework-product-surface.md) 已将 Reference Extension 定位为未来第一方
外部 consumer，并要求迁出时通过独立迁移决策记录目标仓、版本边界、consumer build、release ownership 和回退方式。
本 ADR 接纳该外部孵化仓边界以及 standalone consumer proof 的切换契约；它不授权迁移现有 Reference Extension
assembly、domain 或 contract。

## Decision

### Repository 与 owner

现有 `shengming0817/rss-standalone-consumer` 原地重命名为唯一 canonical repository
[`shengming0817/rss-incubator`](https://github.com/shengming0817/rss-incubator)，保留 Git 历史。托管平台可能提供的旧 URL
redirect 不是兼容承诺、canonical 坐标或失败 fallback；最终状态不保留 RSS 对旧 URL 的引用。

`rss-incubator` 是 RSS 的 first-party product incubator，但不是 RSS 源码树、Product Surface、official profile 或
production acceptance owner。双方职责固定为：

| 事实 | RSS | `rss-incubator` |
|---|---|---|
| Release Surface 选择、公开 API、SemVer 与 package metadata | 唯一 owner | 只消费 |
| 同 RSS revision 的 `.crate`、VCS revision、内容/checksum 与 publish closure | 唯一 owner | 验证输入 |
| RSS package 修复、yank 与 release approval | 唯一 owner | 报告影响并升级 |
| 下游 workspace、源码、根 `Cargo.lock` 与升级命令 | 不拥有 | 唯一 owner |
| 产品构建、candidate consumption、CI 与产品回退 | 不拥有 | 唯一 owner |
| incubator secret、依赖风险与产品安全响应 | 不拥有 | 唯一 owner |

incubator 的维护和安全渠道以该仓自己的 `MAINTAINERS.md` 与 `SECURITY.md` 为事实源，不由 RSS 文档复制。

### 单向依赖与版本边界

唯一允许的依赖方向是：

```text
rss-incubator -> immutable RSS Release Surface artifacts
```

incubator 只能消费已发布 artifact，或带精确版本、checksum 和 VCS revision 的不可变 candidate artifact。禁止相邻
checkout、path/git/workspace dependency、submodule、vendored RSS source，以及消费 RSS internal crate、generated
internals、provider catalog、RuntimePlan 或测试/治理实现。incubator 的 candidate proof 不授予 package maturity、
RSS release correctness、RC 或 publish approval。

### Cutover 顺序与 first-green

切换复用现有 PBI DAG，不建立新的迁移状态机或 registry：

1. #2094 在原外仓建立 Edition 2024 virtual workspace、唯一根 lock 和仓级 owner；RSS legacy gitlink 继续作为过渡载体。
2. #2095 建立 incubator-owned CI 与只修改临时 checkout 的 candidate proof。
3. first-green 后由 #2096 原子删除 RSS 的 `.gitmodules`、gitlink、外仓 checkout/upgrade/lock/metadata proof、CI 初始化和
   对应旧 guard，同时保留 RSS 自有的 Release Surface `.crate` proof。
4. cutover 后，RSS package proof 与 incubator product-consumption proof 各自只有一个 canonical owner，不保留 alias、
   shim、双写、双读或并行 proof 路径。

first-green 必须从 RSS Release Surface 动态派生 artifact exact-set，并在同一次可追溯结果中绑定：RSS commit、
incubator commit、每个 package 的精确版本、checksum 与 archive VCS revision、独立根 lock、registry-only resolution，
以及 locked/offline check、test、clippy 的成功结果和 canonical CI URL。RSS 自有 artifact proof 必须先绿；结果只链接到
现有 issue/PR，不写入 committed receipt、evidence database 或第二套 release registry。

Candidate-first consumer fixture 源码只归 `rss-incubator`；RSS 不保存旧 issue 路径
`fixtures/external-conformance-consumer/`。fixture 可作为非 workspace 模板提交，由 candidate proof 仅在 committed-HEAD
临时快照中物化并生成候选 lock，因而普通 CI 与 committed root lock 不解析尚未发布的 package。

### 失败与回退

- first-green 前继续保留现有 RSS legacy carrier；incubator 准备失败不得通过放宽 RSS artifact proof、加入 path dependency
  或复制源码绕过。
- #2096 的实现或验证失败时不合并 cutover；不存在部分删除或双 owner 的中间完成态。
- cutover 后不恢复 RSS-owned submodule。后续失败只能阻断产品发布、将 incubator pin 回上一已知绿色 artifact、由 RSS
  发布修复版本，或由 RSS owner yank 缺陷版本。仓库拓扑回退不能替代 artifact 修复/yank。

### 产品毕业与明确非目标

incubator candidate 毕业为独立产品仓必须另立 scope/ADR/PBI，并闭合产品身份、capability owner、维护与安全响应、
SemVer、release、upgrade、数据迁移、运营和回退责任；只能消费稳定 RSS Release Surface，不得依赖 RSS internal 或 T3
carrier。所需 capability-specific extension contract 必须按 ADR-024 独立接纳。

本决策不迁移 `assemblies/identityaudit`、`assemblies/settingsonly`、任何 domain 或 contract；不激活 MDM、ZT、
`device-security`、tenant/org lifecycle 或新的 official profile；不新增产品 crate、assembly、provider、通用 SPI、T3、
Evidence ID、selector、fixture、image、closeout carrier、跨仓 required-status handshake 或发布控制面。

## AI-HARD Carrier Map

本 ADR 描述 owner 与迁移顺序，不把 Markdown 声明为 enforcement，也不声明无载体的 `INVARIANT`。

| 风险 | Canonical carrier | 强度与交付 |
|---|---|---|
| RSS artifact correctness 漂移 | Release Surface、Cargo metadata、现有 `package-proof` | Cargo graph Hard + package proof Medium；RSS 已有 |
| incubator 重新成为 RSS 子目录或共享 lock | 独立 repository、virtual workspace、唯一根 `Cargo.lock` | 物理/Cargo 边界；#2094 |
| path/git/workspace 或 RSS internal 依赖 | Cargo resolution、forbidden-source/exact-set proof、真实 candidate CI | Medium T2；#2095 |
| RSS 继续拥有外仓源码拓扑 | 删除 gitlink、checkout/upgrade 实现和 submodule CI，替换旧 standalone proof/既有 workflow guard | Medium；#2096 |

#2096 必须删除或替换旧 carrier，不为该迁移新增 Markdown scanner、平行通用 gate 或永久 source-shape inventory。

## Four-principle check

- **Thorough**：repository、双方 owner、artifact/version seam、first-green、cutover、失败处置和毕业条件形成完整闭环；
  standalone proof 迁移与 Reference Extension 源码迁出明确分离。
- **Breaking**：cutover 后旧 URL、submodule、gitlink、alias、shim、双 owner 和拓扑回退全部退出；没有兼容窗口或双路径。
- **Simple**：一个迁移 ADR、现有 PBI DAG 和既有 proof/CI 载体完成切换，不增加状态机、registry 或控制面。
- **AI-HARD**：永久约束落到 Cargo/物理仓边界和确定性 proof；文档只记录决策与 carrier handoff。

## Consequences

RSS 的 Release Surface 与 `.crate` correctness 保持不变；跨包联合 product-consumption correctness 在 first-green 后归
incubator。ADR-024 中 `identityaudit`/`settingsonly` 的迁出前置仍未满足，其 assembly、domain、contract 和既有 T3
迁移基线不因本决策改变。
