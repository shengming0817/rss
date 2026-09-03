# ADR-026：rss-incubator Ownership 与 External Consumer Cutover

- **Status**：Accepted
- **Date**：2026-08-11
- **Last updated**：2026-08-24
- **Tracking**：#2093、#2153

## Context

RSS 当前通过 `.gitmodules`、`consumers/standalone` gitlink、固定外仓 URL，以及 `package-proof` 对外仓
workspace、lock、metadata 和升级命令的校验，拥有 standalone external consumer 的源码拓扑。这曾为首批
Standalone Component 建立真实跨包消费证据，但也把下游产品 workspace 的构建与安全责任反向纳入 RSS。

[`project-scope`](../rules/project-scope.md) 已将 Reference Extension 定位为外部 consumer，并要求迁出时通过
独立迁移决策记录目标仓、版本边界、consumer build、release ownership 和回退方式。
本 ADR 接纳该外部孵化仓边界以及 standalone consumer proof 的切换契约；它不授权迁移现有 Reference Extension
assembly、domain 或 contract。

## Decision

### 2026-08-24 amendment：Cargo-native consumption 与 producer proof 边界

Foundation first-green 采用 breaking cutover：彻底退役 incubator 的 Python candidate proof、动态 workspace/manifest/lock
改写和临时 fixture materialization，不保留 CLI、schema-v1、shim、alias 或 fallback。所有真实 consumer、conformance fixture
和 journey 永久属于同一 Cargo workspace，并且只使用一个 committed 根 `Cargo.lock`；candidate proof job 必须显式执行完整
`--workspace`，不能用 `default-members` 缩小 receipt 覆盖面。

RSS producer 是 `.crate` 包格式、index entry、archive checksum、`.cargo_vcs_info.json` 和 bundle exact-set 的唯一解析与证明
owner。incubator 不打开 `.crate`、不重算 archive checksum、不解释 index entry，也不读取 archive VCS metadata；它只绑定
immutable producer revision/run/attempt、artifact name/digest 和 producer 的 `candidate-bundle.json` 公共契约，再由 Cargo
source replacement、唯一根 lock 与 resolved metadata 证明实际消费。producer 与 consumer 因而保持不同 owner，同时不重复
解析 package format。

canonical consumer job 在 runner 临时 `CARGO_HOME` 中把 logical candidate registry 映射到下载的 producer registry，先
`cargo fetch --locked`，再 offline 执行 workspace fmt/check/test/doc/clippy、coverage、release build 和 journey。resolved graph
中的非 workspace `rss-*` package 必须全部且仅来自该 candidate registry，name/version exact-set 必须与 producer manifest
一致；path/git/workspace/internal RSS source、artifact identity 漂移或根 lock 改写均 fail closed。

全部门禁通过后只生成一次 breaking `schemaVersion: 2` receipt，绑定 producer/consumer canonical run URL、revision、artifact
identity、producer package proof、Cargo 实际 consumed exact-set、根 lock hash、locked/offline matrix 与 release binary hash。
receipt 只写 GitHub job summary并由 issue/PR 链接，不提交、不上传，也不建立第二 registry 或 evidence store。

### 2026-08-20 amendment：Foundation / Eventing external-consumer handoff

`rss-incubator` 可在既有单向 artifact 边界内扩展为 Foundation 增量 API 与 planned `rss-eventing` 的真实 workspace
外 consumer。RSS 继续唯一拥有 Release Surface 选择、公开 API、SemVer、`.crate` 内容/checksum/VCS revision 与
package proof；incubator 只拥有自己的 workspace、根 lock、consumer source、真实 broker fixture、产品 CI、升级和
回退。Foundation/Eventing candidate 必须以精确版本、checksum 与 VCS revision 作为不可变输入，禁止 path/git/workspace
dependency、相邻 checkout、submodule、vendored RSS source 或任何 RSS internal/test/governance crate。

Foundation first-green 直接从唯一 owner package path 使用新增值并覆盖拒绝路径。Eventing first-green 使用
consumer-owned 真实 broker fixture完成 authoring → publish → consume/reject → restart；它只证明 package API 与真实外部
T2 consumption，不拥有 RSS profile configuration、designated/canonical artifact、activation 或 T3。两者复用本 ADR
既有 receipt shape：同一结果绑定 RSS commit、incubator commit、artifact exact-set、每包版本/checksum/archive VCS
revision、独立根 lock、registry-only resolution、locked/offline check/test/clippy 与 canonical CI URL。receipt 只链接到
issue/PR，不写入 committed registry、artifact catalog、generated inventory 或 evidence database。

`rss-test-eventing` official driver 继续是 #1992 的条件提升项，不随 `rss-eventing` package 或 external first-green
默认发布。只有真实 workspace 外 consumer 已在候选 API 上用独立 broker fixture 通过、consumer owner 明确请求 driver，
并接受 provider/version/MSRV 与 identity/fencing/budget/ambiguity 支持矩阵时，才能由独立交付提供最小 driver；driver
不得拥有 broker 管理面、通用测试平台、CI scheduler 或 T3 registry，也不是 Eventing release closeout 的默认 blocker。

candidate 或 consumer CI 失败时不放宽 RSS artifact proof，也不加入 source/path fallback。已有 package 的增量升级失败时，
incubator pin 回上一已知绿色 immutable version 并重跑 canonical CI，RSS 再发布修复版本或按既有 owner 流程 yank；
新 package 首次 candidate 失败时，直接拒绝 candidate 并保持先前不含该 package 的 consumer lock/dependency exact-set。
两种路径都不得恢复 RSS-owned fixture、submodule、双 receipt owner 或并行 registry。

### Repository 与 owner

现有 `shengming0817/rss-standalone-consumer` 原地重命名为唯一 canonical repository
[`shengming0817/rss-incubator`](https://github.com/shengming0817/rss-incubator)，保留 Git 历史。托管平台可能提供的旧 URL
redirect 不是兼容承诺、canonical 坐标或失败 fallback；最终状态不保留 RSS 对旧 URL 的引用。

`rss-incubator` 是 RSS 的 first-party product incubator，但不是 RSS 源码树、Product Surface、official profile 或
production acceptance owner。双方职责固定为：

| 事实 | RSS | `rss-incubator` |
|---|---|---|
| Release Surface 选择、公开 API、SemVer 与 package metadata | 唯一 owner | 只消费 |
| 同 RSS revision 的 `.crate`、VCS revision、内容/checksum 与 publish closure | 唯一 owner | 绑定 producer proof，不重复解析包格式 |
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
2. #2095 曾建立 incubator-owned CI 与只修改临时 checkout 的 candidate proof；该历史载体已由 #2153
   breaking cutover 原子替换为永久 Cargo workspace、唯一 committed 根 lock 与 runner-temporary registry transport。
3. first-green 后由 #2096 原子删除 RSS 的 `.gitmodules`、gitlink、外仓 checkout/upgrade/lock/metadata proof、CI 初始化和
   对应旧 guard，同时保留 RSS 自有的 Release Surface `.crate` proof。
4. cutover 后，RSS package proof 与 incubator product-consumption proof 各自只有一个 canonical owner，不保留 alias、
   shim、双写、双读或并行 proof 路径。

first-green 必须从 RSS Release Surface 动态派生 artifact exact-set，并在同一次可追溯结果中绑定：RSS commit、
incubator commit、每个 package 的精确版本、checksum 与 archive VCS revision、独立根 lock、registry-only resolution，
以及 locked/offline check、test、clippy 的成功结果和 canonical CI URL。RSS 自有 artifact proof 必须先绿；结果只链接到
现有 issue/PR，不写入 committed receipt、evidence database 或第二套 release registry。

Candidate-first consumer fixture 源码只归 `rss-incubator`；RSS 不保存旧 issue 路径
`fixtures/external-conformance-consumer/`。fixture 是永久 Cargo workspace member，和所有 candidate consumer 共用 committed
根 lock；普通本地开发可只运行不需要 candidate transport 的检查，但 canonical proof 必须覆盖完整 workspace。

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
| RSS artifact correctness 漂移 | Release Surface、Cargo metadata、现有 `package-proof` | Cargo graph Hard + package proof Medium；RSS 已有且唯一解析 package format |
| Foundation/Eventing candidate 冒充已发布公共面 | Release Surface selected/planned/executed exact-set、typed owner projection、package proof | Hard + Medium；#2152/#2162 |
| Foundation/Eventing 外部消费回到 path/source coupling | 单一 committed 根 lock、registry-only Cargo resolution、resolved exact-set、真实 consumer CI | Hard/Medium T2；#2153/#2163 |
| incubator 重新成为 RSS 子目录或共享 lock | 独立 repository、virtual workspace、唯一根 `Cargo.lock` | 物理/Cargo 边界；#2094 |
| path/git/workspace 或 RSS internal 依赖 | manifest registry source、Cargo resolved graph、producer manifest/consumed exact-set、真实 candidate CI | Hard/Medium T2；#2095/#2153 |
| RSS 继续拥有外仓源码拓扑 | 删除 gitlink、checkout/upgrade 实现和 submodule CI，替换旧 standalone proof/既有 workflow guard | Medium；#2096 |

#2096 必须删除或替换旧 carrier，不为该迁移新增 Markdown scanner、平行通用 gate 或永久 source-shape inventory。

## Four-principle check

- **Thorough**：repository、双方 owner、artifact/version seam、first-green、cutover、失败处置和毕业条件形成完整闭环；
  standalone proof 迁移、Foundation/Eventing consumption 与 Reference Extension 源码迁出明确分离。
- **Breaking**：cutover 后旧 URL、submodule、gitlink、alias、shim、双 owner 和拓扑回退全部退出；没有兼容窗口或双路径。
- **Simple**：一个迁移 ADR、现有 PBI DAG 和既有 proof/CI 载体完成切换，不增加状态机、registry 或控制面。
- **AI-HARD**：永久约束落到 Cargo/物理仓边界和确定性 proof；文档只记录决策与 carrier handoff。

## Consequences

RSS 的 Release Surface 与 `.crate` correctness 保持不变；跨包联合 product-consumption correctness 在 first-green 后归
incubator。ADR-024 中 `identityaudit`/`settingsonly` 的迁出前置仍未满足，其 assembly、domain、contract 和既有 T3
迁移基线不因本决策改变。Foundation/Eventing external first-green 只完成各自 T2 handoff，不激活 public package、
official profile、production artifact 或 T3；这些状态继续由 ADR-024 与各自 implementation/carrier PBI 原子切换。
