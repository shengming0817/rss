# Research: Platform Application waist 边界

## 权威来源

- [`ADR-024`](../../architecture/202608012034-024-enterprise-framework-product-surface.md) 拥有 Platform Public、Official
  Integration、Reference Extension、Internal Implementation 与 official profile 语义。
- [`project-scope.md`](../../rules/project-scope.md) 拥有公共消费、DI Port/Adapter、外部控制面和 T3 范围。
- [`api-versioning.md`](../../rules/api-versioning.md) 拥有 Release API 与 internal API 的版本边界。
- [`Spec 010`](../010-release-surface-convergence/research.md) 拥有正向 Release Surface、当前两条通用公共窄腰和
  internal baseline 决策，并保留 ADR-024 的 capability-specific extension 条件提升机制。

当前 `diport`、generated/runtime internals、provider catalog 与 composition detail 都没有外部 Release API 承诺。
official profile 的 candidate/active 也不能从 assembly 中的 production 字样或 artifact lifecycle 值推导。

## Waist 选择

Platform façade 应表达应用作者稳定意图，而不是镜像内部 crate 图：

| 应用意图 | Public capability | 保持 internal |
|---|---|---|
| 声明入口 | contract/handler authoring | generated registry、route mounting owner |
| 读取请求权威 | verified Principal/Tenant/Request view | verifier、credential、mint constructor |
| 注册应用模块 | ApplicationModule | provider catalog、assembly resolver |
| 选择受支持平台 | profile-typed builder | AssemblyLock/RuntimePlan constructor |
| 观察生命周期 | RuntimeHandle | worker/task ownership 与 shutdown internals |
| 诊断失败 | Conditions/Diagnostics 的闭值 code、vetted public detail、retryability | raw provider/config/credential、PII、原始错误文本/source chain 与 inventory internals |

表中能力已由 #2045 映射到
[`executable contract`](../../../xtask/tests/fixtures/platform_application_waist/src/lib.rs)；该文件是 exact symbol 与签名
单源。设计选择 façade-owned value/view、private field、profile typestate 和 consuming lifecycle，而不是镜像 internal
crate 图或为未来扩展预建 Provider/Profile trait。

`Contract` 是唯一开放 authoring trait。Rust 无法用 private seal 只允许另一个生成 crate 实现 trait，因此 selective sealing
会制造虚假 Hard 边界；正确边界是“开放声明、私有 admission”。外部 impl 可声明候选 contract，但无法取得 route、registry、
provider 或 runtime capability；#2049 再把声明与 canonical generated facts 精确 join。

## Consumer 选择

仓内 domain、assembly、example 和 Reference Extension 都与内部 workspace 同步演进，无法证明 package content、公共依赖、
独立 ownership 或升级边界。最低充分证明必须包含：

- 独立 repository 与 lockfile；
- 从实际 `.crate`/local registry 解析 façade；
- 最小 contract/handler/module 正向编译并 compile-use 每个承诺能力；
- 从公开 typed builder 启动有界 application seam、执行一次将 verified context 交给 handler 的 request，并通过
  `RuntimeHandle` 观察 diagnostics 后停止；
- internal import 与泄漏路径负例；
- N-1→N SemVer fixture seed。

consumer 使用 #2049 最终 revision 生成的 façade artifact；#2051 的共享 mechanics 不能替代该 same-revision proof。
它执行最低充分 T2 public seam，但不启动真实 provider、Reference Extension 或 production T3。测试输入不得经 public
API 暴露 verified identity/tenant 的 mint constructor，也不得引入 Provider SPI。

## AI-HARD 判定

| 风险 | 首选 owner | 载体 |
|---|---|---|
| façade 依赖 internal crate | Cargo graph、release dependency closure | Hard/Medium T1 |
| internal 类型经签名泄漏 | visibility/wrapper + public API/compile-negative | Hard 优先，补充 Medium T1 |
| 可信 identity/tenant 可伪造 | private/sealed constructor 与 typed verified context | Hard T1 |
| waist 只编译却不可运行 | final artifact 的 bounded startup/request/shutdown consumer | Medium T2 接缝 |
| diagnostics/error 泄漏敏感详情 | sealed public/internal detail funnel + negative external fixture | Hard/Medium T1 |
| 仓内 alias 冒充公共产品 | actual package + independent consumer | Medium T1/T2 接缝 |
| SemVer 漂移 | release-selected baseline + N-1→N fixture | Medium T1 |

### #2045 编译证明矩阵

| Invariant | 正向防空 | 负向载体 | 等级/替换 owner |
|---|---|---|---|
| PLATFORM-WAIST-AUTHORITY-01 | context accessors、plain TenantId 可读 | Principal/Tenant/Context 私字段；TenantId 无 authority conversion | Medium T1；#2049 private projection Hard |
| PLATFORM-WAIST-OWNERSHIP-01 | module/builder/handle 全路径可命名 | façade path 无 internal re-export、raw ownership 出口 | Medium T1；#2048 leakage gate |
| PLATFORM-WAIST-DIAGNOSTIC-01 | code/retryable/typed detail 可读 | snapshot/detail 私有 mint、无 raw From/source/subject | Medium T1；#2049 sealed funnel Hard |
| PLATFORM-WAIST-LIFECYCLE-01 | Core/Eventing build/start/shutdown 可编译 | marker/custom profile/Clone 被拒绝，重复 start/shutdown 为 moved value | Medium T1；#2049 typestate Hard |

fixture manifest 的 `publish = false` 与跨 normal/dev/build/target dependency kind 的空集合由 Cargo metadata exact-set
断言；每个 consumer 的 dependency set 也由 Cargo metadata 按 case 校验，正例只含 façade，serde 只属于 trait 负例。
源文件以 `deny(private_interfaces, private_bounds)` 拒绝 indirect signature leakage；负例使用 rustc JSON 的 error code +
primary source line exact-set，并将每条 expected diagnostic 绑定到该行的目标 symbol，禁止全局 stderr 词袋互相代偿。
UI inventory 从目录稳定派生，要求唯一 `positive.rs`、每个 `*_fail.rs` 恰有同名 `.stderr` 且没有孤儿或未知文件。
该证明不覆盖真实 dependency closure、`.crate` 内容、SemVer 或 T2，这些分别由 #2048/#2052 拥有。

### Gate budget admission

本轮只增加一个固定 selector：
`./hack/cargo.sh test -p xtask --test platform_application_waist_trybuild`。它在一个 target 内合并上述四个 invariant，
case inventory 由目录机器事实派生，不新增 release-check step、runtime runner、package consumer 或 T2/T3 carrier。

现有 `authn` trybuild Hard proof 只拥有生产 `VerifiedJwt`、`ServiceToken`、mTLS/grant 等 authority constructor；
`assembly-schema` private-field trybuild 只拥有 `AssemblyLock`/`RuntimePlan` 构造边界。两者均无法命名尚未落地的 Platform
façade exact signature、开放 authoring trait、profile typestate 或消费式生命周期。把这些设计期失效模式并入任一既有 owner，
会反向让生产 authority/assembly owner 依赖一个尚不存在的 façade，并制造错误的事实归属。因此本 gate 不替换既有证明；
“未实现 façade 的 exact API shape 是否自洽且禁止面关闭”是现有 owner 不可表达的独立失效模式，这是本轮只加不减的预算理由。

删除/合并条件是闭合的：#2048 先把 direct/re-export/generic/error/conversion leakage 接入既有 release-check owner；
#2049 接纳真实 façade 时必须在同一提交迁移 exact signatures，并删除本 harness、UI inventory、独立 fixture 及仅为调度登记的
xtask trybuild dev-dependency。真实 crate privacy、private construction 和 typestate 取代临时 Medium 设计载体，禁止双 owner 并存。
#2052 只增加 actual `.crate`、同 revision independent consumer 与有界 T2，不复刻本设计 runner。

Markdown 只记录能力和 owner，不扫描 Rust source 或充当兼容 gate。

## 兼容性与迁移

当前没有外部 Platform Rust consumer，因此 façade 建立时不为 internal crate path 保留 shim、alias 或兼容 re-export。
Reference Extension assembly 保持原位；其未来迁出仍需 ADR-024 规定的独立迁移决策、consumer baseline 和回退边界。
