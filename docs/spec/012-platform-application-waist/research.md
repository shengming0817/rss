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

表中名称是能力类别，不是 #2041 冻结的 Rust symbol。#2045 必须从当前类型和 consumer 场景推导精确签名，并优先
选择 wrapper/visibility，而不是为未来扩展预建 trait。

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

Markdown 只记录能力和 owner，不扫描 Rust source 或充当兼容 gate。

## 兼容性与迁移

当前没有外部 Platform Rust consumer，因此 façade 建立时不为 internal crate path 保留 shim、alias 或兼容 re-export。
Reference Extension assembly 保持原位；其未来迁出仍需 ADR-024 规定的独立迁移决策、consumer baseline 和回退边界。
