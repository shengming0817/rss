# Feature Specification: Release Surface 收敛

**Created**: 2026-08-08
**Status**: Accepted design baseline
**Owner issue**: #2041

## 背景

[`ADR-024`](../../architecture/202608012034-024-enterprise-framework-product-surface.md) 已定义 RSS 的产品面，
ADR-024 已定义公共消费边界，
cargo xtask contract breaking / cargo public-api 已区分 Release API 与仓内 Rust `pub`。当前缺口不是为每个
workspace package 追加产品声明，而是建立一个最小、正向且可派生的 Release Surface，使发布承诺只覆盖明确进入
发布闭包的 artifact 与 API。

## 目标

1. 定义正向显式 Release Surface：只有被发布集合选中的 package、profile artifact 与 API 才获得版本承诺；
   未被选中的 package 默认 internal，无需逐项声明。
2. 固化当前已接纳的两条通用公共窄腰：Plain Rust consumer 使用 Standalone Component waist，企业应用使用
   Platform Application waist。Official Integration、Internal Provider Contract 与 composition detail 位于窄腰之后；
   未来 capability-specific extension 仍须通过 ADR-024 规定的独立条件提升流程。
3. 分离 internal exported-symbol drift 与 Release API/SemVer 语义，并为后续 PBI 提供唯一依赖顺序和证明边界。

## 用户场景与独立验收

### US1 — 维护者可以回答本次发布了什么

发布集合只列实际发布项，并与 Cargo package/publish 事实及 assembly/profile metadata 校验。新增 internal package
不会要求维护者同步更新一份全 workspace 产品清单。

独立验收：未被发布集合选中的 package 保持 internal；缺失或冲突的已选发布事实由既有事实读取链 fail-closed。

### US2 — 两类消费者只看到各自窄腰

Plain Rust consumer 不依赖 Platform runtime；Platform application consumer 不接触 provider、执行引擎或装配所有权。

独立验收：两类 workspace 外 consumer 分别只能通过其发布 package 编译，internal import 负例失败。

### US3 — internal baseline 不再被误认为 SemVer 承诺

仓内 `pub`、`publish = false` 与 curated `cargo public-api` baseline 只表达内部可见性或敏感 seam 漂移审查。

独立验收：Release API baseline 仅从正向发布集合派生，且没有把 internal crate 自动提升为公开产品面。

## 功能需求

- **FR-001**：Release Surface 必须采用正向发布集合；未列 package 必须默认 internal。
- **FR-002**：发布集合必须与 Cargo manifest、assembly/profile metadata 和 ADR-024 校验或派生，不得复制全
  workspace inventory、当前数量或顺序。
- **FR-003**：Standalone Component waist 与 Platform Application waist 必须是当前已接纳的两类通用公共 Rust
  消费入口；真实独立 provider/consumer、owner、SemVer/支持责任、typed bridge 与 conformance 齐备后，仍可经独立
  scope/ADR/PBI 接纳 capability-specific extension contract。
- **FR-004**：`diport`、generated registry、`eventexec`/`runtimeexec` ownership、provider catalog、
  `AssemblyLock`/`RuntimePlan` constructor 与 raw provider client 必须保持在 Release API 之外。
- **FR-005**：internal signature baseline 必须继续服务仓内敏感 seam 漂移审查，但不得授予 Release API、SemVer
  或外部支持承诺。
- **FR-006**：Release API compatibility、公共依赖和类型泄漏必须进入既有 release-check owner，不得新建第二
  runner、scanner、registry 或 evidence database。
- **FR-007**：Markdown 只承载设计与 traceability；后续 enforcement 必须落在 Cargo/visibility、typed facts、
  既有验证入口或真实外部 consumer。

## 非目标

- 不创建逐 package 产品面、发布状态或支持状态 metadata。
- 不在本规格 PR 中创建 release model、TOML/JSON schema、gate、crate、façade 或生成物。
- 不公开通用第三方 Provider SPI、动态插件、provider registry、service locator 或 marketplace。
- 不修改 official profile 状态，不新增 T3 owner、carrier、selector 或 production artifact。
- 不为废弃草案建立目录别名、双写或兼容读取路径。

## 成功标准

- **SC-001**：文档对未选 package 的唯一结论是默认 internal，而不是逐包登记。
- **SC-002**：两条公共窄腰、Release API 与 internal baseline 的边界均可映射到唯一后续 PBI。
- **SC-003**：所有禁止泄漏的 internal 类型类别均有后续 Hard/Medium 证明 owner。
- **SC-004**：本规格不包含 schema、实时 package/profile 数量或并行事实源。
- **SC-005**：#2042、#2044、#2045、#2047、#2048 的依赖与交付结果完整可追踪。
