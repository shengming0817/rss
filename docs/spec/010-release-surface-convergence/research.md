# Research: Release Surface 当前事实与决策

## 权威来源

- [`ADR-024`](../../architecture/202608012034-024-enterprise-framework-product-surface.md) 拥有产品面、官方 profile
  候选/激活语义、Provider 三层边界与实施顺序。
- ADR-024 拥有 Evolve/Complete/Freeze/External、公共消费边界、验证深度和
  no-new-work closeout 规则。
- cargo xtask contract breaking / cargo public-api 拥有 Release API 与 internal Rust API、轴 A 与轴 B 的版本语义。
- Cargo manifests 拥有 package、依赖、版本、MSRV 与 publish 事实；assembly/profile manifests 拥有装配与 profile
  事实；`assemblies/artifacts.toml` 拥有当前 artifact 指针。
- PR 728 已确认 `diport` 是 `publish = false` 的 Internal Provider Contract，internal public-api baseline 不自动产生
  Release API 或 SemVer。

上述来源只通过链接和派生消费。本规格不复制产品面表、profile 状态表、package inventory 或当前数量。

## 被拒绝的源包设计

外部产品化源包曾把每个 workspace package 都纳入闭值产品分类，并为发布状态、支持状态和 profile membership
建立平行 metadata/schema。该方案会让“internal”也变成必须维护的显式登记，并与 Cargo、assembly/profile 和
ADR-024 形成多事实源，因此整体废弃，不提供兼容层。

同样拒绝以下做法：

- 以 internal crate 的 `pub`、签名快照或可实现 trait 推导外部兼容承诺；
- 让 package 或 provider 自行声明 maturity、conformance receipt 或自动注册资格；
- 用发布清单重建 provider catalog、assembly registry 或 profile inventory；
- 为 Markdown 标题、措辞或当前数量增加 CI scanner。

## 采用的模型

Release Surface 是正向选择，不是全仓分类：

```text
Cargo / assembly / profile facts
            +
explicit release selection
            |
            v
release artifacts + Release API owners
            |
            +-- Standalone Component waist --> Plain Rust consumer
            |
            `-- Platform Application waist --> Platform consumer

everything not selected --> internal
```

发布选择只能引用既有事实，并由后续 #2042 复用 workspacefacts/assembly governance 做一致性校验。它不是 package
registry、provider registry 或第二套 profile truth。

图中两条 waist 是当前已接纳的通用公共入口，不封死 ADR-024 的条件提升机制。未来 capability-specific extension
只有在真实独立 provider/consumer、owner、SemVer/支持责任、typed bridge 与最低充分 conformance 齐备后，才能经
独立 scope/ADR/PBI 进入 Release Surface；当前仍不发布通用 Provider SPI。

## AI-HARD 判定

| 风险 | 首选载体 | 强度/层级 |
|---|---|---|
| internal package 被误发布 | Cargo publish/package facts + release selection exact-set | Medium / T1 |
| internal 类型泄漏 | Cargo dependencies、visibility；release API/type leakage 检查 | Hard 优先，补充 Medium / T1 |
| API 漂移或破坏 | release-selected `cargo public-api`、`cargo-semver-checks` | Medium / T1 |
| workspace 内自测冒充外部可消费 | package tarball + workspace 外 consumer | Medium / T1/T2 接缝 |
| Provider SPI 被隐式公开 | `publish = false`、不进入 release selection、封闭 composition | Hard/Medium / T1 |

文档本身是 Soft 设计载体，不承担上述 enforcement。

## 兼容性结论

废弃的产品化草案没有外部 consumer 或已发布 artifact，因此不保留旧编号、metadata、schema、alias 或双读路径。
本规格不修改 active wire contract；轴 B 的 identity 与版本保留规则继续由 cargo xtask contract breaking / cargo public-api 独立拥有。
