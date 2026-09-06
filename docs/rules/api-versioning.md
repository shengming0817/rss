# API 与 Contract 版本规则

本文拥有 Release API、wire breaking、deprecation 与 definition retention。精确 package/contract inventory 由 manifest、
release catalog、schema 与 Cargo facts 派生，文档不复制。

## 两个兼容轴

- 轴 A：Rust Release API/SemVer。
- 轴 B：wire/contract compatibility。只要 persisted、networked 或跨版本消费，schema/manifest identity 受保护。
- 组件持久化格式及必要升级定义由组件 owner 维护，适用本文件的兼容与退出规则；生产迁移执行由产品负责。
- 两轴正交：internal Rust breaking 不必升 wire version；wire breaking 不能靠 Rust SemVer 掩盖。
- internal `pub`、Markdown、同名 carrier 或历史发布不自动建立当前承诺。

## Rust Release API

- 首次发布前冻结已接纳的 major/minor 版本线，版本更新只修改 patch；改变版本线需要独立架构决策。该阶段的
  public API replacement 不要求兼容或 minor bump。
- 首次发布前的 intentional breaking replacement 若触发本地 SemVer gate，授权必须在 workspace metadata 中
  精确绑定 package、baseline commit 与 issue；gate 仅在当前 base 完全匹配时按 major diff 验证，base 漂移即
  自动恢复普通 SemVer 检查。禁止无 baseline、通配 package 或环境变量豁免。
- 首次发布后各 crate 独立遵循 SemVer：1.0 前的 breaking public API change 至少升级 minor，1.0 起升级 major。
- 删除或改签受保护 symbol 按 SemVer/breaking policy 处理；未接纳 internal package 可直接 breaking refactor。
- package rename、facade、re-export 或 shim 不得隐式延续旧 identity；replacement 原子切 consumer 并删旧路径。
- Foundation/common primitive 只能有一个 owner。提升时 canonical owner 新建 private-representation/closed-value
  public type，consumer 直接切换并删除重叠 internal generic type；不得保留 alias、deprecated re-export、
  `From`/`TryFrom`、feature flag、双路径或 convenience facade。
- public owner projection 以 typed rustdoc source identity 判定。来自另一 owner 的 `pub use` 是新兼容路径；未知
  owner 或类型泄漏均 fail-closed。首次发布后以已发布版本或 release tag 做 SemVer baseline。

## Wire breaking

- contract ID、kind、owner、route/topic、consistency/auth、request/response/event schema 与 stable error code 都参与 fingerprint。
- 删除 required field、收窄 accepted value、改变 protection/tenant/effect、删除 enum value、改变 `const`/`format`、
  resolved schema hash 或 semantic identity 默认 breaking。
- additive optional field 仅在旧 consumer 可忽略、新 producer 有确定 default/absence 语义时兼容。
- active breaking change 默认创建新 contract version 并保留旧 identity 至 deprecation 条件满足；禁止原地改写
  persisted wire。原地 no-compat 只接受绑定 base commit 与完整 deny findings 的精确 breaking authorization；
  contract/schema/base 漂移后必须重新授权，不接受 pre-GA、flag、环境变量、日期窗口或 lifecycle 降级代替。
- unknown diff/rule 默认 breaking，不能因 scanner 不认识而放行。

## Consistency/effect review

`INVARIANT: CONSISTENCY-EFFECT-BREAKING-REVIEW-01`：closed consistency/effect enums、穷举 mapping 与 deterministic
base/current fingerprint 是 canonical carrier；Git/base I/O 与 review gate 为 Medium，unknown default-deny。

review-only acknowledgement 与 intentional breaking authorization 正交：前者只确认 closed review finding，后者只
授权 fingerprint 精确列出的 deny；任一都不能扩展到未列变化。

## Deprecation 与删除

- deprecation 在 changelog 记录 owner、replacement、consumer set、最早删除条件与 migration evidence；1.0 起至少保留
  一个 minor release（安全或正确性风险除外），1.0 前删除仍需匹配 SemVer bump 与 migration notes。
- 删除前必须证明 active mounts/subscribers、persisted state、generated binding 与 external consumers 均已迁移。
- replacement first-green 后同一交付切 canonical pointer 并删除旧 target/schema/binding；不留 alias/shim/双读。
- 没有 successor 的退役需要产品承诺退出依据与 final no-residual proof。

## Saga/workflow definition

- non-terminal instance 固定 exact contract ID、definition version/fingerprint、schema digest 与 action registry generation；
  resume 不升级到 latest 或相似 schema。
- definition retention 至所有引用 instance terminal 且 retention/receipt 条件满足；registry 不提供无证明的 retire/remove。
- step/action schema、effect identity、compensation semantic 或 retry policy 变化使用新 definition version。

## URL/bootstrap

- public HTTP path 的 major version 是 wire identity；bootstrap/discovery 只返回明确 supported version。
- server 不做隐式 path rewrite、content negotiation fallback 或旧 version alias。
- generated router、contract registry 与 runtime mount 必须使用同一 version identity。
- bootstrap 是 auth/lifecycle 特性，不是无 domain 的顶级兼容命名空间；其 path 仍由 contract metadata/codegen 持有。

## Carrier

- Hard：schema/manifest、closed enums、generated binding 与 Cargo/visibility。
- Medium：breaking comparison、deprecation residual scan 与 migration integration。
