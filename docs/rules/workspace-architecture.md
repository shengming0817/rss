# Workspace 与分层规则

本文拥有稳定目录职责与 crate 依赖方向。精确 workspace member、package kind 和依赖边由 `Cargo.toml`、
Cargo metadata 与 `xtask/src/layers.rs` 派生；文档不复制可变清单。

## 根目录职责

- `crates/` 只放扁平库 crate；bounded context 是域 crate，feature 是域内模块。
- `adapters/` 实现上层 port；域与服务不得反向依赖 adapter。
- `contracts/` 是 wire 声明源，`generated/` 是确定性派生物；手写代码不得修改 generated 输出。
- `assemblies/`、`bins/` 与 `xtask/` 是组合根或工具入口，可依赖所需下层库，但不得成为领域事实 owner。
- 目录移动不改变依赖权限；权限只由 Cargo 图、visibility 与 typed policy 决定。

## 依赖方向

稳定层次为 Foundation → Engine → DI-infra → Service → Domain → Adapter/Composition。

- Foundation 只依赖更低位 Foundation、标准库和获准外部库；不得依赖运行时、服务、域或 adapter。
- Engine 依赖 Foundation；不得依赖服务、域或 adapter。
- DI-infra 只拥有 provider-agnostic port/value；不得拥有领域 service、repo 或业务实体。
- Service 依赖 Foundation、Engine 与 DI-infra；不得依赖 Domain 或 Adapter。
- Domain 可依赖下层能力与 generated contract；兄弟域互不依赖，跨域只经 contract。
- Adapter 可向内依赖其实现的 port/domain type；Domain 不得向外依赖 Adapter。
- Composition root 负责 provider 选择、构造、lifecycle 与 fail-fast，不把选择权下沉到域。

Cargo 拒绝环；`deny.toml` 与 `cargo xtask layer-deps` 拒绝非法边和未登记例外。

## Foundation 内部 DAG

Foundation 内部只允许 typed catalog 声明的前向边；独立 mint/capability crate 不因同层身份获得互依权限。
新增前向边必须有稳定语义 owner，反向边和未登记边 fail-closed。

`INVARIANT: BASE-INTRADAG-01`：Cargo/rustc 提供无环 Hard 证明，`layer-deps` 对 sanctioned 方向和
anti-vacuity 提供 Medium 证明。精确节点与边只在 typed catalog 维护。

## 可见性与公开面

- 域内类型默认 private 或 `pub(crate)`；跨 crate `pub` 只表示 Rust 可命名，不自动成为 Release API。
- 对外稳定面必须由发布 catalog、SemVer/breaking proof 与真实 consumer 共同接纳。
- private field、newtype、sealed trait、typestate 和必填构造器优先封闭不可伪造状态。
- provider impl 由 adapter/composition 拥有；port 定义位置按签名是否需要域类型决定。

## 失败语义与载体

- 未知 package kind、无法分类的内部边、空 inventory 或 catalog 漂移必须 fail-closed。
- Hard：Cargo graph、visibility、sealed/private types 与 production compilation。
- Medium：`layer-deps`、`cargo-deny`、public-api/consumer proof 及相关 synthetic-red/anti-vacuity。
