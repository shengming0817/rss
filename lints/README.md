# RSS 自写 dylint lint

RSS 治理三档载体里「残留真要 AST 级的少数 funnel」那一档（见 `docs/rules/architecture.md`
§Rust 原生强制 二档表）。clippy `disallowed-*` / `cargo-deny` / 类型系统表达不了的 AST 级约束，
落到这里的自写 [dylint](https://github.com/trailofbits/dylint) lint。

## 为什么是独立 workspace

lint crate 链接 `rustc_private`，须用 **nightly** 工具链（见 `rust-toolchain.toml`）。`lints/` 自成
一个嵌套 Cargo workspace（本目录 `Cargo.toml` 的 `[workspace]`）+ 根 `Cargo.toml` 的 `exclude = ["lints"]`，
与根 **stable 1.96** workspace 完全隔离——`cargo build/test/clippy --workspace`（根）不会编译这里、
不触碰 nightly。

**隔离的副作用**：根 `deny.toml`（`[sources] unknown-git = "deny"` 等）也**不扫描** `lints/` 子 workspace。
本子树唯一 git 依赖是 `clippy_utils`（rust-lang 官方 `rust-clippy` 仓库，`rev` 与 nightly channel 配对），经人工审核；
`lints/Cargo.lock` **刻意提交**（与根 workspace 策略一致，保证 nightly + clippy_utils rev 可复现，勿删）。
dylint 自写 lint 不走根 `[workspace.lints.clippy]`——与 clippy 是平行机制，只经 `cargo dylint` 触发。
新增 lint 引入新的 git/registry 依赖时须人工核查（因根 `deny.toml` 不覆盖本子 workspace）。

## 前置

```bash
cargo install cargo-dylint dylint-link
```

`channel`（`rust-toolchain.toml`）与各 lint crate 的 `clippy_utils` git `rev` **成对**绑定，升级须同步改两者
（勿单独动其一，否则 nightly 与 clippy_utils ABI 不齐、编译失败、排查难）。升级步骤：① 取目标 dylint
版本的 [releases](https://github.com/trailofbits/dylint/releases) → `internal/template/{rust-toolchain,Cargo.toml}`
拿配对的 channel + `clippy_utils` rev；② 同步改 `lints/rust-toolchain.toml` 与各 `lints/*/Cargo.toml`；
③ `cd lints && cargo test` 验证。

## 运行

```bash
# 仓库根：对整个 workspace 跑所有已注册 lint（注册在根 Cargo.toml [workspace.metadata.dylint]）
cargo dylint --all
cargo dylint list            # 列出已注册 lint

# 所有 lint 自测（对 lints/ 子 workspace 跑全部 UI 测试）
cd lints && cargo test --workspace

# 单个 lint 自测（UI 测试，自动取 lints/ 的 nightly）
cd lints/rss_domain_no_serialize && cargo test
```

> ✅ **已接入聚合门（#1023）**：`cargo dylint --all` 现是 `cargo xtask verify` / `make verify` 的一步，并经
> `DYLINT_RUSTFLAGS=-D warnings` 升为 **fail-closed**（默认 `Warn` 的注册 lint 违例即让 verify 非零退出）。
> 激活 forge=azure 无 CI ⇒ verify 是治理门的唯一实际 gate（提交前 / ship·fix 收尾跑）。
> **仍在 #1054**：覆盖面仍是 `domain` 模块命名约定（非完整域 crate 边界）——见下「强度现状」。

## 已落地 lint

当前注册清单（与根 `Cargo.toml [workspace.metadata.dylint]` 和 `lints/Cargo.toml` 同步）：
`rss_domain_no_serialize`、`rss_spawn_missing_scope`、`rss_crosstenant_callsite`、
`rss_dlq_operator_callsite`、`rss_diport_impl_allowlist`、`rss_principal_facet_impl_allowlist`、
`rss_authplan_callsite`、`rss_authenticated_callsite`、`rss_handler_local_principal_authz`、
`rss_diport_error_debug_redacted`、`rss_diport_dto_debug_redacted`、`rss_pdp_impl_adapter_only`、
`rss_projection_append_only`、`rss_partition_serial_allowlist`、`rss_diport_envelope_reserved_writer`、
`rss_redact_debug_required`。

| lint id | INVARIANT | 守的约束 |
|---------|-----------|---------|
| `rss_domain_no_serialize` | SERDE-DOMAIN-FREEZE-01 | domain 实体禁 derive serde `Serialize`/`Deserialize`（只有 contract/DTO/`generated` 可序列化到 wire）。默认 `Warn`。 |
| `rss_spawn_missing_scope` | SPAWN-CTX-REBIND-01 | `tokio::spawn`/`spawn_blocking` 子任务体内读 `runctx::try_with`/`try_current`，却未在外层 `runctx::scope(...)` 重绑 ctx（spawn footgun 静态防误用，ADR-002）。默认 `Warn`。仅 intraprocedural；`#[cfg(test)]` 子树因 `cargo dylint --all` 默认不带 `--all-targets` 不被扫（故 `runctx` 自测的 footgun 演示不报，也无 stable 构建 `unknown_lints` 之虞）。 |
| `rss_crosstenant_callsite` | TENANCY-CROSSTENANT-CAP-01 | vocab 跨租户 All-scope mint 三步仅 `audit::ports::CrossTenantReadScope::from_durable_append` 可调用；其 receipt 由 audit application 私有字段 Hard seal。默认 `Warn`。捕获直接 call / 函数项别名 / fn-pointer，按 caller crate + 精确 inherent impl type + method 放行；UI 以外部 caller 红、精确 method 绿、`audit` 同 crate 同名 free fn 红锁住分支。 |
| `rss_dlq_operator_callsite` | EVENTBUS-DLQ-OPERATOR-CAP-01 | `eventexec` operator capability 的 `issue_for_authorized_operator()` 仅 admin/PDP 边界 crate（当前 `httpserve`）可直接调用；runtime CLI 只能经精确 `issue_authorized_dlq_capability` / `issue_authorized_reconcile_capability` wrapper 签发（DLQ mutation 与 reconcile recovery capability callsite-allowlist；上游私有字段为 Hard，本 lint 守下游「谁可调」为 Medium）。默认 `Warn`。捕获直接 call 与函数项别名；`#[cfg(test)]` 子树默认不扫，测试 fixtures 可直接 mint。 |
| `rss_diport_impl_allowlist` | DIPORT-IMPL-ALLOWLIST-01 | `diport` DI port trait（`Signer`/`Publisher`/`ManagedResource`… + 基 trait `*Local` + `Clock`/`SubscribeInitializer`）仅 adapter / 组合根可 impl（impl-site allowlist；funnel 下游约束——上游 `deny.toml` wrapper 守「port 只在 diport 定义」DIPORT-MACRO-CONFINE-01 为 Medium，本 lint 守下游「谁可 impl」为 Medium，#1060 闭环 ADR-003 §4.2 方案 ② 缺口）。默认 `Warn`。trait 归属按**被 impl trait 的 crate 名 == `diport`**（覆盖全部 + 未来新增 port，无名单漂移）；impl 站点二选一放行（均键 **package 身份 / 位置**，非源文件路径）——① 被编译 crate 是 `diport` 自身（含 dynosaur/trait-variant 宏生成 bridge impl，按 `LOCAL_CRATE` 身份判，**同时关掉**域 crate 用宏展开 impl 的绕过面），② 被编译 package 的 `CARGO_MANIFEST_DIR` **父目录名** ∈ `adapters`/`bins`/`assemblies`（对齐 `xtask/src/layers.rs` 顶层成员，新 adapter 自动覆盖；`xtask` 故意不入）。键 package 位置而非源文件 ⇒ 域 crate 把 impl 放进 `crates/<domain>/src/adapters/` 子目录无法绕过。`#[cfg(test)]` 子树默认不扫（test mock impl 放行）。**路径 allowlist 绿分支无法在 UI harness 模拟**（harness 控制 example 源路径），其 anti-vacuity 由真 workspace `cargo dylint --all`（12 adapter 0 诊断）承载；UI 单 example target（`rss_diport_impl_allowlist_ui` 红 + 内嵌非 port trait / inherent / item-level `#[allow]` 绿子例）。 |
| `rss_principal_facet_impl_allowlist` | PRINCIPAL-FACET-IMPL-AUTHN-01 | `runctx::PrincipalFacet` 仅 `authn`（+ 定义 crate `runctx` 的 test facet）可 impl（impl-site caller-crate allowlist；`AppCtx` 生产**伪造门**——principal payload 是 `Arc<dyn PrincipalFacet>`，外部 crate impl 不了 facet 就造不出 `AppCtx`、无法伪造任意 tenant/principal 越权）。默认 `Warn`。跨 crate「只有 authn 能 impl」类型层不可表达（sealed-trait 跨 crate 不可行，ADR-003 §4.2 / ADR-002 §D5），dylint 为最强可用载体（Medium）。trait 归属按**被 impl trait 的 crate 名 == `runctx` 且 item 名 == `PrincipalFacet`**（runctx 还导出非-trait `RequestCtx`/`MissingCtx`，故按 crate+name 精确判）；impl 站点放行按 `LOCAL_CRATE` 名 ∈ {`runctx`, `authn`}（caller-crate allowlist，同 `rss_crosstenant_callsite` 范式）。`#[cfg(test)]` 子树默认不扫（test mock facet impl 放行）。UI 两个 example target（`rss_principal_facet_impl_allowlist_ui` 红 + 内嵌非 runctx trait / inherent / item-level `#[allow]` 绿子例 / `authn` 绿）；绿向 anti-vacuity 另由真 workspace `cargo dylint --all`（authn 真实 facet impl 0 诊断）双锁。 |
| `rss_authplan_callsite` | AUTH-PLAN-MINT-01 | `primitives::authplan::AuthPlan` 构造入口仅组合根可调用，listener 级认证计划不得在业务 crate 内散装 mint。默认 `Warn`。 |
| `rss_authenticated_callsite` | AUTH-EVIDENCE-MINT-01 | `httpserve::Authenticated` 与 audit subject 读取 funnel 仅组合根验签桥可构造/调用，防 handler 绕过认证边界。默认 `Warn`。 |
| `rss_handler_local_principal_authz` | HANDLER-LOCAL-PRINCIPAL-AUTHZ-01 | handler/domain 禁用 `Authenticated` getter 与非 allowlist 的 `PrincipalKind::{Admin,SuperAdmin,...}` / role-name 字面量授权分支；业务授权必须消费 route gate 插入的 `AuthorizedSubject` 并比较 typed `GrantPermission` / `RoutePermissionId`。默认 `Warn`。allowlist 仅覆盖 route gate、generated DTO enum parse/serde、authn funnel、runtime bridge、`ContractAuthorizer` 方法、PrincipalKind audit/event/wire mapper 和 audited audit target-tenant read。 |
| `rss_diport_error_debug_redacted` | DIPORT-ERR-RAWSOURCE-BAN-01 | 受守护 crate（`diport` / `bootstrap` / `eventexec`）error struct 禁持裸 `Box<dyn std::error::Error + Send + Sync + 'static>` source 字段；改用 `diport::RedactedSource` newtype（`Debug`/`Display` 恒 `<redacted>`，不展开内层，#1144）。默认 `Warn`。上游 Hard：`RedactedSource` 类型系统保证脱敏（DIPORT-ERR-SOURCE-REDACT-01）；本 lint 下游 Medium gate：守「受守护 error struct 确实采纳该 newtype」。守护范围限 `LOCAL_CRATE ∈ {diport, bootstrap, eventexec}`（其它 crate 合法持裸 Box 不误报）。`check_field_def` 逐字段检测语法形状 `Box<dyn Error...>`（`sym::Error` diagnostic item 识别 std::error::Error）；**消费侧**用 `RedactedSource` 字段（命名 ADT、非 trait-object）天然不命中；**canonical `diport::redacted::RedactedSource` 定义自身**（内层为裸 Box）按 `DefId` 路径结构性豁免，`bootstrap` / `eventexec` 中同名假类型仍触发。UI 四个 example target（`diport` 红含 canonical 豁免绿子例 / `bootstrap` 红含同名绕过红例 / `eventexec` 红含同名绕过红例 / `not_diport` 绿）分别证受守护 crate 激活、canonical 豁免与非激活。 |
| `rss_diport_dto_debug_redacted` | DIPORT-DTO-RAWBYTES-BAN-01 | `diport` DTO 字段禁裸字节缓冲（`Vec<u8>` / `[u8;N]` / `Box<[u8]>` / `Option` 包装），改用 `RedactedBytes` newtype。默认 `Warn`。 |
| `rss_pdp_impl_adapter_only` | PDP-IMPL-ADAPTER-ONLY-01 | `diport::Pdp` 验签端口仅 provider adapter 可 impl，组合根/域不得内联 always-allow PDP。默认 `Warn`。 |
| `rss_projection_append_only` | PROJECTION-APPEND-ONLY-01 | `projection_events` 表 append-only：不得对其 `DELETE` 或 `TRUNCATE`。默认 `Warn`。 |
| `rss_partition_serial_allowlist` | PARTITION-SERIAL-IMPL-ALLOWLIST-01 | `consistency::PartitionSerialDelivery` 仅 adapter / 组合根可 impl，守 projection serial witness 的 Medium 半段。默认 `Warn`。 |
| `rss_diport_envelope_reserved_writer` | DIPORT-ENVELOPE-WIRE-WRITER-01 | `EnvelopeMetadata::insert_wire_pair` reserved-capable wire 写面仅 adapter / 组合根可调用；业务写 metadata 走拒 reserved key 的普通入口。默认 `Warn`。 |
| `rss_redact_debug_required` | REDACT-DEBUG-REQUIRED-01 | issue #1359 高风险敏感 DTO（`AuditEvent` / `RoleBinding` / `Session` / `RequestCtx` / `SecretMaterial` 等）禁止裸 `derive(Debug)`；改用 `#[derive(secure::Redact)]` + 逐字段 `#[redact(...)]`。默认 `Warn`。 |

逃生门：确需豁免的 callsite（如确需序列化的非 DTO 类型、确需读裸 ctx 的 spawn），在该 item 上加
`#[allow(<lint_id>)] // reason: ...`（与仓库 item-level carve-out 纪律一致）。
每条 lint 的符号 / 红例 / 盲区单源在其 `src/lib.rs` rustdoc。新增 lint：复制
[dylint 模板](https://github.com/trailofbits/dylint/tree/master/internal/template) 到
`lints/<rss_xxx>/`，加进本目录 `Cargo.toml` members + 根 `[workspace.metadata.dylint] libraries`。
**ui example target 名取唯一 `<lint>_ui`**（非裸 `ui`）：多个 lint crate 同名 example 在 `cargo test --workspace`
会产生 artifact 路径碰撞（Cargo 警告、未来或升 hard error，见 rust-lang/cargo#6313）；`src/lib.rs` 的
`ui_test_example(env!("CARGO_PKG_NAME"), "<lint>_ui")` 第二参须同步，golden 仍随源文件名 `ui/main.stderr`。

> **例外（caller-crate-name lint 的绿例）**：若 lint 按 **caller crate 名** 判 allowlist（如
> `rss_crosstenant_callsite` 只准 `authn` 调），绿例须把 example target 名取作 allowlist 项本身（如 `authn`）
> ——UI fixture 编译为单一 example crate、其 crate 名 = target 名，故只有这样 `crate_name(LOCAL_CRATE)` 才命中
> allowlist 分支。此时 target 名**故意偏离** `<lint>_ui`；红例仍用 `<lint>_ui`。碰撞风险：不同 lint 的同名绿例
> target（如两个 lint 都用 `authn`）——届时按需在 target 名加 lint 前缀消歧。golden 随各源文件名（如 `ui/authn.stderr`，
> 无诊断时为**空文件**，须提交以锁定「期望零诊断」）。
