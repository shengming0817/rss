# Research: identity 域 crate 对标与设计依据

> 对标入口 = `docs/references/framework-comparison.md`（单一事实源）。identity 涉及的「授权 PDP / ABAC」行：primary `casbin/casbin-rs`（RBAC/ABAC enforcer）· secondary `eclipse-biscuit/biscuit-rust`（能力令牌）；`osohq/oso` 已弃用，仅概念参考、勿读源码。

## 1. ABAC deny-overrides 语义（核心设计依据）

**对标**：`ref: casbin/casbin-rs src/effector.rs@fc425d4`（实拉源码 2026-04-25 master）。

casbin-rs 的 deny-override 落在 `DefaultEffectStream::push_effect`（`DefaultEffector` impl `Effector`）：`EffectKind { Allow=0, Indeterminate=1, Deny=2 }`；遇 `Allow` 置 `res=true` 但继续，遇 `Deny` 立即 `done=true; res=false` 终止——**单条 Deny 压过任意 Allow**。

**RSS 侧对应**（`identity::domain::evaluate_abac`，`domain/abac.rs`）：
- `PolicyRule.effect ∈ {Allow, Deny}`；遍历命中规则，任一命中 Deny → 整体 `Decision::Deny`（短路）；否则有命中 Allow → `Allow`；**无规则命中 → 默认 Deny**（比 casbin 更严的 fail-closed 缺省，对齐零信任）。
- 偏离：casbin 使用 matcher 表达式与函数表；RSS 不引入 DSL 或动态函数注册，而用 ADR-025
  的 closed typed family（equality/ordering/membership/string）和 family-specific operand。
  XACML/Casbin 只作为语义与扩展分类对标，不构成 wire/runtime 兼容承诺。
- 跨租 / 类型不匹配在 RSS 侧 fail-closed 判不命中（不 panic），casbin 无此租户语义——RSS 多租户硬约束（IDENTITY-AUTHZ-TENANT-01）。

## 2. RBAC 模型

**对标**：`ref: casbin/casbin-rs src/model/default_model.rs@fc425d4`（role-permission-subject 的 `g`/`p` 模型）。

RSS 侧 `authorize_rbac` 不用 casbin 的字符串策略矩阵，而是 typed `Role`/`Permission`/`RoleBinding` + `ResourcePattern` 匹配——同租户绑定 → 角色权限 → action+resource 匹配 → Allow，否则默认 Deny。偏离理由：RSS 域类型已冻结（#997），且 typed funnel 比字符串矩阵更安全（newtype 不可伪造、跨租编译期可表达）。

## 3. 密码哈希 / 凭据

**对标**：Rust 工业实践 `RustCrypto`（`argon2` / `password-hash` trait）+ 既有 `secure` crate 能力。

RSS 侧 `CredentialRepo::authenticate` 在单一 tenant writer transaction 中跑 argon2（或 bcrypt）KDF +
constant-time 比对，并返回 `AuthOutcome::{Authenticated, RejectedKnown, RejectedUnknown}`；密码明文永不存 /
不进日志 / Debug 脱敏 login 与 hash（`crates/observ`、`secure::redact_error` 与 typed metric enums）。底层哈希复用 `secure` crate（`secure::verify_password`），
不在 identity 重复封装。凭据 version pin 支持密码变更 CAS。登录查找键是 `LoginIdentifier`；canonical actor 是
`ids::UserId`——二者类型不相交（#1277）。

## 4. 账户锁定

业界标准锁定策略（OWASP ASVS / NIST 800-63B 节流方向）：失败计数阈值 + 滑动窗口 + 锁定 TTL + lazy-unlock（无需后台 job）。RSS 取阈值 5 / 窗口 15min / 锁定 TTL 15min（P1-12 缺口），与 session 同 L1 tx 原子。

## 5. 会话 / 登录编排

**对标**：`go-kratos/kratos`（中间件 / pipeline 范式，概念出处，非源码）+ RSS 既有 `crates/audit/src/`（域 crate handler/application/domain 分层 + 订阅范式，**RSS 内对标**）。

`LoginService` 沿用「`LoginIdentifier` → `authenticate` → `AuthOutcome` → `ids::UserId` → AuthGrant +
session-created outbox（L2）」骨架：payload.subject = UUID；envelope 经 `from_user_id`（#1235）。seed-login
仅 journeys/dev；生产二进制由 shipped-feature-guard 禁 `identity/seed-login`。真实 epoch / refresh / PDP
验签在 authn（#1003），identity 仅消费冻结签名。

## 6. 决议：本 feature 不引入的东西（避免越界 / 过度设计）

- **不引入** 策略表达式 DSL（casbin Polar）——用 typed operator 枚举。
- **不引入** `vocab::Decision` Obligations/FieldMask，除非 ABAC effect 表达确需——届时 PR2 最小扩展并 PR body 标注。
- **不实现** jwt/refresh/PDP/CredentialFence（authn #1003）、真实持久化（adapter）、EST/证书（deviceidentity）。
- **不新建** 共享 Rust 类型跨域——事件 payload 经 contract/generated。
