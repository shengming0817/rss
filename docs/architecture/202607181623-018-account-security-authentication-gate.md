# ADR-018：持久账户安全状态与认证门控

- **状态**：Accepted
- **日期**：2026-07-18
- **关联**：issue #1833，AuthN hardening PR-06
- **对标**：Keycloak `services/src/main/java/org/keycloak/services/managers/DefaultBruteForceProtector.java`

## 背景

credential 上的失败窗口和 `locked_until` 是有 TTL 的暴力破解临时阻断；Active、Suspended、Locked、
Deactivated 是持久账户生命周期。把两者折叠为同一个 `AccountStatus::Locked` 会让 TTL 到期隐式解除管理员
锁定，也让登录先读 lockout、再认证的两次存储调用暴露 TOCTOU。refresh 若不读取当前账户状态，则已停用账户
仍可继续获得新 token。

本决策建立一个持久状态真源和一个原子认证漏斗。临时暴破阻断继续保存在 credential 记录中，但不再拥有账户
生命周期迁移能力。

## 决策

### 持久状态机

`AccountSecurityState` 以 `(tenant_id,user_id)` 唯一标识，包含闭值 `status`、`authn_epoch`、`version`、
`status_changed_at` 与 `updated_at`。新 credential 同事务创建 `Active / epoch=0 / version=1` 状态。

合法迁移固定为：

```text
Active ──→ Suspended ──→ Active
   │           └──────→ Deactivated
   ├────→ Locked ─────→ Active
   │           └──────→ Deactivated
   └──────────────────→ Deactivated
```

Deactivated 是终态；同态和图外迁移拒绝。每个成功迁移递增 version；进入 Suspended、Locked 或 Deactivated
递增 epoch；恢复 Active 保留 epoch。mutation 只能由 state 的合法 transition 产生，并携带完整 expected
snapshot；存储 CAS 必须同时匹配 tenant、user、status、epoch 和 version，不能把公开 hydration 得到的
伪造源状态当作 durable 真源。

`AccountSecurityLifecycle` 当前只保留为 identity 内部的 sealed persistence capability，不在 production
composition 中构造或挂载，也没有 HTTP、command 或 event 的跨边界 operation。因此本 PR 不为一个不存在的
管理入口伪造 `contract.toml` consistency 声明。统一安全事件撤销协议落地时，管理 operation、明确的
consistency level、真实 composition consumer 和权限边界必须在同一变更中加入。

持久化 CAS 必须消费 mutation 携带的完整 expected/next snapshots，以 tenant、user、expected status、
expected epoch 与 expected version 作为更新条件，并原子写入完整 next snapshot；不得由 adapter 根据局部字段
重新推导状态或只更新部分 snapshot。这个约束属于 repository 原子更新语义，不等于已经存在跨边界 lifecycle
operation。

`AccountLockout` 只产生 `AllowRetry` 或 `TemporarilyBlocked`。达到失败阈值和 TTL 到期都只更新
`failure_count/window_start/locked_until`，不会改变 durable status、epoch 或 version。

### 登录事务漏斗

`CredentialRepo::authenticate` 是唯一登录认证入口；独立 `lockout_status` port 被删除。PostgreSQL provider
在一个 tenant writer transaction 内使用固定锁序：

1. `SELECT ... FOR UPDATE` credential；
2. `SELECT ... FOR UPDATE` 对应 account-security；
3. 执行真实密码 KDF，未知 login 执行 dummy KDF；
4. 校验 durable Active 状态和 temporary lockout；
5. 仅 Active 且未临时阻断时处理密码成功 rehash/清零，或密码失败计数。

credential 存在但 security row 缺失、损坏或跨租时，在支付 KDF floor 后返回 storage failure，不补建、不按
Active 继续。非 Active 对外统一为 invalid credentials，且 token、session、outbox 均无副作用。in-memory
provider 以单个 inner lock 复现同一原子边界。

### Refresh pre-mint 门控

初始 User refresh 只接受 crate-private `ActiveAccountSecurity` receipt；receipt 只能从 Active state 铸造，
携带 tenant、canonical `UserId` 和当前 epoch。LoginService 在 mint 前经 `AccountSecurityReadRepo` 重读
状态，并要求 Active 且 tenant/user/epoch 与 receipt 一致。

rotation 从持久 refresh record 解析 canonical User，随后在 mint/CAS 前重读 Active 状态。Device、Admin、
SuperAdmin 或非法 subject 的旧记录拒绝；不存在裸 subject/tenant 的通用 initial issuance 入口。存储错误、
缺失状态和非 Active 状态均 fail-closed，并发生在 signer 与 rotation CAS 之前。

每个 refresh family 在根记录持久化 `authn_epoch_at_issue`，子记录只能从 sealed rotation 继承同一 epoch。
application 的 pre-mint 重读不仅要求 tenant/user/Active 匹配，还必须要求当前 epoch 等于 family issuance
epoch；因此 Suspend→Active 后旧 family 即使账号已恢复 Active 也不能继续轮换。

pre-mint read 不能关闭 read-to-CAS TOCTOU，所以 PostgreSQL `rotate` writer transaction 以账号安全行为最终
fence：先 `FOR UPDATE` 读取同 tenant/user 的 account-security row，要求 `status='active'` 且 epoch 等于
family issuance epoch，再执行 old refresh CAS 与 child INSERT。结果是 typed
`Applied | Replay | AccountStale`；AccountStale 不消费 old，也不插 child。0069 切换不猜测 legacy issuance
epoch：旧 binary 先通过正常流程撤销全部 active family，迁移锁内拒绝遗留 active 行、删除 consumed/revoked
历史行，然后一次性安装 non-null/nonnegative epoch 列。

## 后续 PR 边界

- **PR-07**：把 Session 升级为 AuthGrant，并持久化 session 的 `authn_epoch_at_issue`，将 family 绑定 session。
- **PR-08**：为 RSS access JWT 增加 `sid/jti/auth_time/authn_epoch`，并保留 verified grant facts。
- **PR-13**：把密码和账户状态变更接入统一安全事件事务，原子递增 epoch、撤销 grant/family 并写 outbox。
- **PR-14**：在 refresh rotation CAS 的同一事务中增加 session/grant fence，并闭合 reuse compromise。

本 PR 已通过 refresh record epoch 与最终 account writer fence 消除账号状态的 read-to-CAS TOCTOU；尚未把
epoch 写入 session/JWT，也不声称已有安全事件原子撤销或 session/grant final fence。

## AI-HARD 载体

| 不变式 | 载体 | 评级 |
|---|---|---|
| 非 Active 不能铸造认证 receipt | 私有字段 + crate-private Active conversion | Hard |
| 调用方不能构造非法 lifecycle mutation | 私有字段 + transition-only constructor | Hard |
| 登录不能拆成状态预检与认证两次调用 | 删除 `lockout_status`，仅保留 combined authenticate | Hard |
| refresh 不能缺少 security reader | 非 `Option` 构造器依赖 | Hard |
| 裸 subject/tenant 不能签 initial refresh | 非公开 initial funnel + typed Active receipt | Hard |
| refresh child 不能改写 family issuance epoch | 私有字段 + sealed rotation 继承 | Hard |
| credential/security 严格一对一与跨租隔离 | 双向 FK、CHECK、FORCE RLS、最小 GRANT | 数据库 Hard |
| final writer 必须在 refresh CAS 前锁内校验 Active + epoch | 单事务 SQL 锁序 + typed outcome + PostgreSQL 集成测试 | Medium |
| PostgreSQL 共事务和 credential→security 锁序 | 并发、故障注入、missing-row 反空测试 | Medium |
| production provider 与 refresh gate 确实接线 | composition anti-vacuity 与真实 PostgreSQL 测试 | Medium |

本决策不建立 Soft-only 约束。subject、epoch、password、token 不进入 Debug、错误正文或 metric label。
