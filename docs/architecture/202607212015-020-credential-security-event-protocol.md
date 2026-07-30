# ADR-020：持久凭据安全事件协议与原子撤销漏斗

- **状态**：Accepted
- **日期**：2026-07-21
- **关联**：issue #1841 / #1840 / #1842；承接 ADR-018 / ADR-019；#1842 完成 password/account 生产接线
- **对标**：Ory Fosite refresh rotation、Keycloak user-session management

> **ADR-021 ownership amendment（#1835）**：`CredentialSecurityEventKind` 及其 Account/Grant 子枚举与
> AuthGrant 一起下沉 `authn`，identity 直接消费该 exact type。本文的 sealed command、事件 target、
> authorization/receipt、`producer_tx` 与 active wire 所有权仍在 identity；不增加 alias、translation
> enum 或第二套 close reason。

## 背景

账户状态、密码操作、logout 与 refresh reuse 都会使既有认证授权失效。若每个入口各自选择 target、关闭原因和
事务顺序，AI 后续实现很容易遗漏 epoch、只撤销 refresh 或先写 outbox，形成多个安全真源。另一方面，只有 wire
schema 而没有生产 producer、subscriber、审计和运行时证据时，不能把契约标为 active。

本决策建立唯一的内部事件分类和共事务能力；#1841 冻结协议，#1840 完成 active fact 的生产闭环。

## 决策

### 唯一封闭模型

`authn::CredentialSecurityEventKind` 是凭据安全事件的唯一闭合分类，层级固定为：

- `Account(AccountSecurityEventKind)`：PasswordChanged、PasswordReset、AccountLocked、
  AccountSuspended、AccountDeactivated、LogoutAll、CredentialDeleted；
- `Grant(GrantSecurityEventKind)`：LogoutCurrent、RefreshReuseDetected。

不保留 `AuthGrantCloseReason` alias、兼容构造器或第二套事件 enum。可执行 transition 只由 variant 派生：账户级
事件持有 `Subject` target，递增 account-security epoch/version 并撤销该 subject 的全部活动 grant/family；grant
级事件持有 `Grant` target、不改变 epoch，LogoutCurrent 进入 Revoked，RefreshReuseDetected 进入 Compromised。
Compromised 优先级最高，允许 Revoked 提升为 Compromised，禁止降级。公开的描述性 policy/scope API 已删除，
避免声明策略与真实 mutation 平行漂移。

identity 的账户级和 grant 级命令分别封闭私有字段；生产入口使用不可互换的
`PasswordChangeCommand`、`AccountStatusSetCommand`、`LogoutCurrentCommand`、`LogoutAllCommand` 与
`RefreshExecutionCommand`。refresh command 只有由 Active record 派生的 Rotate 和由已存在 non-Active record
派生的 ContainReuse 两个密封分支。
构造命令时固定完整 expected snapshot 与 closed target；执行只接受对应 generated route receipt 和精确 command，
冲突要求调用方读取新状态并重建命令，不能把旧命令重放成成功。domain command 与 PostgreSQL provider 都必须
保留完整 expected snapshot，不能把 stale command 改写为终态幂等成功。

`ReactivateAccountCommand` 只表达 Suspended/Locked→Active，不携带 event，也不接受 producer receipt。恢复保留
已经递增的 epoch，仅更新账户 snapshot；此前被撤销或标记 Compromised 的 grant/family 保持终态，不能随账户
恢复而复活。Deactivated 不可恢复。

### 唯一事务漏斗与锁序

PostgreSQL 对 identity 暴露唯一的 concern-specific `identity_producer_tx`；它委托私有内核
`producer_tx`，后者接受 crate-private sealed
`ProducerFactAuthorization`；生产 credential-security authorization 只能来自对应 mounted route receipt，
fact/entry 由 route-specific command 内部事件派生，不接受调用方独立替换。
不存在零参数 mint、无 receipt 的事件生产入口或 sibling-module 固定 fact token。password-change、
account-status-set、logout-current、logout-all 与 refresh 各自由 mounted generated producer route 铸造精确 receipt；
receipt 只能授权 `identity.security-event` 的 exact fact/contract。authorization 进入同一个 projection +
OutboxFact 提交漏斗，canonical append 仍不可从漏斗外调用。reactivation 的无事件 CAS 不是 producer 入口。

因此 `identity.password-change` 与 `identity.account-status-set` 的 HTTP consistency 都是 L2
`OutboxFact`；password-change 不再生成 `LOCAL_TX` spec/observation，也不属于 active LocalTx inventory。两条路由
的数据库 settlement 由 plain producer transaction 的 closed outcome/告警承载，不能套 LocalTx runner 或遥测。

安全事件事务固定锁序为
`credential（仅 password）→ account-security → refresh-family → auth-grant → projection/outbox`。
credential material、账户状态/epoch、refresh family、AuthGrant 和 OutboxFact 必须全成或全败；不触及 credential
的命令从 account-security 开始，不能反向取得锁。PostgreSQL 的全部路径由一个
`PgIdentitySecurityLifecycle` 进入同一个 SQLx producer transaction funnel，不再由 `CredentialRepo` 或独立账户
lifecycle 提供第二写入口。

成功 receipt 只能在数据库确认 commit 后铸造。CAS 冲突返回冲突；commit result unknown 返回错误且不返回
receipt、不自动重试。#1841 不新增 dedup ledger：线性命令、expected snapshot 与不可伪造 receipt 是本协议的重放
边界。0069/0070 继续承载账户、grant、refresh 与 outbox。0071 曾新增 opaque target mapping，但生产 consumer
从未读取它；0076 删除该无界数据集及全部写入、解析和公开能力。opaque ref 只作为脱敏事件 correlation，不是
可逆目录。

### Active wire 与生产闭环

`identity.security-event@v1` 已由 #1840 提升为 `active`；actor/target 均携版本化 `keyId` 与独立密钥生成的
tenant/domain-separated HMAC-SHA256 opaque ref，`occurredAt` 只接受 epoch 后且可由 wire `int64` 表示的时间，
producer/consumer 对 epoch 前或范围溢出显式返回 typed error。事件其余必填字段为 `kind`、`tenantId`、`occurredAt`，
字段，`additionalProperties=false`。kind 为上述十个闭值；target 是唯一 tagged object，kind 只有
`subject | grant`，ref 是随机 opaque UUID。payload 与 transport metadata 不出现 raw subject、grant/session、
sid/jti、token、password/credential material、email/username 或其他 PII。tenant、target kind、opaque ref 与
并由同一 sealed command/fact 数据流派生。不存在把 opaque ref 还原为 subject/grant 的生产 port 或数据库表。

`audit.security-event` 以 transactional-only adapter-native consumer 激活；五个 mounted producer route、
幂等 audit append、runtime dispatch 与 L2 assurance 已形成闭环。audit 域只从四字段 wire
消费式构造私有字段的 sealed command，并精确接受十组合法 kind/target：八个 Account kind 只能配 `subject`，
`logoutCurrent` 与 `refreshReuseDetected` 只能配 `grant`；任何 mismatch 都 fail-closed。随机 opaque target ref
只作为本事件的脱敏 resource correlation。consumer 不读取 identity-owned target mapping，也不把 opaque ref
还原为 raw subject/grant。激活不增加兼容 shim 或双写。

## 失败语义与安全模型

- credential/account projection、grant/family 与 OutboxFact 任一步失败都回滚；不得返回成功 receipt。
- stale expected snapshot 不能部分更新、补写 outbox 或静默 no-op。
- active fact 只携带随机 opaque ref，不携带 raw 用户/会话标识或凭据材料；audit 直接消费脱敏 fact，生产代码
  不提供 reverse-resolution side channel。
- production 挂载由 runtime E2E、PostgreSQL 故障注入与 L2 assurance 共同证明。
- refresh 正常轮换使用 conditional producer 的 `NoMutation`，不追加安全事件；只有 reuse 状态转换 winner
  追加一条 `RefreshReuseDetected`。pending bearer 只能由 commit 后的
  `PersistedRefreshRotationReceipt` 释放。

## AI-HARD 载体

| 不变式 | 载体 | 评级 |
|---|---|---|
| kind、closed target 与可执行 transition 不能分离或由调用方覆盖 | 封闭层级 enum + 私有派生 API | Hard |
| 外部不能伪造 command、producer authorization 或成功 receipt | 私有字段 + move-only token + sealed trait/constructor | Hard |
| 安全事件不能建立第二事务/append 漏斗 | 唯一 `identity_producer_tx` + private core `producer_tx` + 非互换 `IdentityTx` capability | Hard |
| wire 只有四字段、十 kind、typed opaque target 且拒绝未知字段 | JSON Schema + codegen `deny_unknown_fields` | Hard |
| opaque target 不可逆解析 | 无 resolver port、无 mapping relation、无 raw id wire 字段 | Hard + 数据库 Hard |
| audit consumer 不能旁路 contract 还原 identity target 或替换 fact 字段 | audit-owned sealed command + runtime-baseline forbidden-side-channel gate | Hard + Medium |
| active topology 不得缺 producer/subscriber/runtime 闭环 | codegen registry + L2 assurance | Hard + Medium |
| password/status route 不能在无 exact producer receipt 时调用安全 writer | generated route marker + `ProducerAssuranceReceipt` 参数 + provider authorization | Hard |
| refresh 不能经 store rotate/revoke 或 grant close 形成第二写入口 | 纯 reader store + 唯一 `execute_refresh` + 删除旧 port | Hard |
| refresh bearer 不能在 commit ACK 前返回 | private pending secrets + persisted receipt typestate | Hard |
| reactivation 不得产生安全事件或复活 grant/family | 无 producer receipt 的窄 CAS command + 单调终态测试 | Hard + Medium |
| 合法跨文件 producer_tx 调用集合保持双向闭合 | 全 production AST exact-set guard + extra-file synthetic red/green | Medium |
| 共事务锁序、回滚、CAS 与 commit-unknown 语义 | PostgreSQL 并发/故障注入测试 | Medium |
| plain producer 的数据库锁等待有界且不重放 | 不可表达无界 Plain policy + PostgreSQL 持锁集成测试 | Hard + Medium |

本决策不建立 Soft-only 约束。Medium 守卫只承载跨文件拓扑或数据库动态语义，能够由类型系统封闭的约束均已
上移为 Hard。

## 被拒绝方案

- 保留 `AuthGrantCloseReason` 并新增平行 security-event enum：产生两个安全真源。
- 新增 `identity_security_tx`：复制事务漏斗并扩大可绕过面。
- 让调用方传 scope/policy 或独立 target kind：允许合法 kind 与错误撤销范围组合。
- 只发布 tenant + scope、不提供 typed target：consumer 只能过宽处理或 fail-closed no-op。
- 把 raw subject/grant id 直接写进 durable fact：扩大跨系统关联面，违反最小披露。
- 为 commit-unknown 自动重试或新增通用 ledger：线性命令没有稳定跨请求幂等 key，自动重放可能重复安全变更。
- 在 producer/subscriber/runtime assurance 缺失时将 fact 标为 active：制造虚假生产证据。

## 对标与实现参考

- Keycloak current-session 对标采用其 OIDC logout endpoint：`/realms/{realm-name}/protocol/openid-connect/logout`，语义为注销已认证用户；见 [Keycloak OIDC layers — Logout endpoint](https://www.keycloak.org/securing-apps/oidc-layers#_logout_endpoint)。
- Keycloak all-session 对标采用其 Admin REST user logout：`POST /admin/realms/{realm}/users/{user-id}/logout`，并区分 realm-wide `POST /admin/realms/{realm}/logout-all`；见 [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html#_post_adminrealmsrealmusersuser_idlogout)。RSS route 不复制 Keycloak 管理面授权模型，只对标 current/all 撤销范围。
- PostgreSQL 实现统一使用一个 `PgIdentitySecurityLifecycle` 的 SQLx transaction funnel；password change、account restriction 与 logout 不建立分离 transaction API。事务语义参考 [sqlx-core transaction.rs](https://github.com/launchbadge/sqlx/blob/main/sqlx-core/src/transaction.rs)。
