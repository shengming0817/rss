# ADR-020：持久凭据安全事件协议与原子撤销漏斗

- **状态**：Accepted
- **日期**：2026-07-21
- **关联**：issue #1841 / #1840；承接 ADR-018 / ADR-019；#1840 完成生产激活
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

identity 的账户级和 grant 级命令分别封闭私有字段；生产 logout 再由不可互换的
`LogoutCurrentCommand` / `LogoutAllCommand` 包装。构造命令时固定完整 expected snapshot 与 closed target；
执行只接受对应 generated route receipt 和精确 command，冲突要求调用方读取新状态并重建命令，
不能把旧命令重放成成功。memory 与 PostgreSQL provider 都必须比较完整 expected snapshot，不能把 stale command
改写为终态幂等成功。

### 唯一事务漏斗与锁序

不新增 identity 专用事务入口。现有 PostgreSQL `producer_tx` 接受 crate-private sealed
`ProducerFactAuthorization`；生产 credential-security authorization 只能来自对应 mounted route receipt，
fact/entry 由 route-specific command 内部事件派生，不接受调用方独立替换。
不存在零参数 mint、无 receipt 的生产入口或 sibling-module 固定 fact token。authorization 进入同一个 projection + OutboxFact
提交漏斗，canonical append 仍不可从漏斗外调用。

安全事件事务固定锁序为 `account-security → refresh-family → auth-grant`。未来把 credential material 更新合入
同一事务时，只能向前扩为 `credential → account-security → refresh-family → auth-grant`。账户状态/epoch、
refresh family、AuthGrant 和 OutboxFact 必须全成或全败。

成功 receipt 只能在数据库确认 commit 后铸造。CAS 冲突返回冲突；commit result unknown 返回错误且不返回
receipt、不自动重试。#1841 不新增 dedup ledger：线性命令、expected snapshot 与不可伪造 receipt 是本协议的重放
边界。0069/0070 继续承载账户、grant、refresh 与 outbox。0071 曾新增 opaque target mapping，但生产 consumer
从未读取它；0076 删除该无界数据集及全部写入、解析和公开能力。opaque ref 只作为脱敏事件 correlation，不是
可逆目录。

### Active wire 与生产闭环

`identity.security-event@v1` 已由 #1840 提升为 `active`，只含 `kind`、`target`、`tenantId`、`occurredAt` 四个必填
字段，`additionalProperties=false`。kind 为上述九个闭值；target 是唯一 tagged object，kind 只有
`subject | grant`，ref 是随机 opaque UUID。payload 与 transport metadata 不出现 raw subject、grant/session、
sid/jti、token、password/credential material、email/username 或其他 PII。tenant、target kind、opaque ref 与
并由同一 sealed command/fact 数据流派生。不存在把 opaque ref 还原为 subject/grant 的生产 port 或数据库表。

`audit.security-event` 以 transactional-only adapter-native consumer 激活；current/all route receipt、生产
producer、幂等 audit append、runtime dispatch 与 L2 assurance 已形成闭环。audit 域只从四字段 wire 消费式
构造私有字段的 sealed command：`logoutCurrent + grant` 与 `logoutAll + subject` 是仅有的合法组合，随机 opaque
target ref 同时作为本事件的脱敏 actor/resource correlation。consumer 不读取 identity-owned target mapping，也不把
opaque ref 还原为 raw subject/grant。激活不增加兼容 shim 或双写。

## 失败语义与安全模型

- projection、grant/family 与 OutboxFact 任一步失败都回滚；不得返回成功 receipt。
- stale expected snapshot 不能部分更新、补写 outbox 或静默 no-op。
- active fact 只携带随机 opaque ref，不携带 raw 用户/会话标识或凭据材料；audit 直接消费脱敏 fact，生产代码
  不提供 reverse-resolution side channel。
- production 挂载由 runtime E2E、PostgreSQL 故障注入与 L2 assurance 共同证明。

## AI-HARD 载体

| 不变式 | 载体 | 评级 |
|---|---|---|
| kind、closed target 与可执行 transition 不能分离或由调用方覆盖 | 封闭层级 enum + 私有派生 API | Hard |
| 外部不能伪造 command、producer authorization 或成功 receipt | 私有字段 + move-only token + sealed trait/constructor | Hard |
| 安全事件不能建立第二事务/append 漏斗 | 唯一 `producer_tx` + crate-private `TxCapability` | Hard |
| wire 只有四字段、九 kind、typed opaque target 且拒绝未知字段 | JSON Schema + codegen `deny_unknown_fields` | Hard |
| opaque target 不可逆解析 | 无 resolver port、无 mapping relation、无 raw id wire 字段 | Hard + 数据库 Hard |
| audit consumer 不能旁路 contract 还原 identity target 或替换 fact 字段 | audit-owned sealed command + runtime-baseline forbidden-side-channel gate | Hard + Medium |
| active topology 不得缺 producer/subscriber/runtime 闭环 | codegen registry + L2 assurance | Hard + Medium |
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
- PostgreSQL 实现沿用仓库 `PgIdentitySecurityLifecycle` 的 SQLx transaction funnel；事务语义参考 [sqlx-core transaction.rs](https://github.com/launchbadge/sqlx/blob/main/sqlx-core/src/transaction.rs)，不建立第二套 logout transaction API。
