# ADR-020：持久凭据安全事件协议与原子撤销漏斗

- **状态**：Accepted
- **日期**：2026-07-21
- **关联**：issue #1841；承接 ADR-018 / ADR-019；生产激活依赖 #1842 / #1843
- **对标**：Ory Fosite refresh rotation、Keycloak user-session management

> **ADR-021 ownership amendment（#1835）**：`CredentialSecurityEventKind` 及其 Account/Grant 子枚举与
> AuthGrant 一起下沉 `authn`，identity 直接消费该 exact type。本文的 sealed command、事件 target、
> authorization/receipt、resolver、`producer_tx` 与 draft wire 所有权仍在 identity；不增加 alias、translation
> enum 或第二套 close reason。

## 背景

账户状态、密码操作、logout 与 refresh reuse 都会使既有认证授权失效。若每个入口各自选择 target、关闭原因和
事务顺序，AI 后续实现很容易遗漏 epoch、只撤销 refresh 或先写 outbox，形成多个安全真源。另一方面，只有 wire
schema 而没有生产 producer、subscriber、审计和运行时证据时，不能把契约标为 active。

本决策建立唯一的内部事件分类和共事务能力，并冻结一个严格 draft fact；不在 #1841 虚构生产闭环。

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

identity 的账户级和 grant 级命令分别封闭私有字段，再由 `CredentialSecurityCommand` 包装。构造命令时固定完整 expected
snapshot、closed target 与 move-only fact authorization；执行只接受 CAS，冲突要求调用方读取新状态并重建命令，
不能把旧命令重放成成功。memory 与 PostgreSQL provider 都必须比较完整 expected snapshot，不能把 stale command
改写为终态幂等成功。

### 唯一事务漏斗与锁序

不新增 identity 专用事务入口。现有 PostgreSQL `producer_tx` 接受 crate-private sealed
`ProducerFactAuthorization`；HTTP producer authorization 来自 mounted receipt，credential-security authorization
只能由 sealed command 按值交给 fact builder，再由同一个 `CredentialSecurityFact` 原样交给 transaction outcome。
不存在零参数 mint 或 sibling-module 固定 fact token。两类 authorization 都进入同一个 projection + OutboxFact
提交漏斗，canonical append 仍不可从漏斗外调用。

安全事件事务固定锁序为 `account-security → refresh-family → auth-grant`。未来把 credential material 更新合入
同一事务时，只能向前扩为 `credential → account-security → refresh-family → auth-grant`。账户状态/epoch、
refresh family、AuthGrant 和 OutboxFact 必须全成或全败。

成功 receipt 只能在数据库确认 commit 后铸造。CAS 冲突返回冲突；commit result unknown 返回错误且不返回
receipt、不自动重试。#1841 不新增 dedup ledger：线性命令、expected snapshot 与不可伪造 receipt 是本协议的重放
边界。0069/0070 继续承载账户、grant、refresh 与 outbox；0071 只新增 append-only
`credential_security_target_mappings`，把随机 opaque target ref 映射到 provider-owned subject/grant target。
mapping 与 mutation、OutboxFact 在同一 `producer_tx` 提交，启用 FORCE RLS，业务角色只有 INSERT/SELECT、没有
UPDATE/DELETE。

### Draft wire 与激活门

`identity.security-event@v1` 保持 `lifecycle = "draft"`，只含 `kind`、`target`、`tenantId`、`occurredAt` 四个必填
字段，`additionalProperties=false`。kind 为上述九个闭值；target 是唯一 tagged object，kind 只有
`subject | grant`，ref 是随机 opaque UUID。payload 与 transport metadata 不出现 raw subject、grant/session、
sid/jti、token、password/credential material、email/username 或其他 PII。tenant、target kind、opaque ref 与
provider mapping 从同一 sealed command/fact 数据流派生；受权 resolver 请求同时绑定 tenant scope、ref 与 expected
kind，wrong tenant/ref/kind 返回无结果，损坏的 subject/grant row shape 返回 typed error。

draft 没有 subscriptions，不进入 active event registry，也不声称已接 production。#1842 / #1843 必须同时闭合
真实 operation 权限、route receipt、生产 producer emit、审计 subscriber、runtime dispatch、reuse compromise
传播和 L2 assurance 后，才能将其提升为 active；激活是生命周期晋级，不增加兼容 shim 或双写。

## 失败语义与安全模型

- projection、target mapping、grant/family 与 OutboxFact 任一步失败都回滚；不得返回成功 receipt。
- stale expected snapshot 不能部分更新、补写 outbox 或静默 no-op。
- draft fact 只携带随机 opaque ref，不携带 raw 用户/会话标识或凭据材料；解析只能经 tenant-scoped sealed resolver
  request，审计细节由未来受权的消费边界补充。
- production 未挂载是显式边界，不以静态 contract/codegen 证据替代运行证据。

## AI-HARD 载体

| 不变式 | 载体 | 评级 |
|---|---|---|
| kind、closed target 与可执行 transition 不能分离或由调用方覆盖 | 封闭层级 enum + 私有派生 API | Hard |
| 外部不能伪造 command、producer authorization、resolver request 或成功 receipt | 私有字段 + move-only token + sealed trait/constructor | Hard |
| 安全事件不能建立第二事务/append 漏斗 | 唯一 `producer_tx` + crate-private `TxCapability` | Hard |
| wire 只有四字段、九 kind、typed opaque target 且拒绝未知字段 | JSON Schema + codegen `deny_unknown_fields` | Hard |
| opaque target 只能解析为同 tenant/ref/kind 的 closed row | sealed resolver request + checked provider hydration + FORCE RLS | Hard + 数据库 Hard |
| draft 不进入 active topology | lifecycle codegen registry 分流 | Hard |
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
- 将 draft 直接标为 active：在 producer/subscriber/runtime assurance 缺失时制造虚假生产证据。
