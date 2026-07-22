# ADR-021：会话绑定的 RSS User access-token 证据

- **状态**：Accepted
- **日期**：2026-07-22（UTC）
- **关联**：issue #1835 / #1839；amend ADR-017 / ADR-018 / ADR-019 / ADR-020
- **兼容性**：intentional breaking；不保留本地 Device/Admin/SuperAdmin mint、RSS trusted-kinds、通用 VerifiedClaims 构造器或旧 token 双读

## 背景

ADR-019 已把登录与 refresh family 绑定到持久 `AuthGrant`，但 access JWT 仍只携带
`sub/tenant_id/kind`。资源请求无法定位 grant，也无法证明 token 使用的是登录时刻和签发时账户 epoch。
同时，RSS issuer 允许调用方选择 User/Device/Admin/SuperAdmin，RSS verifier 又通过运行时
trusted-kinds 放行同一集合；这让本地 signer 具备不需要 AuthGrant 的特权主体 mint 能力。

`VerifiedClaims` 的通用 `{subject, tenant, kind}` shape 也不能表达“只有 RSS User token 才具有本地 grant
证据”。若仅新增若干 `Option` 字段，Federated/Service 产物可以携带同名字段，RSS 产物也可以缺失 quartet，
profile substitution 仍然可表达。

## 决策

### RSS access 固定为本地 User grant

RSS access issuer 只接受从完整活动 `AuthGrant` 借出的 `RssAccessIssueInput`。输入字段私有，调用方不能独立
选择 subject、tenant、kind、sid、auth_time 或 epoch。签发固定生成：

- `sub`：grant 的 canonical `UserId`；
- `tenant_id`：grant tenant；
- `kind=user`：常量，不接受调用方或配置覆盖；
- `sid`：grant 的 canonical UUIDv4 `AuthGrantId`；
- `jti`：每次 mint 内部新生成的 canonical UUIDv4；
- `auth_time`：grant 原始认证时刻；
- `authn_epoch`：`authn_epoch_at_issue`；
- `iat/exp/iss/aud/typ/token_use/alg`：继续由 typed profile 与 issuer config 派生，`exp` 不超过 grant expiry。

必须满足 `0 <= auth_time <= iat < exp`。refresh rotation 必须重新取得活动 AuthGrant 后 mint，不能从 refresh
record 或当前账户快照拼装 issue facts，也不能把 refresh 时刻改写为 auth_time。

本地 RSS 不再签发 Device/Admin/SuperAdmin。这些非 User 主体只属于独立 Federated Access trust domain；
Service 继续使用独立 Service Token profile。删除 `RSS_ACCESS_TOKEN_TRUSTED_KINDS`，RSS verifier builder 不暴露
`trust_kind`；Federated builder 和 `RSS_FEDERATED_ACCESS_TOKEN_TRUSTED_KINDS` 保留。

### VerifiedClaims 是闭合 profile shape

`VerifiedClaims` 以私有 tagged profile shape 表示三种互斥产物：

- `RssUser { UserId, TenantId, VerifiedAccessGrantFacts }`：grant quartet 必须完整；
- `FederatedAccess { subject, tenant, PrincipalKind }`：允许 Federated 的闭值主体语义，但没有本地 grant；
- `ServiceToken { ServiceCallerDomain }`：没有 tenant/kind/grant 可选 bag。

删除通用 `VerifiedClaims::new(subject, tenant, kind)`。provider 只能使用 profile-specific checked factory；authn
的三个 verify funnel 必须匹配精确 variant，不能只读字符串后忽略 profile。Federated token 即使携带
`sid/jti/auth_time/authn_epoch` 同名 extension，也不能得到 RSS grant receipt。

`VerifiedJwt` 只为 RSS variant 借出最小 `VerifiedGrantReceipt`。receipt 与 VerifiedClaims、AuthGrant、issue
input 的 Debug 全脱敏；raw sid/jti/auth_time/epoch 不进入日志、metric label、error body 或 tracing field。

### AuthGrant 与安全原因词汇下沉 authn

`authn` 是 issuer 所在服务层，按 crate 分层不能依赖 `identity` 域。为了让 issuer 的公开签名在类型层只接受
AuthGrant，不建立 raw issue seam，`AuthGrant` 聚合及其直接状态词汇下沉 `authn`：`AuthGrantId`、
`AuthnEpoch`、status/snapshot/close mutation，以及完整 `CredentialSecurityEventKind` 层级。

必须移动完整 security kind，而不是只移动 grant-local 两个 variant：AuthGrant 的 `close_reason` 同时保存
ADR-020 的七个 Account 原因与两个 Grant 原因。identity 直接消费同一个 exact enum；不得新增
`AuthGrantCloseReason`、字符串 translation enum、alias 或兼容构造器。

所有权下沉不移动 #1841 的事务能力：`AccountSecurityState`、`CredentialSecurityEvent`、account/grant sealed
command、move-only fact authorization/receipt、tenant-scoped target resolver 和 `producer_tx` 仍由 identity
拥有。identity 从同一个 AuthGrant/security kind 派生 target、mutation 与事件；账户事件 bump epoch，grant
事件不 bump epoch。`identity.security-event@v1` 仍使用随机 opaque target ref，绝不把 JWT sid/jti 放进 payload、
mapping ref、幂等键或 transport metadata。

### 每请求 durable current fence

RSS User 在密码学验证成功后、铸造 HTTP 认证证据前，必须把完整
`VerifiedGrantReceipt` 消费为不可自由构造的 `AccessGrantValidationInput`。production provider 以一次
tenant-scoped PostgreSQL 读取在同一 snapshot 中比较 grant id、UserId、tenant、auth time、grant epoch、
grant Active/expiry，以及 account Active/epoch。缺失、终态、过期或任一不一致均返回 401；存储故障
返回可重试 503，不得退回 JWT-only 证据。密码学失败在 durable 读之前拒绝。

只有 validator 返回 move-only `ValidatedAuthGrant` 后，runtime 验签桥才能在精确 wrapper 内铸造
`CurrentAuthGrant` 并交给 `Authenticated::new_rss_user`。handler 同时可只读访问已验证
`VerifiedJwt`，但不能用 receipt 绕过 durable fence。Federated 不执行本地 grant 读，且 receipt 始终为
`None`。

## 失败语义与边界

- 缺失、错类型、非 canonical UUIDv4、负 auth_time/epoch、时间逆序、错误 profile 或非 User RSS token均拒绝；
- signer/verifier/provider 失败不回退到无 grant 的旧 RSS 规则；
- `VerifiedGrantReceipt` 只是已签名定位证据，不是当前服务器状态；它只能转换为密封校验输入，不能直接构造 `CurrentAuthGrant`、logout 或 security command；
- public `AuthGrant::hydrate` 是 adapter hydration 边界，因此 concrete AuthGrant 参数 Hard 保证 shape/状态；RSS issue
  input 的字段私有，且唯一 producer 是 `AuthGrant::access_issue_input`。边界 claim matrix 与 compile-fail/trybuild
  用例作为 Medium 回归证据；source-aware DefId dylint 额外限定 `LoginService::login`、
  `PgAuthGrantLifecycle::find_active` 与 `RefreshService::{prepare_initial,rotate}` 的精确调用拓扑，并以
  direct/alias/re-export 红例与精确 impl-method 绿例防空。

## AI-HARD 载体

| 不变式 | 载体 | 评级 |
|---|---|---|
| RSS mint 不能选择非 User 身份或独立 grant 字段 | `issue_access(RssAccessIssueInput)` + private grant-borrowing input + 删除旧 principal API | Hard |
| RSS verify 不能由配置重新放行非 User | RSS builder 无 `trust_kind`，profile-specific exhaustive validation | Hard |
| RSS/Federated/Service verified shape 不能错配 | private tagged shape + checked named factories + exact funnel match | Hard |
| RSS grant quartet 不可部分存在 | `VerifiedAccessGrantFacts` 私有字段 + complete checked constructor | Hard |
| raw verified evidence 不能伪造 VerifiedJwt/receipt | crate-private seal + borrowed private receipt | Hard |
| durable validator 输入不能拆分替换 tenant/subject/grant/epoch | receipt-consuming private `AccessGrantValidationInput` + compile-fail | Hard |
| #1841 关闭原因不能形成第二真源 | 单一 `CredentialSecurityEventKind` exact type + exhaustive transition | Hard |
| wire/security event 不增加 sid/jti | 既有 schema/codegen `additionalProperties=false` + opaque target | Hard |
| AuthGrant create/hydrate/issue 的 production source 拓扑不可绕过 | DefId + caller impl dylint，direct/alias/re-export 红例、精确绿例 | Medium |
| 每个 RSS 受保护请求都是当前 grant/account | 必填 validation service + 单查询 provider + move-only proof + exact runtime marker callsite + 真 PostgreSQL/E2E | Medium |
| mint↔verify、substitution、redaction 与 runtime listener 行为 | package/integration/security tests | Medium |

## 被拒绝方案

- 保留 `JwtAccessPrincipal`，只要求业务“自觉传 User”：本地特权 token 仍可表达。
- 只收紧 issuer、不收紧 verifier/config：旧或受控 signer 仍可生成 RSS Admin/SuperAdmin。
- `TokenProfile + Option<GrantFacts>`：允许 RSS 无 facts 与 Federated 携 local facts。
- 从 refresh record/current account 复制字段生成 issue input：无法证明原始 auth_time 与完整 AuthGrant 来源。
- 只下沉 `GrantSecurityEventKind`：AuthGrant 的 account close reason 会迫使 authn 反向依赖 identity，或制造平行原因模型。
- receipt 直接铸 `CurrentAuthGrant`/logout command：跳过服务器端 active/epoch fence。
- 把 sid/jti 写入 ADR-020 durable event：扩大跨系统关联面并违反最小披露。
