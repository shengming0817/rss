# ADR-017：互斥 Token Profile、输入硬边界与 listener 信任链

- **状态**：Accepted
- **日期**：2026-07-18
- **关联**：issue #1831；由 ADR-021 / #1835 收紧 RSS 为 User-only grant profile
- **依赖**：ADR-006（typed auth plan / PDP）、ADR-007（service identity）、ADR-009（typed route finalize）
- **兼容性**：intentional breaking；不保留旧 token、旧环境变量、旧 Rust API 或双读路径

## 背景

原有一个 provider 同时携带 ES256/HS256 key，listener 又把外部 access、RSS 自签 access 与 service token
折叠为泛化 JWT。该形态允许 profile、算法、issuer、audience、key source 与 listener 在运行期被错误组合；
重复或超大 header/token 也可能在边界检查前进入 decode、JSON、key lookup、crypto 或 replay。

RFC 8725 要求不同类型 JWT 使用互斥验证规则与不同 keys（[§3.11 Explicit Typing](
https://www.rfc-editor.org/rfc/rfc8725.html#section-3.11)、[§3.12 Mutually Exclusive Validation Rules](
https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12)）。RSS access token 采用
[RFC 9068 §2.1](https://www.rfc-editor.org/rfc/rfc9068.html#section-2.1) 的 `typ=at+jwt`；JWS
protected header 的 `crit` 按 [RFC 7515 §4.1.11](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11)
处理。`token_use` 不是标准 JWT/JWS claim，而是 RSS 私有的 profile discriminator。

## 决策

### 三个互斥 profile

`TokenProfile` 是穷尽枚举，marker 是 sealed type，policy 字段私有并由 marker 单源派生：

| Profile | `typ` | `token_use` | 算法 | 最大 `exp-iat` | 签发 |
|---|---|---|---|---:|---|
| RSS Access | `at+jwt` | `access` | ES256 | 900s | RSS typed issuer，仅从 User AuthGrant |
| Federated Access | `at+jwt` | `access` | ES256 | 900s | 无 |
| Service Token | `rss-service+jwt` | `service` | HS256 | 300s | Service typed issuer |

RSS/Federated 即使 `typ`、`token_use`、算法相同，也必须分别锁定 listener binding、issuer、audience 与
ES256 key source。Service Token 使用独立 issuer、audience、HS256 `kid`/secret 与 cluster-global replay；
不得从 access JWKS 取 key。

ADR-021 后 RSS identity shape 也与 Federated 互斥：RSS 固定 `kind=user` 且必须携带完整
`sid/jti/auth_time/authn_epoch`；没有运行时 trusted-kinds。Device/Admin/SuperAdmin 只由 Federated profile
按其独立 allowlist 接受，Federated 的同名 extension claims 不产生本地 grant evidence。

每个现有 listener 在启动期固定一个 profile：Primary/Admin 必须显式选择 `rss-access` 或
`federated-access`，Internal 必须显式选择 `mtls` 或 `service-token`，Health 永远 NoAuth。profile 不从
token `typ`、claim、HTTP header 或 query 推断。同一 listener 不双收 RSS/Federated，也不增加 ListenerKind。

### 解析顺序与 claim 边界

紧凑 JWS 的 encoded total/header/payload/signature 上限分别为 16 KiB / 4 KiB / 12 KiB / 1 KiB；等于上限
接受，`+1` 拒绝。验证顺序固定为 total → 三段拆分与逐段长度 → base64url → JSON → signing input →
exact `kid` lookup → crypto → replay。超限输入不得进入后续重处理。

protected header 必须有大小写精确的 `alg`、`typ`、`kid`；`kid` 非空且精确匹配。当前没有受支持的 critical
extension，因此出现 `crit` 就拒绝，包括空数组、`null`、非数组与未知名称；未知 non-critical header 可忽略。

所有 profile 必须有数值 `iat`/`exp`，且满足 `iat <= exp`、`iat <= now + leeway` 和对应 profile 最大寿命。
RSS/Federated 的 User/Device/Admin 必须有 verified `tenant_id`，SuperAdmin 必须没有。Service Token 必须有
非空 `jti`、`kind=service`，禁止 tenant claim；tenant 只来自已纳入 MAC 的 canonical `X-Tenant-ID`。

Authorization 与 Service `X-Tenant-ID` 都要求 exact-one。重复同值与异值都拒绝；HeaderValue 字节长度必须在
UTF-8、复制与解析之前检查。错误响应、日志与 metric label 不得包含 token、subject、tenant、kid 或 jti。

### 部署配置

部署只接受下列 namespace，不双读旧名：

- selectors：`RSS_PRIMARY_TOKEN_PROFILE`、`RSS_ADMIN_TOKEN_PROFILE`、`RSS_INTERNAL_AUTH_SCHEME`；
- RSS Access：`RSS_ACCESS_TOKEN_{ISSUER,AUDIENCE,SIGNING_ACTIVE_KEY_ID,SIGNING_NEXT_KEY_ID,SIGNING_RETIRING,SIGNING_ROTATED_AT,ROTATION_MODE,ROTATION_CLOCK_SKEW_SECS,ROTATION_JWKS_PROPAGATION_SLO_SECS,ROTATION_MARGIN_SECS,TTL_SECS,JWKS_PATH,JWKS_REFRESH_INTERVAL_SECS}`；
- Federated：`RSS_FEDERATED_ACCESS_TOKEN_{ISSUER,AUDIENCE,TRUSTED_KINDS,JWKS_PATH,JWKS_REFRESH_INTERVAL_SECS}`；
- Service：`RSS_SERVICE_TOKEN_{ISSUER,AUDIENCE,HS256_KID,HS256_SECRET_B64URL}`。

未选择的 profile 不构造 provider；其 namespace 任一变量出现都作为 orphan config 启动失败。RSS/Federated
同时激活时，issuer、audience、canonical JWKS path 任一重合都启动失败；Service issuer/audience 也不得与
任一 access profile 重合。JWKS 初始加载和刷新都拒绝 HS key、缺/空 `kid`、错误曲线与空快照；刷新失败保留
last-good，并降低对应的 `rss_access_token_jwks_ready` 或 `federated_access_token_jwks_ready`。

## AI-HARD 载体

- **Hard**：sealed marker、typed issuer/provider/binding、私有字段、穷尽枚举与不存在的错误-profile API。
- **Medium**：compile-fail/UI tests、构造 callsite dylint、public API drift、assembly anti-vacuity fixtures与
  E2E 行为矩阵。

本 ADR 不单独新增 Soft-only invariant。正式 invariant 名只有在上述 machine carrier 与红/绿
anti-vacuity evidence 同批存在时才登记。

## 上线与回滚

这是 pre-GA 的原子破坏式切换：旧 `typ=JWT`、缺 `token_use`、无 `kid`、超寿命 token 与旧配置全部失效。
部署必须清空在途 token并要求重新认证；mint、verify、runtime config 与 listener binding 不允许拆分发布。
回滚只能整体回滚 binary 与配置，不得在新 binary 中恢复 alias、deprecated shim 或双读。

具体停流、refresh/session 全量失效、基于最后签发 token 的 `exp` 与验签/时钟余量排空、readiness/canary
验证和整体回滚步骤以
[Security Production Closeout](../ops/security-production-closeout.md#atomic-token-profile-cutover) 为运维单源。
