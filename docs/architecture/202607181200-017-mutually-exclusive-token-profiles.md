# ADR-017：互斥 Token Profile、输入硬边界与 listener 信任链

- **状态**：Accepted
- **日期**：2026-07-18
- **关联**：issue #1831；由 ADR-021 / #1835 收紧 RSS 为 User-only grant profile；**#1997 amendment**
  将 Service Token 收为标准 compact JWS HS256（signed `tenant_id` + header challenger equality，删除私有 MAC）
- **依赖**：ADR-006（typed auth plan / PDP）、ADR-007（service identity）、ADR-009（typed route finalize）
- **兼容性**：intentional breaking；不保留旧 token、旧环境变量、旧 Rust API、私有 MAC helper 或双读路径

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

历史上 Service Token 曾把 canonical `X-Tenant-ID` 拼进私有 HS256 MAC 输入（非 RFC 7515 signing
input）。**#1997** 原子删除该扩展：Service Token 改为标准 compact JWS；tenant 权威只来自 signed
claim；header 仅作 challenger equality。不换 crypto/依赖，不新增 T3/Soft gate。

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

**#1997**：所有 profile（含 Service Token）的 signing input **仅**为 RFC 7515 标准
`base64url(header).base64url(payload)`。禁止把 header 拼进 MAC 或其它非标准 signing input。
最终 tree / PR **不保留**旧私有 MAC token 样本、负向墓碑 fixture，也不要求运维持有 archived
old token；不兼容切换靠排空 + 原子部署完成，不靠旧样本回归。

protected header 必须有大小写精确的 `alg`、`typ`、`kid`；`kid` 非空且精确匹配。当前没有受支持的 critical
extension，因此出现 `crit` 就拒绝，包括空数组、`null`、非数组与未知名称；未知 non-critical header 可忽略。

所有 profile 必须有数值 `iat`/`exp`，且满足 `iat <= exp`、`iat <= now + leeway` 和对应 profile 最大寿命。
RSS/Federated 的 User/Device/Admin 必须有 verified `tenant_id`，SuperAdmin 必须没有。Service Token 必须有
非空 `jti`、`kind=service`，以及 **signed canonical `tenant_id` claim**（权威 ambient tenant 的唯一来源）。
Service principal 自身仍 `tenant=None`；ambient scope 只从 sealed typed claim 建立。

Authorization 与 Service `X-Tenant-ID` 都要求 exact-one。对 Service Token：exact-one canonical
`X-Tenant-ID` 是 **challenger only**——OIDC verifier 在标准签名成功、typed claim 生成之后、replay
consume 之前做一次 claim/header equality；缺 header、重复 header、非 canonical UUID、与 signed claim
不等均 401。Header 不得单独建立 ambient tenant。mTLS 仍不产生 tenant。错误响应、日志与 metric label
不得包含 token、subject、tenant、kid 或 jti。

### 部署配置

部署只接受下列参数，不双读旧名：

- selectors：`RSS_PRIMARY_TOKEN_PROFILE`、`RSS_ADMIN_TOKEN_PROFILE`、`RSS_INTERNAL_AUTH_SCHEME`；
- RSS Access：`RSS_ACCESS_TOKEN_{ISSUER,AUDIENCE,SIGNING_ACTIVE_KEY_ID,SIGNING_NEXT_KEY_ID,SIGNING_RETIRING,SIGNING_ROTATED_AT,ROTATION_MODE,ROTATION_CLOCK_SKEW_SECS,ROTATION_JWKS_PROPAGATION_SLO_SECS,ROTATION_MARGIN_SECS,TTL_SECS,JWKS_PATH,JWKS_REFRESH_INTERVAL_SECS}`；
- Federated：`RSS_FEDERATED_ACCESS_TOKEN_{ISSUER,AUDIENCE,TRUSTED_KINDS,JWKS_PATH,JWKS_REFRESH_INTERVAL_SECS}`；
- Service：`RSS_SERVICE_TOKEN_{ISSUER,AUDIENCE,HS256_KID,HS256_SECRET_B64URL}`。

未选择的 profile 不构造 provider；其 namespace 任一变量出现都作为 orphan config 启动失败。RSS/Federated
同时激活时，issuer、audience、canonical JWKS path 任一重合都启动失败；Service issuer/audience 也不得与
任一 access profile 重合。JWKS 初始加载和刷新都拒绝 HS key、缺/空 `kid`、错误曲线与空快照；刷新失败保留
last-good，并降低对应的 `rss_access_token_jwks_ready` 或 `federated_access_token_jwks_ready`。

#1997 不新增配置键、不引入 dual-read / alias，也不新增 T3 或 Soft gate。

## AI-HARD 载体

- **Hard（typed API 结构收口）**：sealed marker、typed issuer/provider、穷尽枚举；Service Token mint
  的 sign helper **不**接收 tenant-header / binding 参数（signing input 在类型上只能是标准
  `header.payload`）；HS256 verify 路径 **不**接收 challenger 参数（crypto 只验标准 JWS）；
  challenger equality 发生在 typed claim 生成之后、独立于 crypto API；ambient tenant 只经 sealed
  typed claim 暴露。
- **Medium（精确行为）**：fixed standard known-answer / recording signer 锁定 signing-input 字节；
  compile-fail/UI、callsite dylint、public API drift、assembly anti-vacuity 与 E2E 行为矩阵（缺/
  重复/mismatch header、缺 `tenant_id` claim、坏签名、claim/header equality、mTLS tenantless）。

不把「已删除的旧 API 名」或私有 MAC compile-fail tombstone 登记为永久 Hard carrier；最终 tree 不保留
该类墓碑。正式 invariant 名只有在上述 machine carrier 与红/绿 anti-vacuity evidence 同批存在时才登记。
本 ADR 不单独新增 Soft-only invariant。

## 上线与回滚

这是 pre-GA 的原子破坏式切换：旧 `typ=JWT`、缺 `token_use`、无 `kid`、超寿命 token、旧配置，以及
#1997 前依赖私有 MAC / 缺 signed `tenant_id` 的 service-token 语义全部失效。部署必须清空在途 token
并要求重新认证；mint、verify、runtime config 与 listener binding 不允许拆分发布，也不允许旧私有
MAC 与新标准 JWS 双读。运维与测试 **不得**依赖 archived old token 样本做 canary 或负向证据。

外部消费者不得恢复 alias、deprecated shim、非标准 signing input 或双读。产品部署、停流、
readiness/canary 与回滚由消费者仓库负责，不是 RSS library 的交付面。
