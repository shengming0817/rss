# Data Model: PDP 验签接线（#1109 剩余 W）

**Phase 1** · 实体 + 类型 + 错误映射。本 feature 无持久化表（验签纯计算 + 可选内存 JWKS 缓存）；「数据模型」= 类型形态与 fail-closed 映射。

## 冻结类型（消费，不改 —— `crates/diport/src/pdp.rs`）

| 类型 | 形态 | 说明 |
|------|------|------|
| `RawCredential` | `{ scheme, token bytes }`，构造 `RawCredential::jwt(raw)` / `::service_token(raw)` | 入站凭据，adapter verify 入参 |
| `VerifiedClaims` | 私有 `{ subject: String, tenant: Option<String>, kind: Option<String> }`，构造 `VerifiedClaims::new(...)`，访问器 `subject()/tenant()/kind()`，Debug 脱敏 | 验签产物；adapter **唯一构造入口**（验签成功后）；kind 透传不校验 |
| `PdpError` | `#[non_exhaustive] enum { InvalidSignature, Expired, Untrusted }`，不携 source | fail-closed 三变体（纯 taxonomy） |
| `Pdp` / `DynPdp` | `async fn verify(&self, raw: &RawCredential) -> Result<VerifiedClaims, PdpError>` | dynosaur dyn port；组合根注入 `Box<DynPdp>` |

## 新增类型（adapter 内部 —— `adapters/oidc`，PR-A1/A2）

### `SupportedAlg`（`#[non_exhaustive]`）
```
Es256   // ECDSA P-256 / SHA-256（p256），非对称，JWT 生产默认
Hs256   // HMAC-SHA256（hmac+sha2），对称，service_token
// EdDSA 接缝预留（follow-up）
```

### `KeyMaterial` / `KeyEntry` / `KeySource`
- `KeyMaterial = Es256VerifyingKey(p256::ecdsa::VerifyingKey) | Hs256Secret(MacKey)`（构造期解析，热路径只 verify）。
- `KeyEntry = { kid: Option<String>, alg: SupportedAlg, material: KeyMaterial }`。
- `KeySource`（抽象，构造器入参，签名跨 A2 稳定）：
  - `StaticKeySource`（PR-A1）：按 kid 索引的固定 `Vec<KeyEntry>` / `HashMap`。
  - `JwksKeySource`（PR-A2）：远程 fetch + 缓存 + 轮转，同 `KeySource` 抽象，附 `ManagedResource` 真实关闭。

### `OidcProvider`（sealed-marker）
```
key_set:          KeySource          // JWT 验签 key（ES256/HS256）
service_key_set:  KeySource          // service_token 专用（HS256-only，路径隔离）
clock:            Box<dyn Clock>     // 必填位置参注入，禁系统时钟
trusted_issuers:  HashSet<String>    // iss 白名单
expected_audience: <aud 集>          // aud 校验
leeway:           Duration           // exp/nbf 时钟偏移容忍
```
- 构造器必填位置参（含 Clock）；保留 `impl ManagedResource`（静态 key → name()="oidc"/shutdown()=Ok，去 todo!()；JWKS 句柄 → 真实关闭）。

### claims DTO（adapter 私有，验签后解码）
`{ exp, nbf, iat, iss, aud, sub, tenant(自定义), kind(自定义) }` → 校验后映射 `VerifiedClaims::new(sub, tenant, kind)`。

## 新增类型（httpserve own —— `crates/httpserve`，PR-B）

### `Authenticated`（放行证据 extension）
- 基础级类型，**零 authn 依赖**；仅脱敏标量：已验证的 `scheme: RequiredScheme`（验签桥**实际验证的**凭据方案，用 `RequiredScheme` 非 `AuthScheme` → 类型层杜绝「NoAuth 证据」）+ `principal_kind: vocab::PrincipalKind`（主体类别）。私有字段 + `Authenticated::new(scheme, principal_kind)` 构造 funnel（`new` callsite 由 `rss_authenticated_callsite` dylint 限组合根，AUTH-EVIDENCE-MINT-01）。
- enforce 层对 `Require(required)` 路由：request extension 携 `Authenticated`、其 `principal_kind` 非 `Anonymous`、**且 `scheme()` exact-match `required`** → 放行；无证据 / `Anonymous` / 方案不匹配（如 Jwt 证据撞 `Require(Mtls)`）→ fail-closed 401（AUTH-EVIDENCE-REQUIRE-01，杜绝 scheme 混淆）。
- **不引** `authn::Principal`（避免跨层依赖）；组合根桥接把 Principal + 验证的 scheme 降维成 `Authenticated`。

## 新增（组合根 bins —— PR-C）

### `verify_bridge` 中间件
- axum 中间件：`extract Authorization 凭据 → authn::verify_jwt/verify_service_token(raw, &DynPdp) → Ok((VerifiedJwt, Principal))` → **内联** 降维：`httpserve::Authenticated::new(verified_scheme, principal.kind())`——`verified_scheme: RequiredScheme` = 验签桥**实际验证的**凭据方案（须与入站 `RawCredential` 的 scheme 一致；enforce 据此 exact-match 路由 `Require(required)`，方案不匹配 fail-closed）、`principal.kind(): vocab::PrincipalKind`，`req.extensions_mut().insert(authenticated)`；`Err(AuthnError)` → fail-closed 401（带 requestId）。
- ⚠ 降维是 `auth_bridge.rs` 内**内联** mapping（**非** `impl From<&authn::Principal> for httpserve::Authenticated`：From impl 会落 httpserve 或 authn 任一 crate，前者违分层、后者无意义；内联在组合根 bins 无此问题）；具体取值方法名以 PR-B `Authenticated` + authn `PrincipalKind` 的实际 API 为准（本文不锁不可编译的方法名锚点）。
- **传播边界（评审 F3）**：`Authenticated`（principal_kind facet）足够让 httpserve enforce 放行；**handler / 域授权读完整 `Principal`** 需 runctx principal facet 绑定，属 **W 阶段后续**，不在本批承诺——本批 e2e 仅断言 `Authenticated` 放行 + facet，不断言 handler 取完整 Principal。
- 持 `Box<DynPdp>`（构造器必填，= 真 OidcProvider）。
- tracing span：ok → `authz.decision=allow` + `principal.kind`（PrincipalKind 枚举，非 PII）；err → `authz.decision=deny` + `PdpError` 变体名（InvalidSignature/Expired/Untrusted 告警级别可分）。**禁** `{:?}` 整体 Principal/VerifiedClaims/token。

## fail-closed 映射表（verify → PdpError）

| 内部失败 | PdpError | 理由 |
|---------|----------|------|
| 段数≠3 / base64 坏 / payload JSON 坏 / sig decode 坏 | `InvalidSignature` | 结构损坏归签名无效 |
| HMAC / ECDSA 校验不通过 | `InvalidSignature` | 直接 |
| `alg: none` | `InvalidSignature` | alg=none 攻击 |
| exp 过期（now > exp + leeway） | `Expired` | 时钟越界 |
| nbf 未到（now + leeway < nbf） | `Expired` | 时钟越界 |
| 未知/禁用 alg（RS256 等） | `InvalidSignature` | 不在白名单，`jws::parse` 拒（UnsupportedAlg） |
| kid 无匹配 key | `Untrusted` | key 不受信 |
| iss 不在 trusted 集 / aud 不含 expected | `Untrusted` | 签发者/受众不受信 |
| alg 与 key 类型不符（confusion） | `Untrusted` | key 类型不符 |
| 空 subject | `InvalidSignature`（adapter 早拒；authn 亦双闸） | fail-closed |

## 状态/不变式

- **VerifiedClaims 仅 Pdp 验签后 mint**（ADR-006 ①，Hard）：本 feature 加回归断言守不退化。
- **Principal 仅经 from_verified_*(&newtype) 派生**（ADR-006 ②，Hard：`VerifiedJwt` `pub(crate) seal`）。
- **Box<DynPdp> 注入必填**（Hard：构造器位置参，缺失即编译错）。
- **Authenticated 缺失 / scheme 不匹配 → fail-closed 401**（私有字段 typed extension = **Hard/类型层**；enforce 默认拒 + scheme exact-match = **Medium**，单测 + 集成测试守，AUTH-EVIDENCE-REQUIRE-01；`Authenticated::new` 仅组合根 = **Medium** callsite dylint，AUTH-EVIDENCE-MINT-01）。
- **stub Pdp 不入生产 bin**（Medium：deny.toml adapter wrapper + dev-dep 隔离）。
