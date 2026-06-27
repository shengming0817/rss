//! authn JWT 签发（mint/sign）：claims 组装 + ES256/HS256 紧凑 JWS 序列化，复用 `diport::Signer` + 注入 `Clock`。
//!
//! 与验签侧对称：验签经 [`crate::verify_jwt`]（结构闸 + `Principal` 派生）+ `diport::Pdp`（真验签留
//! `adapters/oidc`，#1109）；mint 经本模块组装紧凑 JWS、把**签名字节**委托注入的 `diport::Signer`。authn 自身
//! **零 crypto、零 I/O**：claims/header 组装、base64url、signing-input 拼装是纯函数，唯一外部动作是
//! `await signer.sign()`——与 verify→mint bridge `await pdp.verify()` 同范式。真实 JWS-兼容 signer adapter
//! （ES256 定长 r‖s / HS256 HMAC）+ httpserve 接线留 W（softca 输出 DER ≠ JWS r‖s，不可复用，#1314 计划）。
//!
//! ref: RFC 7515 §7.1（JWS Compact Serialization：`base64url(header)."."base64url(payload)` 为 signing
//! input，签名段 base64url 无填充——[`JwtIssuer::issue`] 直接实现，与 `adapters/oidc/src/jws.rs` 验签侧同
//! RFC 反方向：mint=组装 / verify=解析）；RFC 7519（JWT registered claims：sub/exp/iat/iss/aud）；
//! Keats/jsonwebtoken `src/encoding.rs`（`encode(&Header,&claims,&EncodingKey)`：serialize→base64url→拼
//! signing input→签名→拼签名段，同形工业 mint；RSS **不依赖**——手写 base64+serde_json + 委托 `diport::Signer`）。
//! alg 闭枚举 [`JwtAlg`] 是 OIDC-ALG-WHITELIST-01 的 mint 侧镜像（alg=none / RS256 类型层不可 mint）。

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine;
use vocab::PrincipalKind;
use vocab::tenant::TenantId;

// kind claim 串单源（验签侧 `derive_from_claims` 与 mint 侧 `kind_claim` 共用，防 round-trip 漂移）。
use super::{KIND_ADMIN, KIND_DEVICE, KIND_SERVICE, KIND_SUPER_ADMIN, KIND_USER};

/// 统一 base64url 引擎（无填充，RFC 7515 §2 / RFC 4648 §5；与验签侧 `decode_claims` / oidc 同形，
/// header/payload/signature 三段均经此编码）。
const B64_URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// JOSE `alg`（签名算法）闭枚举——mint 侧 alg 白名单。
///
/// 对称 `adapters/oidc/src/jws.rs` 验签侧 `SupportedAlg`：ES256（JWT 路径）/ HS256（service-token 路径）。
/// `alg=none` / RS256 等**类型层不可表达**（闭枚举 = mint 侧白名单）。pre-GA 允许与验签侧 2-variant 枚举
/// 重复（CLAUDE.md domain-patterns：同形不强行共享 Rust 类型）。
///
/// INVARIANT: OIDC-ALG-WHITELIST-MINT-01（Hard，类型层；alg=none/RS256 不可 mint，anti-vacuity：
/// `jwt_alg_jose_strings` 锁 JOSE 串）。alg↔purpose↔key 三者一致性（OIDC-ALG-KEYPATH-01）由**组合根**接线
/// 时保证 + signer adapter 自身 fail-closed（purpose allowlist + key 精确匹配，如 softca）承载——authn 无法
/// 在类型层守（`SigningPurpose` 是 adapter 定义的 opaque 值，非 authn 词汇），故该 Hard 强制层属 wiring/W。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlg {
    /// ECDSA P-256 + SHA-256（JOSE `ES256`）。
    Es256,
    /// HMAC-SHA-256（JOSE `HS256`）。
    Hs256,
}

impl JwtAlg {
    /// JOSE protected header `alg` 字面量。
    fn as_jose(self) -> &'static str {
        match self {
            JwtAlg::Es256 => "ES256",
            JwtAlg::Hs256 => "HS256",
        }
    }
}

/// JWT 签发配置（per-issuer；组合根构造）。
///
/// 非服务依赖的签名 / 整形配置；服务依赖（signer / clock）走 [`JwtIssuer::new`] 必填位置参。`key` / `alg` /
/// `purpose` 须由组合根按 OIDC-ALG-KEYPATH-01 一致接线（ES256 ↔ jwt-purpose ↔ ES256-key）。
pub struct JwtIssuerConfig {
    /// 签名 key 标识（组合根注入，禁默认取系统）。
    pub key: diport::KeyId,
    /// 签名算法（决定 header `alg`，须与 `purpose` 一致）。
    pub alg: JwtAlg,
    /// 签名用途（fail-closed 归因；provider 据此 + key 校验）。
    pub purpose: diport::SigningPurpose,
    /// `iss` claim。
    pub issuer: String,
    /// `aud` claim。
    pub audience: String,
    /// token 有效期（`exp = iat + ttl`）。
    pub ttl: Duration,
}

/// 已签发 JWT（typed 输出 newtype；私有内容；`Debug` 脱敏；不 derive `Serialize`）。
///
/// 唯一 mint 点 = [`JwtIssuer::issue`]（`pub(crate)` 构造 funnel）。同 [`crate::AccessToken`] / [`crate::Jwt`]
/// 脱敏范式：bearer 凭据不进 `Debug` / tracing。携带 `exp`（= JWT `exp` claim，权威单源）供下游 wire 回带
/// `accessExpiresAt`——与 token 内 claim 同一次时钟计算，杜绝 wire 值与 claim 漂移。
pub struct MintedJwt {
    raw: String,
    expires_at: i64,
}

impl std::fmt::Debug for MintedJwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MintedJwt(<redacted>)")
    }
}

impl MintedJwt {
    /// 受控构造（生产唯一调用方 = [`JwtIssuer::issue`]）。`expires_at` = JWT `exp`（epoch 秒）。
    pub(crate) fn new(raw: String, expires_at: i64) -> Self {
        Self { raw, expires_at }
    }

    /// 取紧凑 JWS 串引用。
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// JWT `exp`（UNIX epoch 秒）——与紧凑串内 `exp` claim 同源同值。
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// JWT 签发错误（库枚举；`thiserror`；message 为 const 静态字面量，runtime 数据只进 `#[source]`）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwtIssueError {
    /// 签发器配置非法（空 `issuer` / 空 `audience` / `ttl == 0`）——构造期 fail-fast（对称验签侧
    /// `VerifierConfigBuilder::build` 拒空 iss/aud）。杜绝签发无签发者绑定（`iss=""`）/ 即时过期的弱 token。
    #[error("jwt issuer config is invalid")]
    InvalidConfig,
    /// subject 为空——不签发匿名 token（fail-closed，对称验签侧空 subject 拒绝）。
    #[error("jwt subject must not be empty")]
    EmptySubject,
    /// scoped 主体（user/device/admin）缺 tenant——无法签发租户内 token（fail-closed）。
    #[error("scoped principal kind requires a tenant")]
    MissingTenant,
    /// 该 `PrincipalKind` 不可签发为 JWT（如 `Anonymous` 及未来不可签发 kind）。
    #[error("principal kind is not issuable as a jwt")]
    KindNotIssuable,
    /// 签名算法与 principal kind 的 scheme 错配（ES256 限 user/device/admin/super、HS256 限 service）——
    /// fail-closed，杜绝签发语义与验签 scheme 分裂的凭据（验签侧 `verify_credential` 把 scheme 锁到 alg）。
    #[error("jwt alg does not match principal kind scheme")]
    AlgKindMismatch,
    /// 注入 `Clock` 早于 UNIX epoch（不可能的系统态）——fail-closed，不签发。
    #[error("clock is before unix epoch")]
    ClockBeforeEpoch,
    /// `iat` / `ttl` / `exp` 计算溢出 i64——fail-closed。
    #[error("jwt expiry computation overflowed")]
    ExpiryOverflow,
    /// claims / header JSON 序列化失败（不应发生；fail-closed）。
    #[error("jwt claims serialization failed")]
    ClaimsEncode(#[source] serde_json::Error),
    /// 注入 `Signer` 签名失败（`SignerError` 已脱敏 source）。
    #[error("jwt signing failed")]
    Sign(#[source] diport::SignerError),
}

/// JOSE protected header（私有 mint DTO；只 `Serialize`；不 derive `Debug`——瞬态、不进 tracing）。
///
/// `kid` = 签名 key 标识：验签侧 JWKS 源据 `kid` 选 key，**无 `kid` token 在 JWKS 源 fail-closed 拒签**
/// （`adapters/oidc/src/jwks.rs` `end_to_end_jwks_no_kid_token_fail_closed`）。对齐 `jsonwebtoken::Header`
/// 把 `kid` 作 header 一等字段。
#[derive(serde::Serialize)]
struct JoseHeader<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
}

/// JWT payload claims（私有 mint DTO；只 `Serialize`，借用零拷贝；不 derive `Debug`——含 subject/tenant PII）。
///
/// claim 名与 `adapters/oidc` 验签侧默认对齐：`sub`/`iat`/`exp`/`iss`/`aud` 固定（RFC 7519 注册名），
/// `tenant_id`/`kind` = oidc `config.tenant_claim()` / `config.kind_claim()` 默认名（R1：两侧 claim 名单源
/// 由 login-wiring issue 的集成测试守，本轮无真验签联测）。
#[derive(serde::Serialize)]
struct MintClaims<'a> {
    sub: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<&'a str>,
    kind: &'a str,
    iat: i64,
    exp: i64,
    iss: &'a str,
    aud: &'a str,
}

/// `PrincipalKind` → JWT `kind` claim 串单一漏斗（复用验签侧 `KIND_*` 常量，杜绝 round-trip 漂移）。
///
/// `Anonymous`（及未来不可签发 kind）→ [`JwtIssueError::KindNotIssuable`]（fail-closed）。`PrincipalKind` 为
/// 跨 crate `#[non_exhaustive]`，`_` 臂兜底拒绝——新增可签发 kind 须在此显式加臂（对称
/// `Principal::row_visibility` 的 fail-closed `_`）。
///
/// **mint↔verify 路径分流（注意）**：`Service` 签发的是 **service-token**（配 HS256），其验签经
/// `verify_service_token` → `from_verified_service_token`（**固定** `kind=Service`、**不读** `kind` claim）；
/// 而 `verify_jwt` → `derive_from_claims` **拒绝** `kind="service"`（落 `_` 臂 → `PrincipalInvalid`）。故
/// `Service` token 不可走 JWT 验签路径——这是有意的 scheme 隔离（`CredentialScheme::Jwt` vs `ServiceToken`），
/// 非缺陷。`User/Device/Admin/SuperAdmin`（配 ES256）走 `verify_jwt`。
fn kind_claim(kind: PrincipalKind) -> Result<&'static str, JwtIssueError> {
    match kind {
        PrincipalKind::User => Ok(KIND_USER),
        PrincipalKind::Device => Ok(KIND_DEVICE),
        PrincipalKind::Admin => Ok(KIND_ADMIN),
        PrincipalKind::SuperAdmin => Ok(KIND_SUPER_ADMIN),
        PrincipalKind::Service => Ok(KIND_SERVICE),
        PrincipalKind::Anonymous => Err(JwtIssueError::KindNotIssuable),
        _ => Err(JwtIssueError::KindNotIssuable),
    }
}

/// scoped 主体（user/device/admin）须带 tenant claim；super-admin / service 跨租户省略（对称验签侧）。
fn needs_tenant(kind: PrincipalKind) -> bool {
    matches!(
        kind,
        PrincipalKind::User | PrincipalKind::Device | PrincipalKind::Admin
    )
}

/// alg↔kind scheme 一致性：ES256 = JWT 路径（user/device/admin/super）、HS256 = service-token 路径（service）。
/// 对齐验签侧 `verify_credential` 的 scheme→alg 锁（`CredentialScheme::Jwt`→ES256 / `ServiceToken`→HS256）——
/// 错配（如 HS256 签 user、ES256 签 service）产出签发语义与验签 scheme 分裂的凭据，mint 侧 fail-closed 拒签。
fn alg_allows_kind(alg: JwtAlg, kind: PrincipalKind) -> bool {
    match alg {
        JwtAlg::Es256 => matches!(
            kind,
            PrincipalKind::User
                | PrincipalKind::Device
                | PrincipalKind::Admin
                | PrincipalKind::SuperAdmin
        ),
        JwtAlg::Hs256 => matches!(kind, PrincipalKind::Service),
    }
}

/// JWT 签发器（authn-owned；CONSUMES `diport::Signer` + `diport::Clock`，不新建 DI port）。
///
/// 组装 claims（sub/tenant/kind/iat/exp/iss/aud）+ ES256/HS256 紧凑 JWS，签名委托注入的 `Signer`。authn 零
/// crypto / 零 I/O（签名委托 port；组装是纯计算）。必填依赖经构造器位置参（缺失即编译错误，rust-standards
/// §工程护栏）；`Clock` 注入（禁默认系统时钟）。
///
/// **泛型静态分发 `Arc<S>`（INVARIANT: DIPORT-ASYNC-ARC-SEND-01）**：async DI port 的 dynosaur `DynSigner`
/// 是 Send 但**非 Sync**，`Box<DynSigner>` 持有者不 Sync ⇒ 无法作 `Arc<JwtIssuer>` 共享 handler state、
/// `issue().await` future 不 Send（axum handler 要求 Send future）。故签发器经**泛型** `S: Signer + Send +
/// Sync + 'static` + `Arc<S>` 注入（零运行期成本、provider 仍可互换）——`JwtIssuer<S>` 随 `S` 为 Send + Sync，
/// `issue().await` 为 Send，可作共享登录服务状态；组合根仍持 `Arc<S>` 句柄供 `ShutdownStack` 编排关闭（不被 move 走）。
pub struct JwtIssuer<S> {
    signer: Arc<S>,
    clock: Box<dyn diport::Clock>,
    config: JwtIssuerConfig,
}

impl<S: diport::Signer + Send + Sync + 'static> JwtIssuer<S> {
    /// 组合根构造：`signer`（`Arc<S>` 静态分发）/ `clock` 必填位置参 + [`JwtIssuerConfig`]。
    ///
    /// 构造期 fail-fast（对称 oidc 验签侧 `VerifierConfigBuilder::build`）：空 `issuer` / 空 `audience` /
    /// 空 `key`（JOSE `kid` 来源，无 kid token 在 JWKS 源 fail-closed 拒签）/ `ttl == 0` →
    /// [`JwtIssueError::InvalidConfig`]——杜绝签发无签发者绑定 / 无 kid / 即时过期的弱 token。
    pub fn new(
        signer: Arc<S>,
        clock: Box<dyn diport::Clock>,
        config: JwtIssuerConfig,
    ) -> Result<Self, JwtIssueError> {
        if config.issuer.is_empty()
            || config.audience.is_empty()
            || config.key.as_str().is_empty()
            || config.ttl.is_zero()
        {
            return Err(JwtIssueError::InvalidConfig);
        }
        Ok(Self {
            signer,
            clock,
            config,
        })
    }

    /// 计算 `(iat, exp)`（注入 `Clock`；fail-closed：clock < epoch / i64 溢出）。
    fn time_claims(&self) -> Result<(i64, i64), JwtIssueError> {
        let secs = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtIssueError::ClockBeforeEpoch)?
            .as_secs();
        let iat = i64::try_from(secs).map_err(|_| JwtIssueError::ExpiryOverflow)?;
        let ttl =
            i64::try_from(self.config.ttl.as_secs()).map_err(|_| JwtIssueError::ExpiryOverflow)?;
        let exp = iat.checked_add(ttl).ok_or(JwtIssueError::ExpiryOverflow)?;
        Ok((iat, exp))
    }

    /// 组装 claims → 紧凑 JWS → 委托签名 → typed [`MintedJwt`]。
    ///
    /// per-call typed 入参：`subject`（主体标识）/ `tenant`（scoped 主体必填、跨租户省略）/ `kind`。
    /// **所有 fail-closed 校验（subject/kind/tenant/clock/overflow）在签名之前**——失败短路、signer 不被调用、
    /// 绝不返回半成品 token。
    pub async fn issue(
        &self,
        subject: &str,
        tenant: Option<TenantId>,
        kind: PrincipalKind,
    ) -> Result<MintedJwt, JwtIssueError> {
        // 1) 输入 fail-closed（对称验签侧 `derive_from_claims`：空 subject / 不可签发 kind / scoped 缺 tenant）。
        if subject.is_empty() {
            return Err(JwtIssueError::EmptySubject);
        }
        let kind_str = kind_claim(kind)?;
        // alg↔kind scheme 一致性 fail-closed（OIDC-ALG-KEYPATH-01 mint 镜像）：错配 mint 会产出签发语义与
        // 验签 scheme 分裂的凭据（验签侧 `verify_credential` 把 Jwt→ES256 / ServiceToken→HS256 锁死）。
        if !alg_allows_kind(self.config.alg, kind) {
            return Err(JwtIssueError::AlgKindMismatch);
        }
        let tenant_claim = if needs_tenant(kind) {
            // TenantId Display = canonical lowercase-hyphenated（验签侧 `TenantId::parse` 接受同一形态）。
            Some(tenant.ok_or(JwtIssueError::MissingTenant)?.to_string())
        } else {
            None
        };

        // 2) iat / exp（注入 Clock，fail-closed）。
        let (iat, exp) = self.time_claims()?;

        // 3) 纯组装 header + claims → base64url（B64_URL，与验签侧 / oidc 同引擎）。
        let header = JoseHeader {
            alg: self.config.alg.as_jose(),
            // kid = 签名 key 标识（验签侧 JWKS 源据此选 key；无 kid token 在 JWKS 源 fail-closed 拒签）。
            kid: self.config.key.as_str(),
            typ: "JWT",
        };
        let claims = MintClaims {
            sub: subject,
            tenant_id: tenant_claim.as_deref(),
            kind: kind_str,
            iat,
            exp,
            iss: &self.config.issuer,
            aud: &self.config.audience,
        };
        let header_b64 =
            B64_URL.encode(serde_json::to_vec(&header).map_err(JwtIssueError::ClaimsEncode)?);
        let payload_b64 =
            B64_URL.encode(serde_json::to_vec(&claims).map_err(JwtIssueError::ClaimsEncode)?);
        // JWS Signing Input（RFC 7515 §5.1）：base64url(header)."."base64url(payload)。
        let signing_input = format!("{header_b64}.{payload_b64}");

        // 4) 委托签名（唯一非纯步；fail 传播，绝不返回半成品 token）。签名失败 / 关键路径 tracing span 待
        //    httpserve 接线补（无生产调用方前不埋空转 span，同 verify→mint bridge #1109 deferral）。
        let signature = self
            .signer
            .sign(diport::SignRequest {
                key: self.config.key.clone(),
                purpose: self.config.purpose.clone(),
                message: signing_input.as_bytes().to_vec().into(),
            })
            .await
            .map_err(JwtIssueError::Sign)?;

        // 5) 紧凑序列化：signing_input "." base64url(signature)。`exp` 与 claim 同源（time_claims 一次计算）。
        let signature_b64 = B64_URL.encode(signature.as_bytes());
        Ok(MintedJwt::new(
            format!("{signing_input}.{signature_b64}"),
            exp,
        ))
    }
}

#[cfg(test)]
mod tests {
    //! mint 单测：紧凑 JWS 结构、各 alg、exp 边界、全部 fail-closed 路径（signer 不被调用 = anti-vacuity）、
    //! 输出脱敏、错误 message const + source 脱敏。替身 `RecordingSigner` / `TestClock` 自包含（CLAUDE.md：
    //! 单测不依赖 adapter crate）。
    use super::*;
    use diport::{KeyId, SignRequest, Signature, Signer, SignerError, SigningPurpose};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    /// 测试用 canonical 租户（`TenantId::parse` 接受形态）。
    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    /// 固定签发时刻（UNIX 秒），便于断言 iat / exp。
    const NOW_SECS: u64 = 1_700_000_000;
    /// 替身签名的确定输出字节（mint 不验 crypto，只断言 base64url 透传）。
    const SIG_BYTES: &[u8] = b"deterministic-signature-bytes";

    /// 记录型签名替身：捕获最近一次 `SignRequest`、可配 Ok(确定字节) / Err。克隆共享句柄供注入后断言。
    #[derive(Clone)]
    struct RecordingSigner {
        captured: Arc<Mutex<Option<SignRequest>>>,
        fail: bool,
    }
    impl RecordingSigner {
        fn ok() -> Self {
            Self {
                captured: Arc::new(Mutex::new(None)),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::ok()
            }
        }
        fn captured(&self) -> Option<SignRequest> {
            // reason: test-only stub——poison 取 inner 比再 panic 更利诊断。
            self.captured
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }
    impl Signer for RecordingSigner {
        async fn sign(&self, request: SignRequest) -> Result<Signature, SignerError> {
            *self.captured.lock().unwrap_or_else(|e| e.into_inner()) = Some(request);
            if self.fail {
                // reason: 模拟 provider 签名失败 → issue 须传播 Err、绝不返回半成品 token。
                return Err(SignerError::new(std::io::Error::other("test-sign-fail")));
            }
            Ok(Signature::new(SIG_BYTES.to_vec()))
        }
        async fn shutdown(&self) -> Result<(), SignerError> {
            Ok(())
        }
    }

    /// 确定性测试时钟（impl `diport::Clock`，不取系统时钟）。
    struct TestClock(SystemTime);
    impl diport::Clock for TestClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn now_time() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECS)
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(CANON_TENANT).expect("canonical tenant")
    }

    /// 合法默认配置（key/alg/purpose/iss/aud/ttl）；validation 测试经 struct-update 注入非法字段。
    fn config_with(alg: JwtAlg, purpose: &str, ttl: Duration) -> JwtIssuerConfig {
        JwtIssuerConfig {
            key: KeyId::new("test-key"),
            alg,
            purpose: SigningPurpose::new(purpose),
            issuer: "https://issuer.test".to_string(),
            audience: "rss-api".to_string(),
            ttl,
        }
    }

    /// 注入替身 signer（`Arc<S>` 静态分发）/ clock 构造 issuer（透传 `new` 的 Result，validation 测试用）。
    fn try_issuer(
        signer: RecordingSigner,
        clock: SystemTime,
        config: JwtIssuerConfig,
    ) -> Result<JwtIssuer<RecordingSigner>, JwtIssueError> {
        JwtIssuer::new(Arc::new(signer), Box::new(TestClock(clock)), config)
    }

    /// 合法配置构造 issuer（happy-path 测试用；config 合法故 unwrap）。
    #[allow(clippy::expect_used)]
    fn issuer_with(
        signer: RecordingSigner,
        clock: SystemTime,
        alg: JwtAlg,
        purpose: &str,
        ttl: Duration,
    ) -> JwtIssuer<RecordingSigner> {
        try_issuer(signer, clock, config_with(alg, purpose, ttl)).expect("valid config")
    }

    #[allow(clippy::expect_used)]
    fn decode_segment(seg: &str) -> serde_json::Value {
        let bytes = B64_URL.decode(seg).expect("base64url segment");
        serde_json::from_slice(&bytes).expect("json segment")
    }

    fn segments(jwt: &MintedJwt) -> Vec<String> {
        jwt.as_str().split('.').map(str::to_owned).collect()
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_happy_path_produces_three_segment_jwt() {
        let issuer = issuer_with(
            RecordingSigner::ok(),
            now_time(),
            JwtAlg::Es256,
            "auth.jwt.access",
            Duration::from_secs(3600),
        );
        let jwt = issuer
            .issue("user-123", Some(tenant()), PrincipalKind::User)
            .await
            .expect("issue ok");

        let parts = segments(&jwt);
        assert_eq!(parts.len(), 3, "紧凑 JWS 三段 header.payload.signature");

        let header = decode_segment(&parts[0]);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        // F1：kid = 签名 key（验签侧 JWKS 源据此选 key；无 kid 在 JWKS 源 fail-closed 拒签）。
        assert_eq!(header["kid"], "test-key");

        let claims = decode_segment(&parts[1]);
        assert_eq!(claims["sub"], "user-123");
        assert_eq!(claims["kind"], "user");
        assert_eq!(claims["tenant_id"], CANON_TENANT);
        assert_eq!(claims["iss"], "https://issuer.test");
        assert_eq!(claims["aud"], "rss-api");
        assert_eq!(claims["iat"].as_u64(), Some(NOW_SECS));
        assert_eq!(claims["exp"].as_u64(), Some(NOW_SECS + 3600));

        assert_eq!(
            parts[2],
            B64_URL.encode(SIG_BYTES),
            "签名段 = base64url(确定字节)"
        );
    }

    #[test]
    fn new_rejects_invalid_config() {
        // 构造期 fail-fast：空 issuer / audience / key（kid 来源）/ ttl=0 → InvalidConfig（对称 oidc 验签侧 build）。
        let cases: [(&str, JwtIssuerConfig); 4] = [
            (
                "empty issuer",
                JwtIssuerConfig {
                    issuer: String::new(),
                    ..config_with(JwtAlg::Es256, "p", Duration::from_secs(3600))
                },
            ),
            (
                "empty audience",
                JwtIssuerConfig {
                    audience: String::new(),
                    ..config_with(JwtAlg::Es256, "p", Duration::from_secs(3600))
                },
            ),
            (
                "empty key (kid)",
                JwtIssuerConfig {
                    key: KeyId::new(""),
                    ..config_with(JwtAlg::Es256, "p", Duration::from_secs(3600))
                },
            ),
            ("zero ttl", config_with(JwtAlg::Es256, "p", Duration::ZERO)),
        ];
        for (name, config) in cases {
            let result = try_issuer(RecordingSigner::ok(), now_time(), config);
            assert!(
                matches!(result, Err(JwtIssueError::InvalidConfig)),
                "{name} 须构造期 fail-fast"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_ignores_tenant_for_cross_tenant_kinds() {
        // 跨租户 kind（super-admin / service）即便传入 Some(tenant) 也省略 tenant claim（needs_tenant=false）。
        for kind in [PrincipalKind::SuperAdmin, PrincipalKind::Service] {
            let alg = if matches!(kind, PrincipalKind::Service) {
                JwtAlg::Hs256
            } else {
                JwtAlg::Es256
            };
            let issuer = issuer_with(
                RecordingSigner::ok(),
                now_time(),
                alg,
                "p",
                Duration::from_secs(3600),
            );
            let jwt = issuer
                .issue("subject", Some(tenant()), kind)
                .await
                .expect("issue ok");
            let claims = decode_segment(&segments(&jwt)[1]);
            assert!(
                claims.get("tenant_id").is_none(),
                "kind={kind:?} 跨租户须省略 tenant claim（即便传入 Some）"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_rejects_alg_kind_scheme_mismatch() {
        // F2：ES256 限 user/device/admin/super、HS256 限 service；错配 fail-closed、signer 不被调用
        // （验签侧 `verify_credential` 把 Jwt→ES256 / ServiceToken→HS256 锁死）。
        for (alg, kind) in [
            (JwtAlg::Es256, PrincipalKind::Service), // ES256 签 service-token kind → 错配
            (JwtAlg::Hs256, PrincipalKind::User),    // HS256 签 jwt kind → 错配
            (JwtAlg::Hs256, PrincipalKind::Admin),
        ] {
            let signer = RecordingSigner::ok();
            let issuer = issuer_with(
                signer.clone(),
                now_time(),
                alg,
                "p",
                Duration::from_secs(3600),
            );
            // scoped kind 给 tenant 排除 MissingTenant 干扰，确保命中 AlgKindMismatch。
            let tenant_arg = if needs_tenant(kind) {
                Some(tenant())
            } else {
                None
            };
            let err = issuer
                .issue("subject", tenant_arg, kind)
                .await
                .expect_err("alg↔kind 错配须 fail-closed");
            assert!(
                matches!(err, JwtIssueError::AlgKindMismatch),
                "alg={alg:?} kind={kind:?}"
            );
            assert!(
                signer.captured().is_none(),
                "alg={alg:?} kind={kind:?} signer 不被调用"
            );
        }
    }

    #[test]
    fn issuer_and_issue_future_are_send_sync() {
        // F3（DIPORT-ASYNC-ARC-SEND-01 mint 落地）：JwtIssuer<S> 可作共享 handler state（Arc<JwtIssuer>
        // 需 Send+Sync），且 issue().await future 须 Send（axum handler 要求）。`Box<DynSigner>`（非 Sync）
        // 持有者会破此断言——anti-vacuity。
        fn assert_send<T: Send>(_: T) {}
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let issuer = issuer_with(
            RecordingSigner::ok(),
            now_time(),
            JwtAlg::Es256,
            "p",
            Duration::from_secs(3600),
        );
        assert_send_sync(&issuer);
        assert_send(issuer.issue("u", None, PrincipalKind::SuperAdmin));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_passes_signing_input_key_purpose_to_signer() {
        let signer = RecordingSigner::ok();
        let issuer = issuer_with(
            signer.clone(),
            now_time(),
            JwtAlg::Es256,
            "auth.jwt.access",
            Duration::from_secs(3600),
        );
        let jwt = issuer
            .issue("user-123", Some(tenant()), PrincipalKind::User)
            .await
            .expect("issue ok");

        let captured = signer.captured().expect("signer 被调用一次");
        assert_eq!(captured.key.as_str(), "test-key");
        assert_eq!(captured.purpose.as_str(), "auth.jwt.access");
        // 签名 message == signing input == 段0.段1
        let parts = segments(&jwt);
        let expected_input = format!("{}.{}", parts[0], parts[1]);
        assert_eq!(captured.message.as_bytes(), expected_input.as_bytes());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_es256_header_alg_and_purpose() {
        let signer = RecordingSigner::ok();
        let issuer = issuer_with(
            signer.clone(),
            now_time(),
            JwtAlg::Es256,
            "auth.jwt.es256",
            Duration::from_secs(3600),
        );
        let jwt = issuer
            .issue("u", Some(tenant()), PrincipalKind::User)
            .await
            .expect("issue ok");
        let header = decode_segment(&segments(&jwt)[0]);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(
            signer.captured().expect("called").purpose.as_str(),
            "auth.jwt.es256",
            "ES256 路径 purpose 透传（OIDC-ALG-KEYPATH-01 镜像）"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_hs256_header_alg_and_purpose() {
        let signer = RecordingSigner::ok();
        let issuer = issuer_with(
            signer.clone(),
            now_time(),
            JwtAlg::Hs256,
            "auth.svc.hs256",
            Duration::from_secs(3600),
        );
        // service-token 路径：跨租户、无 tenant claim。
        let jwt = issuer
            .issue("svc-acct", None, PrincipalKind::Service)
            .await
            .expect("issue ok");
        let header = decode_segment(&segments(&jwt)[0]);
        assert_eq!(header["alg"], "HS256");
        assert_eq!(
            signer.captured().expect("called").purpose.as_str(),
            "auth.svc.hs256"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_exp_is_iat_plus_ttl() {
        let issuer = issuer_with(
            RecordingSigner::ok(),
            now_time(),
            JwtAlg::Es256,
            "p",
            Duration::from_secs(1800),
        );
        let jwt = issuer
            .issue("u", Some(tenant()), PrincipalKind::User)
            .await
            .expect("issue ok");
        let claims = decode_segment(&segments(&jwt)[1]);
        assert_eq!(claims["iat"].as_u64(), Some(NOW_SECS));
        assert_eq!(claims["exp"].as_u64(), Some(NOW_SECS + 1800));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_fails_closed_clock_before_epoch() {
        let signer = RecordingSigner::ok();
        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
        let issuer = issuer_with(
            signer.clone(),
            before,
            JwtAlg::Es256,
            "p",
            Duration::from_secs(3600),
        );
        let err = issuer
            .issue("u", Some(tenant()), PrincipalKind::User)
            .await
            .expect_err("clock < epoch 须 fail-closed");
        assert!(matches!(err, JwtIssueError::ClockBeforeEpoch));
        assert!(signer.captured().is_none(), "签名前短路，signer 不被调用");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_fails_closed_on_expiry_overflow() {
        let signer = RecordingSigner::ok();
        // ttl 秒数超出 i64 → i64::try_from 失败 → ExpiryOverflow（不触 SystemTime 溢出 panic）。
        let issuer = issuer_with(
            signer.clone(),
            now_time(),
            JwtAlg::Es256,
            "p",
            Duration::from_secs(u64::MAX),
        );
        let err = issuer
            .issue("u", Some(tenant()), PrincipalKind::User)
            .await
            .expect_err("exp 溢出须 fail-closed");
        assert!(matches!(err, JwtIssueError::ExpiryOverflow));
        assert!(signer.captured().is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_propagates_signer_failure() {
        let issuer = issuer_with(
            RecordingSigner::failing(),
            now_time(),
            JwtAlg::Es256,
            "p",
            Duration::from_secs(3600),
        );
        let err = issuer
            .issue("u", Some(tenant()), PrincipalKind::User)
            .await
            .expect_err("signer 失败须传播");
        assert!(matches!(err, JwtIssueError::Sign(_)));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_super_admin_omits_tenant_claim() {
        let issuer = issuer_with(
            RecordingSigner::ok(),
            now_time(),
            JwtAlg::Es256,
            "p",
            Duration::from_secs(3600),
        );
        // super-admin 跨租户：无 tenant claim。
        let jwt = issuer
            .issue("root", None, PrincipalKind::SuperAdmin)
            .await
            .expect("issue ok");
        let claims = decode_segment(&segments(&jwt)[1]);
        assert!(
            claims.get("tenant_id").is_none(),
            "super-admin 省略 tenant claim"
        );
        assert_eq!(claims["kind"], "superAdmin");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_scoped_kinds_include_tenant() {
        for (kind, expected_kind) in [
            (PrincipalKind::User, "user"),
            (PrincipalKind::Device, "device"),
            (PrincipalKind::Admin, "admin"),
        ] {
            let issuer = issuer_with(
                RecordingSigner::ok(),
                now_time(),
                JwtAlg::Es256,
                "p",
                Duration::from_secs(3600),
            );
            let jwt = issuer
                .issue("subject", Some(tenant()), kind)
                .await
                .expect("issue ok");
            let claims = decode_segment(&segments(&jwt)[1]);
            assert_eq!(claims["tenant_id"], CANON_TENANT, "kind={kind:?}");
            assert_eq!(claims["kind"], expected_kind, "kind={kind:?}");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_fails_closed_on_empty_subject() {
        let signer = RecordingSigner::ok();
        let issuer = issuer_with(
            signer.clone(),
            now_time(),
            JwtAlg::Es256,
            "p",
            Duration::from_secs(3600),
        );
        let err = issuer
            .issue("", Some(tenant()), PrincipalKind::User)
            .await
            .expect_err("空 subject 须 fail-closed");
        assert!(matches!(err, JwtIssueError::EmptySubject));
        assert!(signer.captured().is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_fails_closed_scoped_kind_without_tenant() {
        for kind in [
            PrincipalKind::User,
            PrincipalKind::Device,
            PrincipalKind::Admin,
        ] {
            let signer = RecordingSigner::ok();
            let issuer = issuer_with(
                signer.clone(),
                now_time(),
                JwtAlg::Es256,
                "p",
                Duration::from_secs(3600),
            );
            let err = issuer
                .issue("subject", None, kind)
                .await
                .expect_err("scoped 主体缺 tenant 须 fail-closed");
            assert!(matches!(err, JwtIssueError::MissingTenant), "kind={kind:?}");
            assert!(signer.captured().is_none(), "kind={kind:?}");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn issue_fails_closed_on_anonymous_kind() {
        let signer = RecordingSigner::ok();
        let issuer = issuer_with(
            signer.clone(),
            now_time(),
            JwtAlg::Es256,
            "p",
            Duration::from_secs(3600),
        );
        let err = issuer
            .issue("subject", None, PrincipalKind::Anonymous)
            .await
            .expect_err("anonymous 不可签发");
        assert!(matches!(err, JwtIssueError::KindNotIssuable));
        assert!(signer.captured().is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn minted_jwt_debug_is_redacted() {
        let issuer = issuer_with(
            RecordingSigner::ok(),
            now_time(),
            JwtAlg::Es256,
            "p",
            Duration::from_secs(3600),
        );
        let jwt = issuer
            .issue("subject-secret", Some(tenant()), PrincipalKind::User)
            .await
            .expect("issue ok");
        let dbg = format!("{jwt:?}");
        assert_eq!(dbg, "MintedJwt(<redacted>)");
        assert!(!dbg.contains(jwt.as_str()), "Debug 不泄露 token 串");
    }

    #[test]
    fn jwt_alg_jose_strings() {
        // 锁 JOSE 字面量；anti-vacuity：alg=none / RS256 在 [`JwtAlg`] 类型层不可表达。
        assert_eq!(JwtAlg::Es256.as_jose(), "ES256");
        assert_eq!(JwtAlg::Hs256.as_jose(), "HS256");
    }

    #[test]
    fn jwt_issue_error_messages_are_const_and_source_redacted() {
        assert_eq!(
            JwtIssueError::InvalidConfig.to_string(),
            "jwt issuer config is invalid"
        );
        assert_eq!(
            JwtIssueError::EmptySubject.to_string(),
            "jwt subject must not be empty"
        );
        assert_eq!(
            JwtIssueError::MissingTenant.to_string(),
            "scoped principal kind requires a tenant"
        );
        assert_eq!(
            JwtIssueError::KindNotIssuable.to_string(),
            "principal kind is not issuable as a jwt"
        );
        assert_eq!(
            JwtIssueError::AlgKindMismatch.to_string(),
            "jwt alg does not match principal kind scheme"
        );
        assert_eq!(
            JwtIssueError::ClockBeforeEpoch.to_string(),
            "clock is before unix epoch"
        );
        assert_eq!(
            JwtIssueError::ExpiryOverflow.to_string(),
            "jwt expiry computation overflowed"
        );
        // Sign 变体 source 经 SignerError RedactedSource 脱敏：Display/Debug 均不含泄漏 marker。
        let err = JwtIssueError::Sign(SignerError::new(std::io::Error::other("leak-marker")));
        assert_eq!(err.to_string(), "jwt signing failed");
        assert!(!format!("{err:?}").contains("leak-marker"));
    }
}
