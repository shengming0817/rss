//! 验签编排：scheme dispatch → 三段解析（[`crate::jws`]）→ alg-key 路径隔离闸 → 签名/MAC 校验（ES256 = p256
//! ecdsa / HS256 = hmac+sha2 常数时间）→ claim 校验（[`crate::claims`]）→ `VerifiedClaims`。失败 fail-closed
//! 归类 [`PdpError`]，PII 边界：只记 reason 闭值标签 + keys_tried 计数，**绝不**记 token / 签名 / claim 值。
//!
//! 路径隔离（INVARIANT: OIDC-ALG-KEYPATH-01， { level = "Medium", exec = "manual/opt-in", source = "code" }防 alg-confusion）：JWT scheme 只走 ES256 + ES256 key 集；
//! ServiceToken scheme 只走 HS256 + HS256 key 集。token header `alg` 必须匹配 scheme 选定路径的算法，否则
//! `Untrusted`（杜绝攻击者把 HS256 token 拿 ES256 公钥当 HMAC 密钥伪造、或反之）。
//!
//! ref: RustCrypto/elliptic-curves p256 ecdsa（`VerifyingKey::verify` 内部 SHA-256 prehash + 定长 r‖s 签名）；
//! RustCrypto/MACs hmac（`Hmac<Sha256>` MAC）；spiffe/rust-spiffe JWT-SVID 验签链（解析→选 key→验签→校 claim）。

use diport::{
    Clock, PdpError, RawCredential, ServiceTokenReplayStore as _, TokenAlgorithm, TokenProfile,
    TokenProfileMarker, VerifiedClaims,
};
use hmac::{Hmac, Mac};
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;
use sha2::Sha256;

use crate::claims;
use crate::config::{KeySet, VerifierConfig};
use crate::jws::{self, Jws, JwsError, SupportedAlg};

/// tracing `target:` / `resource =` 固定标签（同义串 ≥3 次抽 const，rust-standards §护栏）。
pub(crate) const LOG_TARGET: &str = "oidc";

type HmacSha256 = Hmac<Sha256>;

/// Exhaustive, low-cardinality telemetry reason. Runtime data can never become a metric/log label.
#[derive(Clone, Copy)]
pub(crate) enum TelemetryReason {
    ProfileMismatch,
    MissingTenantBinding,
    TypProfileMismatch,
    AlgProfileMismatch,
    KidNoCandidate,
    BadSignature,
    ReplayScopeInvalid,
    MissingReplayStore,
    ReplayDeadlineInvalid,
    TokenReplayed,
    ReplayUnavailable,
    MalformedToken,
    TokenTooLarge,
    UnsupportedAlg,
    MissingJti,
    MalformedOrMissingClaim,
    ClockBeforeEpoch,
    TokenUseProfileMismatch,
    UntrustedIssuer,
    UntrustedAudience,
    EmptySubject,
    InvalidExpiryBoundary,
    KindMissingOrUntrusted,
    ScopedPrincipalMissingTenant,
    TenantNotCanonical,
    SuperAdminHasTenant,
    UnsupportedPrincipalKind,
    ServiceKindInvalid,
    ServiceTenantClaimForbidden,
    IatAfterExp,
    IatInFuture,
    MaximumLifetimeExceeded,
    Expired,
    NotYetValid,
}

impl TelemetryReason {
    const fn label(self) -> &'static str {
        match self {
            Self::ProfileMismatch => "profile_mismatch",
            Self::MissingTenantBinding => "missing_tenant_binding",
            Self::TypProfileMismatch => "typ_profile_mismatch",
            Self::AlgProfileMismatch => "alg_profile_mismatch",
            Self::KidNoCandidate => "kid_no_candidate",
            Self::BadSignature => "bad_signature",
            Self::ReplayScopeInvalid => "replay_scope_invalid",
            Self::MissingReplayStore => "missing_replay_store",
            Self::ReplayDeadlineInvalid => "replay_store_deadline_invalid",
            Self::TokenReplayed => "token_replayed",
            Self::ReplayUnavailable => "replay_store_unavailable",
            Self::MalformedToken => "malformed_token",
            Self::TokenTooLarge => "token_too_large",
            Self::UnsupportedAlg => "unsupported_alg",
            Self::MissingJti => "missing_jti",
            Self::MalformedOrMissingClaim => "malformed_or_missing_claim",
            Self::ClockBeforeEpoch => "clock_before_epoch",
            Self::TokenUseProfileMismatch => "token_use_profile_mismatch",
            Self::UntrustedIssuer => "untrusted_issuer",
            Self::UntrustedAudience => "untrusted_audience",
            Self::EmptySubject => "empty_subject",
            Self::InvalidExpiryBoundary => "invalid_expiry_boundary",
            Self::KindMissingOrUntrusted => "kind_missing_or_untrusted",
            Self::ScopedPrincipalMissingTenant => "scoped_principal_missing_tenant",
            Self::TenantNotCanonical => "tenant_not_canonical",
            Self::SuperAdminHasTenant => "super_admin_has_tenant",
            Self::UnsupportedPrincipalKind => "unsupported_principal_kind",
            Self::ServiceKindInvalid => "service_kind_invalid",
            Self::ServiceTenantClaimForbidden => "service_tenant_claim_forbidden",
            Self::IatAfterExp => "iat_after_exp",
            Self::IatInFuture => "iat_in_future",
            Self::MaximumLifetimeExceeded => "maximum_lifetime_exceeded",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
        }
    }
}

/// `Pdp::verify` 入口：scheme dispatch → 验签 → claim 映射 → durable replay consume。
pub(crate) async fn verify_credential<P: TokenProfileMarker>(
    config: &VerifierConfig<P>,
    clock: &dyn Clock,
    raw: &RawCredential,
) -> Result<VerifiedClaims, PdpError> {
    if raw.profile() != P::PROFILE {
        log_fail_without_keys(TelemetryReason::ProfileMismatch);
        return Err(PdpError::Untrusted);
    }
    match P::PROFILE {
        TokenProfile::RssAccess | TokenProfile::FederatedAccess => {
            verify_path(config, clock, raw.token(), None).await
        }
        TokenProfile::ServiceToken => verify_service_token_path(config, clock, raw).await,
    }
}

async fn verify_service_token_path<P: TokenProfileMarker>(
    config: &VerifierConfig<P>,
    clock: &dyn Clock,
    raw: &RawCredential,
) -> Result<VerifiedClaims, PdpError> {
    let Some(binding) = raw.service_token_tenant() else {
        log_fail_without_keys(TelemetryReason::MissingTenantBinding);
        return Err(PdpError::InvalidSignature);
    };
    verify_path(config, clock, raw.token(), Some(binding)).await
}

/// 单路径验签：解析 → 路径隔离闸 → 签名校验 → claim 校验。`expected` = 本 scheme 路径锁定的算法。
async fn verify_path<P: TokenProfileMarker>(
    config: &VerifierConfig<P>,
    clock: &dyn Clock,
    token: &str,
    service_token_binding: Option<&diport::ServiceTokenTenantBinding>,
) -> Result<VerifiedClaims, PdpError> {
    let profile = raw_profile_for_config(config);
    let policy = profile.policy();
    let expected = match policy.algorithm() {
        TokenAlgorithm::Es256 => SupportedAlg::Es256,
        TokenAlgorithm::Hs256 => SupportedAlg::Hs256,
    };
    let jws = jws::parse(token, policy).map_err(classify_parse)?;
    if jws.typ != policy.jose_typ() {
        log_fail_without_keys(TelemetryReason::TypProfileMismatch);
        return Err(PdpError::Untrusted);
    }
    // 取当前 key 快照（静态不变 / JWKS 文件源后台刷新的最新；Arc clone 同步零撕裂）。
    let snapshot = config.keys().snapshot();
    // alg-key 路径隔离闸（OIDC-ALG-KEYPATH-01）：token alg 必须匹配 scheme 路径算法，否则 confusion → Untrusted。
    if jws.alg != expected {
        log_fail(TelemetryReason::AlgProfileMismatch, &snapshot);
        return Err(PdpError::Untrusted);
    }
    // kid 缩小候选集（JWKS 轮转按 id 选 key；无 kid → untagged 盲扫）。kid 是 hint、非信任根——下方仍须签名校验。
    let kid = jws.kid.as_str();
    match match expected {
        SupportedAlg::Es256 => verify_es256(&snapshot, kid, &jws),
        SupportedAlg::Hs256 => match service_token_binding {
            Some(binding) => verify_hs256(&snapshot, kid, &jws, binding),
            None => VerifyOutcome::BadSignature,
        },
    } {
        VerifyOutcome::Verified => {}
        VerifyOutcome::NoCandidate => {
            // kid 不在当前快照（未知 / JWKS 轮转出）→ 签名 key 不在受信集 → `Untrusted`（区别于签名结构坏的
            // `InvalidSignature`；同 iss/aud 不受信，spec R2 / SC-005：kid 无匹配 → Untrusted）。
            log_fail(TelemetryReason::KidNoCandidate, &snapshot);
            return Err(PdpError::Untrusted);
        }
        VerifyOutcome::BadSignature => {
            log_fail(TelemetryReason::BadSignature, &snapshot);
            return Err(PdpError::InvalidSignature);
        }
    }
    // 签名通过 → 校 claim 语义（exp/nbf 经注入 Clock + iss/aud/sub）。
    match expected {
        SupportedAlg::Es256 => claims::validate_and_map(config, clock, &jws.payload),
        SupportedAlg::Hs256 => {
            let (claims, token_id, expires_at) =
                claims::validate_service_token_and_map(config, clock, &jws.payload)?;
            let replay_key =
                diport::ServiceTokenReplayKey::derive(diport::ServiceTokenReplayScope {
                    issuer: config.issuer(),
                    audience: config.audience(),
                    key_id: &jws.kid,
                    token_id: &token_id,
                })
                .map_err(|_| {
                    log_fail(TelemetryReason::ReplayScopeInvalid, &snapshot);
                    PdpError::InvalidSignature
                })?;
            let Some((store, timeout)) = config.service_token_replay_store() else {
                log_fail(TelemetryReason::MissingReplayStore, &snapshot);
                return Err(PdpError::Untrusted);
            };
            let deadline =
                diport::ServiceTokenReplayDeadline::from_timeout(timeout).map_err(|_| {
                    log_fail(TelemetryReason::ReplayDeadlineInvalid, &snapshot);
                    PdpError::ProviderUnavailable
                })?;
            match store
                .check_and_record(&replay_key, expires_at, deadline)
                .await
            {
                Ok(diport::ServiceTokenReplayDisposition::Recorded) => Ok(claims),
                Ok(diport::ServiceTokenReplayDisposition::Replayed) => {
                    log_fail(TelemetryReason::TokenReplayed, &snapshot);
                    Err(PdpError::InvalidSignature)
                }
                Err(diport::ServiceTokenReplayStoreError::Unavailable) => {
                    log_fail(TelemetryReason::ReplayUnavailable, &snapshot);
                    Err(PdpError::ProviderUnavailable)
                }
            }
        }
    }
}

fn raw_profile_for_config<P: TokenProfileMarker>(_config: &VerifierConfig<P>) -> TokenProfile {
    P::PROFILE
}

/// 单路径验签三态（区分 fail-closed 语义）：候选为空 = kid 不在受信集（未知 / 轮转出）→ `Untrusted`；候选存在
/// 但无一匹配 / 签名结构坏 → `InvalidSignature`。
enum VerifyOutcome {
    /// 某候选 key 验签通过。
    Verified,
    /// 该 kid 在当前快照无候选 key（fail-closed → `Untrusted`）。
    NoCandidate,
    /// 有候选但无一匹配，或签名结构非法（fail-closed → `InvalidSignature`）。
    BadSignature,
}

/// ES256（P-256 ECDSA）签名校验：定长 r‖s 签名 + 逐**候选** ES256 公钥试验（按 `kid` 过滤，见
/// [`KeySet::es256_candidates`]——支持 JWKS kid 轮转 + 静态多 key）。`VerifyingKey::verify` 内部对 signing input
/// 做 SHA-256 prehash（非预 hash 输入）。
fn verify_es256(keys: &KeySet, kid: &str, jws: &Jws) -> VerifyOutcome {
    let Ok(sig) = Signature::from_slice(&jws.signature) else {
        // 签名非定长 64 字节 r‖s（含空签名 / DER 形态）→ 结构坏 → InvalidSignature。
        return VerifyOutcome::BadSignature;
    };
    let mut had_candidate = false;
    for vk in keys.es256_candidates(kid) {
        had_candidate = true;
        if vk.verify(&jws.signing_input, &sig).is_ok() {
            return VerifyOutcome::Verified;
        }
    }
    if had_candidate {
        VerifyOutcome::BadSignature
    } else {
        VerifyOutcome::NoCandidate
    }
}

/// HS256（HMAC-SHA256）MAC 校验：逐**候选** HS256 密钥算 tag + 常数时间比对（复用
/// `primitives::crypto::constant_time_eq`，CRYPTO-CONST-TIME-01；候选按 `kid` 过滤）。候选为空 → `NoCandidate`。
fn verify_hs256(
    keys: &KeySet,
    kid: &str,
    jws: &Jws,
    binding: &diport::ServiceTokenTenantBinding,
) -> VerifyOutcome {
    let mac_input = diport::service_token_mac_input(&jws.signing_input, binding);
    let mut had_candidate = false;
    for secret in keys.hs256_candidates(kid) {
        had_candidate = true;
        if hs256_tag_matches(secret, &mac_input, &jws.signature) {
            return VerifyOutcome::Verified;
        }
    }
    if had_candidate {
        VerifyOutcome::BadSignature
    } else {
        VerifyOutcome::NoCandidate
    }
}

/// 单密钥 HS256 tag 比对（常数时间）。
fn hs256_tag_matches(secret: &[u8], signing_input: &[u8], signature: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        // HMAC 接受任意长度 key（new_from_slice 对 HMAC 不会失败）；本支理论不可达，fail-closed。
        return false;
    };
    mac.update(signing_input);
    let tag = mac.finalize().into_bytes();
    // 长度不等时 constant_time_eq 返回 false（subtle 语义）；防短签名截断绕过。
    primitives::crypto::constant_time_eq(tag.as_slice(), signature)
}

/// 解析错误归类：畸形 / 不支持算法（含 `alg:none`、RS*）均 → `InvalidSignature`（token 不可用，401 invalid_token）。
/// 与 `Untrusted`（iss/aud 不受信、alg-scheme 混淆）同归 401，但语义分层：此处凭据**结构**坏，`Untrusted` 是**来源**不受信（#1229）。
fn classify_parse(err: JwsError) -> PdpError {
    let reason = match err {
        JwsError::Malformed => TelemetryReason::MalformedToken,
        JwsError::TooLarge => TelemetryReason::TokenTooLarge,
        JwsError::UnsupportedAlg => TelemetryReason::UnsupportedAlg,
    };
    tracing::warn!(
        target: LOG_TARGET,
        resource = LOG_TARGET,
        reason = reason.label(),
        "oidc credential parse failed"
    );
    PdpError::InvalidSignature
}

fn log_fail_without_keys(reason: TelemetryReason) {
    tracing::warn!(
        target: LOG_TARGET,
        resource = LOG_TARGET,
        reason = reason.label(),
        "oidc credential verification failed"
    );
}

/// 脱敏失败日志：reason 闭值标签 + keys_tried 计数（**不**记 token / 签名 / claim / key 材料）。
fn log_fail(reason: TelemetryReason, keys: &KeySet) {
    tracing::warn!(
        target: LOG_TARGET,
        resource = LOG_TARGET,
        reason = reason.label(),
        es256_keys = keys.es256_len(),
        hs256_keys = keys.hs256_len(),
        "oidc credential verification failed"
    );
}

pub(crate) fn log_claim_fail(reason: TelemetryReason) {
    tracing::warn!(
        target: LOG_TARGET,
        resource = LOG_TARGET,
        reason = reason.label(),
        "oidc jwt claim validation failed"
    );
}

#[cfg(test)]
mod tests {
    //! 表驱动验签矩阵 + RFC7515 known-answer + PII 边界回归。
    //! 测试 expect/unwrap carve-out 按 error-handling.md §Carve-out 用 **item-level** `#[allow]` 逐 fn 标注。
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use diport::{Clock, PdpError, RawCredential, ServiceTokenTenantBinding};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

    use super::{
        VerifyOutcome, hs256_tag_matches, verify_credential as verify_credential_async,
        verify_es256,
    };
    use crate::config::{
        AccessStaticKeySource, ServiceTokenKeySource, VerifierConfig, VerifierConfigBuilder,
    };
    use crate::jws::{Jws, SupportedAlg};

    const ISS: &str = "https://issuer.example";
    const AUD: &str = "rss-api";
    const FEDERATED_ISS: &str = "https://federation.example";
    const FEDERATED_AUD: &str = "rss-federated-api";
    const SERVICE_ISS: &str = "https://service-issuer.example";
    const SERVICE_AUD: &str = "rss-service-api";
    /// 固定 "now"（2023-11-14T22:13:20Z）——确定性时间边界，绝不取系统时钟。
    const NOW: i64 = 1_700_000_000;
    /// 一次性测试 EC 私钥标量（固定字节，valid scalar < n；**仅测试 fixture，永非生产 key**）。
    const TEST_SK_BYTES: [u8; 32] = [0x42; 32];
    const TEST_SK2_BYTES: [u8; 32] = [0x11; 32];
    /// HS256 测试共享密钥（service-token 路径 fixture）。
    const HS_SECRET: &[u8] = b"unit-test-hs256-shared-secret-0001";
    const HS_KID: &str = "cell-a.svc-a";
    const HS_KID2: &str = "cell-a.svc-b";
    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const OTHER_TENANT: &str = "11111111-2222-4333-8444-555555555555";

    #[derive(Default)]
    struct TestReplayStore {
        seen: Mutex<HashSet<[u8; 32]>>,
    }

    impl diport::ServiceTokenReplayStore for TestReplayStore {
        async fn check_and_record(
            &self,
            key: &diport::ServiceTokenReplayKey,
            _expires_at: SystemTime,
            _deadline: diport::ServiceTokenReplayDeadline,
        ) -> Result<diport::ServiceTokenReplayDisposition, diport::ServiceTokenReplayStoreError>
        {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| diport::ServiceTokenReplayStoreError::Unavailable)?;
            if !seen.insert(*key.digest_bytes()) {
                return Ok(diport::ServiceTokenReplayDisposition::Replayed);
            }
            Ok(diport::ServiceTokenReplayDisposition::Recorded)
        }
    }

    fn replay_store() -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        diport::DynServiceTokenReplayStore::new_arc(TestReplayStore::default())
    }

    struct CountingReplayStore {
        calls: Arc<AtomicUsize>,
    }

    impl diport::ServiceTokenReplayStore for CountingReplayStore {
        async fn check_and_record(
            &self,
            _key: &diport::ServiceTokenReplayKey,
            _expires_at: SystemTime,
            _deadline: diport::ServiceTokenReplayDeadline,
        ) -> Result<diport::ServiceTokenReplayDisposition, diport::ServiceTokenReplayStoreError>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(diport::ServiceTokenReplayDisposition::Recorded)
        }
    }

    struct UnavailableReplayStore;

    impl diport::ServiceTokenReplayStore for UnavailableReplayStore {
        async fn check_and_record(
            &self,
            _key: &diport::ServiceTokenReplayKey,
            _expires_at: SystemTime,
            _deadline: diport::ServiceTokenReplayDeadline,
        ) -> Result<diport::ServiceTokenReplayDisposition, diport::ServiceTokenReplayStoreError>
        {
            tokio::task::yield_now().await;
            Err(diport::ServiceTokenReplayStoreError::Unavailable)
        }
    }

    #[allow(clippy::expect_used)]
    fn verify_credential<P: diport::TokenProfileMarker>(
        config: &VerifierConfig<P>,
        clock: &dyn Clock,
        raw: &RawCredential,
    ) -> Result<diport::VerifiedClaims, PdpError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(verify_credential_async(config, clock, raw))
    }

    /// 确定性 tracing 捕获（PII 回归测试用）。`cargo test`（非进程隔离的 nextest）多测试共进程：先跑的、
    /// 无 subscriber 的测试会把 warn/debug callsite 的 interest 缓存成 `never`，事件宏短路、不再咨询后装的
    /// thread-local subscriber（`with_default` + `rebuild_interest_cache` 对此无效——后者按全局默认重建）。
    /// 解法：进程级 `Once` 装一个**全局**默认 fmt subscriber（`set_global_default` 内部按本 subscriber 重建
    /// interest → callsite 恒 enabled、永不被缓存成 never），事件按**当前线程**写线程本地缓冲（各测试线程
    /// 隔离、互不串扰）。测试读自己线程的缓冲即可确定性断言。
    mod capture {
        use std::cell::RefCell;
        use std::io::Write;
        use std::sync::Once;

        use tracing_subscriber::fmt::MakeWriter;

        thread_local! {
            static BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        }

        /// 把事件字节写入**当前线程**的捕获缓冲。
        struct ThreadLocalWriter;
        impl Write for ThreadLocalWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                BUF.with(|b| b.borrow_mut().extend_from_slice(buf));
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for ThreadLocalWriter {
            type Writer = ThreadLocalWriter;
            fn make_writer(&'a self) -> Self::Writer {
                ThreadLocalWriter
            }
        }

        static INSTALL: Once = Once::new();

        /// 幂等装全局捕获 subscriber（仅首次真正 `set_global_default`；本 crate 测试无其它全局 subscriber，
        /// 故必成功）。失败也不静默放过——`captured()` 后的 `!is_empty()` 断言会暴露捕获未生效。
        pub(super) fn install() {
            INSTALL.call_once(|| {
                let subscriber = tracing_subscriber::fmt()
                    .with_writer(ThreadLocalWriter)
                    .with_max_level(tracing::Level::DEBUG)
                    .finish();
                let _ = tracing::subscriber::set_global_default(subscriber);
            });
        }

        /// 清空当前线程缓冲（每次捕获前调）。
        pub(super) fn reset() {
            BUF.with(|b| b.borrow_mut().clear());
        }

        /// 取当前线程已捕获的 UTF-8 日志。
        #[allow(clippy::expect_used)]
        pub(super) fn captured() -> String {
            BUF.with(|b| String::from_utf8(b.borrow().clone()).expect("utf8"))
        }
    }

    /// 注入时钟替身：固定 UNIX 秒（非系统时钟，确定性 exp/nbf 边界）。
    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(self.0 as u64)
        }
    }

    #[allow(clippy::expect_used)]
    fn test_sk() -> SigningKey {
        SigningKey::from_slice(&TEST_SK_BYTES).expect("valid P-256 scalar")
    }
    #[allow(clippy::expect_used)]
    fn test_sk2() -> SigningKey {
        SigningKey::from_slice(&TEST_SK2_BYTES).expect("valid P-256 scalar")
    }
    /// SigningKey → SEC1 未压缩点（注入 AccessStaticKeySource）。
    fn sec1_of(sk: &SigningKey) -> Vec<u8> {
        sk.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    #[allow(clippy::expect_used)]
    fn es256_config_with(keys: AccessStaticKeySource) -> VerifierConfig<diport::RssAccessProfile> {
        VerifierConfigBuilder::<diport::RssAccessProfile>::new(ISS, AUD)
            .keys_static(keys)
            .trust_kind("user")
            .build()
            .expect("valid es256 config")
    }
    #[allow(clippy::expect_used)]
    fn es256_config() -> VerifierConfig<diport::RssAccessProfile> {
        let keys = AccessStaticKeySource::builder()
            .add_es256_sec1("test-es256", &sec1_of(&test_sk()))
            .expect("es256 key")
            .build();
        es256_config_with(keys)
    }
    #[allow(clippy::expect_used)]
    fn federated_es256_config() -> VerifierConfig<diport::FederatedAccessProfile> {
        let keys = AccessStaticKeySource::builder()
            .add_es256_sec1("test-es256", &sec1_of(&test_sk2()))
            .expect("federated es256 key")
            .build();
        VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(FEDERATED_ISS, FEDERATED_AUD)
            .keys_static(keys)
            .trust_kind("user")
            .build()
            .expect("valid federated es256 config")
    }
    #[allow(clippy::expect_used)]
    fn hs256_config() -> VerifierConfig<diport::ServiceTokenProfile> {
        let keys = ServiceTokenKeySource::builder()
            .add_hs256_secret(HS_KID, HS_SECRET)
            .expect("hs256 secret")
            .build();
        VerifierConfigBuilder::<diport::ServiceTokenProfile>::new(ISS, AUD)
            .keys_hs256(keys)
            .replay_store(replay_store(), Duration::from_secs(5))
            .build()
            .expect("valid hs256 config")
    }
    #[allow(clippy::expect_used)]
    fn matrix_hs256_config() -> VerifierConfig<diport::ServiceTokenProfile> {
        let keys = ServiceTokenKeySource::builder()
            .add_hs256_secret(HS_KID, HS_SECRET)
            .expect("hs256 secret")
            .build();
        VerifierConfigBuilder::<diport::ServiceTokenProfile>::new(SERVICE_ISS, SERVICE_AUD)
            .keys_hs256(keys)
            .replay_store(replay_store(), Duration::from_secs(5))
            .build()
            .expect("valid matrix hs256 config")
    }

    /// 拼 JWT payload JSON（sub=alice + exp/iss/aud + 任意 extra 片段，如 `,"tenant_id":"t1"`）。
    fn payload(exp: i64, iss: &str, aud: &str, extra: &str) -> String {
        let service = extra.contains(r#""kind":"service""#);
        let exp = if service { exp.min(NOW + 300) } else { exp };
        let token_use = if service { "service" } else { "access" };
        let kind = if extra.contains(r#""kind":"#) {
            ""
        } else {
            r#","kind":"user""#
        };
        let tenant = if service
            || extra.contains(r#""tenant_id":"#)
            || extra.contains(r#""kind":"superAdmin""#)
        {
            ""
        } else {
            r#","tenant_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479""#
        };
        let iat = exp.saturating_sub(if service { 300 } else { 600 });
        format!(
            r#"{{"sub":"alice","iat":{iat},"exp":{exp},"token_use":"{token_use}","iss":"{iss}","aud":"{aud}"{kind}{tenant}{extra}}}"#
        )
    }

    /// 用 ES256 私钥签发 token（header alg=ES256）。RFC6979 确定性签名，无需 RNG。
    fn mint_es256(sk: &SigningKey, payload_json: &str) -> String {
        let header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"test-es256"}"#);
        let body = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header}.{body}");
        let sig: Signature = sk.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
    /// 用 HS256 共享密钥签发 token（header alg=HS256）。
    #[allow(clippy::expect_used)]
    fn mint_hs256(secret: &[u8], payload_json: &str) -> String {
        mint_hs256_with_kid(secret, HS_KID, payload_json)
    }

    #[allow(clippy::expect_used)]
    fn mint_hs256_with_kid(secret: &[u8], kid: &str, payload_json: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let header = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"alg":"HS256","typ":"rss-service+jwt","kid":"{kid}"}}"#
        ));
        let body = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header}.{body}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
        mac.update(signing_input.as_bytes());
        let tag = mac.finalize().into_bytes();
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(tag))
    }

    #[allow(clippy::expect_used)]
    fn tenant_binding(raw: &str) -> ServiceTokenTenantBinding {
        ServiceTokenTenantBinding::new(vocab::tenant::TenantId::parse(raw).expect("tenant"))
    }

    #[allow(clippy::expect_used)]
    fn mint_hs256_bound(secret: &[u8], payload_json: &str, tenant: &str) -> String {
        mint_hs256_bound_with_kid(secret, HS_KID, payload_json, tenant)
    }

    #[allow(clippy::expect_used)]
    fn mint_hs256_bound_with_kid(
        secret: &[u8],
        kid: &str,
        payload_json: &str,
        tenant: &str,
    ) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let header = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"alg":"HS256","typ":"rss-service+jwt","kid":"{kid}"}}"#
        ));
        let body = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header}.{body}");
        let binding = tenant_binding(tenant);
        let mac_input = diport::service_token_mac_input(signing_input.as_bytes(), &binding);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
        mac.update(&mac_input);
        let tag = mac.finalize().into_bytes();
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(tag))
    }

    #[allow(clippy::expect_used)]
    fn mint_hs256_bound_without_kid(secret: &[u8], payload_json: &str, tenant: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"rss-service+jwt"}"#);
        let body = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header}.{body}");
        let binding = tenant_binding(tenant);
        let mac_input = diport::service_token_mac_input(signing_input.as_bytes(), &binding);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
        mac.update(&mac_input);
        let tag = mac.finalize().into_bytes();
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(tag))
    }

    fn ok_claims(r: Result<diport::VerifiedClaims, PdpError>) -> diport::VerifiedClaims {
        match r {
            Ok(c) => c,
            Err(e) => unreachable!("expected Ok(VerifiedClaims), got Err({e:?})"),
        }
    }

    fn access_lifetime_payload(issuer: &str, audience: &str, lifetime: i64) -> String {
        let exp = NOW.saturating_add(lifetime);
        format!(
            r#"{{"sub":"alice","iat":{NOW},"exp":{exp},"token_use":"access","iss":"{issuer}","aud":"{audience}","kind":"user","tenant_id":"{CANON_TENANT}"}}"#
        )
    }

    fn service_lifetime_payload(lifetime: i64) -> String {
        let exp = NOW.saturating_add(lifetime);
        format!(
            r#"{{"sub":"service-a","iat":{NOW},"exp":{exp},"token_use":"service","iss":"{SERVICE_ISS}","aud":"{SERVICE_AUD}","kind":"service","jti":"lifetime-{lifetime}"}}"#
        )
    }

    #[test]
    fn rss_access_verifier_enforces_maximum_lifetime_boundary() {
        let config = es256_config();
        for (lifetime, accepted) in [(899, true), (900, true), (901, false)] {
            let token = mint_es256(&test_sk(), &access_lifetime_payload(ISS, AUD, lifetime));
            let result =
                verify_credential(&config, &FixedClock(NOW), &RawCredential::rss_access(token));
            assert_eq!(
                result.is_ok(),
                accepted,
                "RSS access lifetime {lifetime}s boundary verdict mismatch: {result:?}"
            );
        }
    }

    #[test]
    fn federated_access_verifier_enforces_maximum_lifetime_boundary() {
        let config = federated_es256_config();
        for (lifetime, accepted) in [(899, true), (900, true), (901, false)] {
            let token = mint_es256(
                &test_sk2(),
                &access_lifetime_payload(FEDERATED_ISS, FEDERATED_AUD, lifetime),
            );
            let result = verify_credential(
                &config,
                &FixedClock(NOW),
                &RawCredential::federated_access(token),
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "federated access lifetime {lifetime}s boundary verdict mismatch: {result:?}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn service_verifier_rejects_lifetime_plus_one_before_replay_io() {
        let calls = Arc::new(AtomicUsize::new(0));
        let keys = ServiceTokenKeySource::builder()
            .add_hs256_secret(HS_KID, HS_SECRET)
            .expect("hs256 secret")
            .build();
        let config =
            VerifierConfigBuilder::<diport::ServiceTokenProfile>::new(SERVICE_ISS, SERVICE_AUD)
                .keys_hs256(keys)
                .replay_store(
                    diport::DynServiceTokenReplayStore::new_arc(CountingReplayStore {
                        calls: Arc::clone(&calls),
                    }),
                    Duration::from_secs(5),
                )
                .build()
                .expect("valid service config");

        for (lifetime, accepted, expected_replay_calls) in
            [(299, true, 1), (300, true, 2), (301, false, 2)]
        {
            let token =
                mint_hs256_bound(HS_SECRET, &service_lifetime_payload(lifetime), CANON_TENANT);
            let result = verify_credential(
                &config,
                &FixedClock(NOW),
                &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "service lifetime {lifetime}s boundary verdict mismatch: {result:?}"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                expected_replay_calls,
                "service lifetime {lifetime}s must reject before replay I/O"
            );
        }
    }

    #[test]
    fn three_profile_matrix_accepts_only_its_diagonal() {
        let rss_token = mint_es256(&test_sk(), &payload(NOW + 600, ISS, AUD, ""));
        let federated_token = mint_es256(
            &test_sk2(),
            &payload(NOW + 600, FEDERATED_ISS, FEDERATED_AUD, ""),
        );
        let service_token = mint_hs256_bound(
            HS_SECRET,
            &payload(
                NOW + 300,
                SERVICE_ISS,
                SERVICE_AUD,
                r#","kind":"service","jti":"matrix-service""#,
            ),
            CANON_TENANT,
        );
        let binding = || tenant_binding(CANON_TENANT);

        assert!(
            verify_credential(
                &es256_config(),
                &FixedClock(NOW),
                &RawCredential::rss_access(rss_token.clone()),
            )
            .is_ok()
        );
        assert!(
            verify_credential(
                &federated_es256_config(),
                &FixedClock(NOW),
                &RawCredential::federated_access(federated_token.clone()),
            )
            .is_ok()
        );
        assert!(
            verify_credential(
                &matrix_hs256_config(),
                &FixedClock(NOW),
                &RawCredential::service_token(service_token.clone(), binding()),
            )
            .is_ok()
        );

        let off_diagonal = [
            verify_credential(
                &es256_config(),
                &FixedClock(NOW),
                &RawCredential::rss_access(federated_token.clone()),
            ),
            verify_credential(
                &es256_config(),
                &FixedClock(NOW),
                &RawCredential::rss_access(service_token.clone()),
            ),
            verify_credential(
                &federated_es256_config(),
                &FixedClock(NOW),
                &RawCredential::federated_access(rss_token.clone()),
            ),
            verify_credential(
                &federated_es256_config(),
                &FixedClock(NOW),
                &RawCredential::federated_access(service_token),
            ),
            verify_credential(
                &matrix_hs256_config(),
                &FixedClock(NOW),
                &RawCredential::service_token(rss_token, binding()),
            ),
            verify_credential(
                &matrix_hs256_config(),
                &FixedClock(NOW),
                &RawCredential::service_token(federated_token, binding()),
            ),
        ];
        assert!(
            off_diagonal.iter().all(Result::is_err),
            "3×3 profile matrix 的六个 off-diagonal 必须全部 fail-closed"
        );
    }

    // ── 验收场景 ① 有效 ES256 JWT → 映射 subject/tenant/kind ──────────────────────
    #[test]
    fn valid_es256_jwt_maps_claims() {
        let token = mint_es256(
            &test_sk(),
            &payload(NOW + 600, ISS, AUD, r#","kind":"user""#),
        );
        let claims = ok_claims(verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        ));
        assert_eq!(claims.subject(), "alice");
        assert_eq!(claims.tenant(), Some(CANON_TENANT));
        assert_eq!(claims.kind(), Some("user"));
    }

    #[test]
    fn es256_scoped_kind_without_tenant_is_rejected() {
        let body = format!(
            r#"{{"sub":"alice","iat":{NOW},"exp":{},"token_use":"access","iss":"{ISS}","aud":"{AUD}","kind":"user"}}"#,
            NOW + 600
        );
        let token = mint_es256(&test_sk(), &body);
        let result = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(result, Err(PdpError::InvalidSignature)));
    }

    #[test]
    fn es256_aud_array_containing_audience_accepted() {
        let extra = "";
        let body = format!(
            r#"{{"sub":"alice","iat":{NOW},"exp":{},"token_use":"access","iss":"{ISS}","aud":["other","{AUD}"],"kind":"user","tenant_id":"{CANON_TENANT}"{extra}}}"#,
            NOW + 600
        );
        let token = mint_es256(&test_sk(), &body);
        let claims = ok_claims(verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        ));
        assert_eq!(claims.subject(), "alice");
    }

    // ── 验收场景 ② 篡改 payload → InvalidSignature（error 无 token/key 字节，PdpError 变体不携数据）─────
    #[test]
    fn es256_tampered_payload_rejected() {
        let sk = test_sk();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#);
        let signed_body = URL_SAFE_NO_PAD.encode(payload(NOW + 600, ISS, AUD, "").as_bytes());
        let sig: Signature = sk.sign(format!("{header}.{signed_body}").as_bytes());
        // 签名覆盖 signed_body，但提交另一个合法 payload 段 → signing input 变 → 签名失配。
        let other_body =
            URL_SAFE_NO_PAD.encode(payload(NOW + 600, ISS, AUD, r#","x":"y""#).as_bytes());
        let token = format!(
            "{header}.{other_body}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn es256_wrong_key_rejected() {
        // test_sk2 签发但用 test_sk 公钥的 config 验 → 签名失配。
        let token = mint_es256(&test_sk2(), &payload(NOW + 600, ISS, AUD, ""));
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    // ── 验收场景 ③ exp 越界 → Expired（注入 Clock）──────────────────────────────
    #[test]
    fn es256_expired_token_maps_expired() {
        // exp 1h 前，leeway 60s → 过期。
        let token = mint_es256(&test_sk(), &payload(NOW - 3600, ISS, AUD, ""));
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::Expired)), "got {r:?}");
    }

    #[test]
    fn es256_within_leeway_accepted() {
        // exp 30s 前，leeway 60s → 仍在容忍窗内（不过期）。
        let token = mint_es256(&test_sk(), &payload(NOW - 30, ISS, AUD, ""));
        let claims = ok_claims(verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        ));
        assert_eq!(claims.subject(), "alice");
    }

    // ── 验收场景 ⑧ nbf 未来 → Expired ──────────────────────────────────────────
    #[test]
    fn es256_nbf_future_maps_expired() {
        let body = format!(
            r#"{{"sub":"alice","iat":{NOW},"exp":{},"nbf":{},"token_use":"access","iss":"{ISS}","aud":"{AUD}","kind":"user","tenant_id":"{CANON_TENANT}"}}"#,
            NOW + 600,
            NOW + 600
        );
        let token = mint_es256(&test_sk(), &body);
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::Expired)), "got {r:?}");
    }

    // ── 验收场景 ④ alg=none / RS256 → fail-closed（InvalidSignature）─────────────
    #[test]
    fn alg_none_token_rejected() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let body = URL_SAFE_NO_PAD.encode(payload(NOW + 600, ISS, AUD, "").as_bytes());
        let token = format!("{header}.{body}.");
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn alg_rs256_token_rejected() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let body = URL_SAFE_NO_PAD.encode(payload(NOW + 600, ISS, AUD, "").as_bytes());
        let token = format!("{header}.{body}.c2lnbmF0dXJl");
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn malformed_token_rejected() {
        for token in ["not-a-jwt", "only.two", "a.b.c.d"] {
            let r = verify_credential(
                &es256_config(),
                &FixedClock(NOW),
                &RawCredential::rss_access(token.to_string()),
            );
            assert!(
                matches!(r, Err(PdpError::InvalidSignature)),
                "token `{token}`: {r:?}"
            );
        }
    }

    // ── 验收场景 ⑤ alg-key confusion（jwt scheme + HS256 token）→ Untrusted ───────
    #[test]
    fn jwt_scheme_hs256_token_confusion_rejected() {
        // 攻击者拿 HS256 token 走 JWT 路径（试图让 ES256 公钥被当作 HMAC 密钥）。路径隔离闸先于 key 查找拒。
        let token = mint_hs256(HS_SECRET, &payload(NOW + 600, ISS, AUD, ""));
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::Untrusted)), "got {r:?}");
    }

    #[test]
    fn service_token_scheme_es256_token_confusion_rejected() {
        // 反向：ES256 token 走 service-token 路径 → 路径隔离闸拒。
        let token = mint_es256(&test_sk(), &payload(NOW + 600, ISS, AUD, ""));
        let r = verify_credential(
            &hs256_config(),
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
        );
        assert!(matches!(r, Err(PdpError::Untrusted)), "got {r:?}");
    }

    // ── 验收场景 ⑥ 有效 service_token HS256 → Ok ────────────────────────────────
    #[test]
    fn valid_hs256_service_token_maps_claims() {
        let token = mint_hs256_bound(
            HS_SECRET,
            &payload(
                NOW + 600,
                ISS,
                AUD,
                r#","kind":"service","jti":"nonce-valid""#,
            ),
            CANON_TENANT,
        );
        let claims = ok_claims(verify_credential(
            &hs256_config(),
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
        ));
        assert_eq!(claims.subject(), "alice");
        assert_eq!(claims.kind(), Some("service"));
    }

    #[test]
    fn hs256_service_token_wrong_tenant_binding_rejected() {
        let token = mint_hs256_bound(
            HS_SECRET,
            &payload(
                NOW + 600,
                ISS,
                AUD,
                r#","kind":"service","jti":"nonce-tenant""#,
            ),
            CANON_TENANT,
        );
        let r = verify_credential(
            &hs256_config(),
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(OTHER_TENANT)),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn legacy_unbound_hs256_service_token_rejected() {
        let token = mint_hs256(
            HS_SECRET,
            &payload(
                NOW + 600,
                ISS,
                AUD,
                r#","kind":"service","jti":"nonce-unbound""#,
            ),
        );
        let r = verify_credential(
            &hs256_config(),
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn hs256_service_token_missing_kid_rejected() {
        let token = mint_hs256_bound_without_kid(
            HS_SECRET,
            &payload(
                NOW + 600,
                ISS,
                AUD,
                r#","kind":"service","jti":"nonce-no-kid""#,
            ),
            CANON_TENANT,
        );
        let r = verify_credential(
            &hs256_config(),
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn hs256_service_token_unknown_kid_rejected() {
        let token = mint_hs256_bound_with_kid(
            HS_SECRET,
            "unknown-kid",
            &payload(
                NOW + 600,
                ISS,
                AUD,
                r#","kind":"service","jti":"nonce-unknown-kid""#,
            ),
            CANON_TENANT,
        );
        let r = verify_credential(
            &hs256_config(),
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
        );
        assert!(matches!(r, Err(PdpError::Untrusted)), "got {r:?}");
    }

    #[test]
    fn hs256_service_token_missing_jti_rejected() {
        let token = mint_hs256_bound(
            HS_SECRET,
            &payload(NOW + 600, ISS, AUD, r#","kind":"service""#),
            CANON_TENANT,
        );
        let r = verify_credential(
            &hs256_config(),
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn hs256_service_token_duplicate_jti_rejected() {
        let config = hs256_config();
        let token = mint_hs256_bound(
            HS_SECRET,
            &payload(
                NOW + 600,
                ISS,
                AUD,
                r#","kind":"service","jti":"nonce-dup""#,
            ),
            CANON_TENANT,
        );
        let first = verify_credential(
            &config,
            &FixedClock(NOW),
            &RawCredential::service_token(token.clone(), tenant_binding(CANON_TENANT)),
        );
        assert!(first.is_ok(), "first nonce use should pass: {first:?}");
        let second = verify_credential(
            &config,
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
        );
        assert!(
            matches!(second, Err(PdpError::InvalidSignature)),
            "duplicate nonce must fail closed: {second:?}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn hs256_replay_store_outage_fails_closed_without_identifier_logs() {
        const TOKEN_ID_MARKER: &str = "outage-jti-must-never-be-logged";
        capture::install();
        capture::reset();
        let keys = ServiceTokenKeySource::builder()
            .add_hs256_secret(HS_KID, HS_SECRET)
            .expect("hs256 secret")
            .build();
        let config = VerifierConfigBuilder::<diport::ServiceTokenProfile>::new(ISS, AUD)
            .keys_hs256(keys)
            .replay_store(
                diport::DynServiceTokenReplayStore::new_arc(UnavailableReplayStore),
                Duration::from_secs(5),
            )
            .build()
            .expect("valid hs256 config");
        let token = mint_hs256_bound(
            HS_SECRET,
            &payload(
                NOW + 600,
                ISS,
                AUD,
                &format!(r#","kind":"service","jti":"{TOKEN_ID_MARKER}""#),
            ),
            CANON_TENANT,
        );

        let verdict = verify_credential(
            &config,
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
        );
        assert!(matches!(verdict, Err(PdpError::ProviderUnavailable)));
        let logs = capture::captured();
        assert!(logs.contains("replay_store_unavailable"));
        for forbidden in [TOKEN_ID_MARKER, ISS, AUD, HS_KID] {
            assert!(
                !logs.contains(forbidden),
                "replay outage log leaked scoped identifier {forbidden}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn hs256_same_jti_under_distinct_verified_kids_is_not_a_replay() {
        const SECOND_SECRET: &[u8] = b"second-hs256-secret-for-replay-scope";
        let replay_store = replay_store();
        let keys = ServiceTokenKeySource::builder()
            .add_hs256_secret(HS_KID, HS_SECRET)
            .expect("first hs256 key")
            .add_hs256_secret(HS_KID2, SECOND_SECRET)
            .expect("second hs256 key")
            .build();
        let config = VerifierConfigBuilder::<diport::ServiceTokenProfile>::new(ISS, AUD)
            .keys_hs256(keys)
            .replay_store(replay_store, Duration::from_secs(5))
            .build()
            .expect("valid multi-key hs256 config");
        let payload = payload(
            NOW + 600,
            ISS,
            AUD,
            r#","kind":"service","jti":"shared-jti""#,
        );
        let first = mint_hs256_bound_with_kid(HS_SECRET, HS_KID, &payload, CANON_TENANT);
        let second = mint_hs256_bound_with_kid(SECOND_SECRET, HS_KID2, &payload, CANON_TENANT);

        let first_result = verify_credential(
            &config,
            &FixedClock(NOW),
            &RawCredential::service_token(first, tenant_binding(CANON_TENANT)),
        );
        let second_result = verify_credential(
            &config,
            &FixedClock(NOW),
            &RawCredential::service_token(second, tenant_binding(CANON_TENANT)),
        );

        assert!(first_result.is_ok(), "first scoped key must pass");
        assert!(
            second_result.is_ok(),
            "same jti under a distinct verified kid is a distinct replay scope: {second_result:?}"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn hs256_tampered_rejected() {
        let token = mint_hs256_bound(
            HS_SECRET,
            &payload(
                NOW + 600,
                ISS,
                AUD,
                r#","kind":"service","jti":"nonce-tampered""#,
            ),
            CANON_TENANT,
        );
        // 篡改签名段最后一字符。
        let mut t = token;
        let last = t.pop().unwrap_or('A');
        t.push(if last == 'A' { 'B' } else { 'A' });
        let r = verify_credential(
            &hs256_config(),
            &FixedClock(NOW),
            &RawCredential::service_token(t, tenant_binding(CANON_TENANT)),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    // ── 验收场景 ⑦ 错 iss / aud → Untrusted ────────────────────────────────────
    #[test]
    fn untrusted_issuer_rejected() {
        let token = mint_es256(
            &test_sk(),
            &payload(NOW + 600, "https://evil.example", AUD, ""),
        );
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::Untrusted)), "got {r:?}");
    }

    #[test]
    fn untrusted_audience_rejected() {
        let token = mint_es256(&test_sk(), &payload(NOW + 600, ISS, "other-rp", ""));
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::Untrusted)), "got {r:?}");
    }

    // ── 验收场景 ⑨ 缺/空 sub → InvalidSignature ────────────────────────────────
    #[test]
    fn empty_subject_rejected() {
        let body = format!(
            r#"{{"sub":"","exp":{},"iss":"{ISS}","aud":"{AUD}"}}"#,
            NOW + 600
        );
        let token = mint_es256(&test_sk(), &body);
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    #[test]
    fn missing_exp_rejected() {
        // 缺 required exp → 反序列化失败 → InvalidSignature（拒永久 token）。
        let body = format!(r#"{{"sub":"alice","iss":"{ISS}","aud":"{AUD}"}}"#);
        let token = mint_es256(&test_sk(), &body);
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    // ── kind 不在 allowlist → fail closed ──────────────────────────────────────
    #[test]
    fn untrusted_kind_rejected() {
        let token = mint_es256(
            &test_sk(),
            &payload(NOW + 600, ISS, AUD, r#","kind":"superAdmin""#),
        );
        let result = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(result, Err(PdpError::InvalidSignature)));
    }

    // ── 多 key 轮转：第二把 key 签发 → 命中 ────────────────────────────────────
    #[test]
    #[allow(clippy::expect_used)]
    fn es256_multi_key_rotation_second_key_succeeds() {
        let keys = AccessStaticKeySource::builder()
            .add_es256_sec1("test-es256", &sec1_of(&test_sk2()))
            .expect("k2")
            .add_es256_sec1("test-es256", &sec1_of(&test_sk()))
            .expect("k1")
            .build();
        let token = mint_es256(&test_sk(), &payload(NOW + 600, ISS, AUD, ""));
        let claims = ok_claims(verify_credential(
            &es256_config_with(keys),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        ));
        assert_eq!(claims.subject(), "alice");
    }

    // ── Unknown `kid` never blind-scans static keys ────────────────────────────
    #[test]
    fn es256_token_with_unknown_kid_is_rejected() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"at+jwt","kid":"any-kid"}"#);
        let body = URL_SAFE_NO_PAD.encode(payload(NOW + 600, ISS, AUD, "").as_bytes());
        let signing_input = format!("{header}.{body}");
        let sig: Signature = test_sk().sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        let result = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(result, Err(PdpError::Untrusted)));
    }

    // ── RFC 7515 known-answer 向量 ──────────────────────────────────────────────
    /// RFC 7515 §A.1：HS256 deterministic known-answer（key/signing-input/signature 全已知）。
    #[test]
    #[allow(clippy::expect_used)]
    fn hs256_rfc7515_a1_known_answer() {
        const A1_SIGNING_INPUT: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        const A1_KEY_B64: &str = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        const A1_SIG_B64: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let secret = URL_SAFE_NO_PAD.decode(A1_KEY_B64).expect("rfc key");
        let expected = URL_SAFE_NO_PAD.decode(A1_SIG_B64).expect("rfc sig");
        // 我方 HS256 tag 校验对 RFC 已知签名返回 true。
        assert!(hs256_tag_matches(
            &secret,
            A1_SIGNING_INPUT.as_bytes(),
            &expected
        ));
        // anti-vacuity：篡改任一签名字节 → false。
        let mut bad = expected.clone();
        bad[0] ^= 0x01;
        assert!(!hs256_tag_matches(
            &secret,
            A1_SIGNING_INPUT.as_bytes(),
            &bad
        ));
    }

    /// RFC 7515 §A.3：ES256，用 RFC P-256 公钥（x,y）验 RFC 已知签名。
    #[test]
    #[allow(clippy::expect_used)]
    fn es256_rfc7515_a3_known_answer() {
        const A3_SIGNING_INPUT: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        const RFC_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        const RFC_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        // RFC 7515 A.3.1 JWS Signature（64 字节 r‖s）。
        const A3_SIG: [u8; 64] = [
            14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58,
            249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211, 140, 60, 112,
            229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63,
            127, 138, 131, 163, 84, 213,
        ];
        let mut point = vec![0x04u8];
        point.extend_from_slice(&URL_SAFE_NO_PAD.decode(RFC_X).expect("x"));
        point.extend_from_slice(&URL_SAFE_NO_PAD.decode(RFC_Y).expect("y"));
        let keys = AccessStaticKeySource::builder()
            .add_es256_sec1("test-es256", &point)
            .expect("rfc point")
            .build();
        let jws = Jws {
            alg: SupportedAlg::Es256,
            signing_input: A3_SIGNING_INPUT.as_bytes().to_vec(),
            payload: Vec::new(),
            signature: A3_SIG.to_vec(),
            typ: "at+jwt".to_string(),
            kid: "test-es256".to_string(),
        };
        assert!(
            matches!(
                verify_es256(&keys.snapshot(), "test-es256", &jws),
                VerifyOutcome::Verified
            ),
            "RFC 7515 A.3 已知签名应通过"
        );
        // anti-vacuity：篡改签名 → 有候选但无一匹配 → BadSignature。
        let mut bad = A3_SIG;
        bad[0] ^= 0x01;
        let jws_bad = Jws {
            alg: SupportedAlg::Es256,
            signing_input: A3_SIGNING_INPUT.as_bytes().to_vec(),
            payload: Vec::new(),
            signature: bad.to_vec(),
            typ: "at+jwt".to_string(),
            kid: "test-es256".to_string(),
        };
        assert!(matches!(
            verify_es256(&keys.snapshot(), "test-es256", &jws_bad),
            VerifyOutcome::BadSignature
        ));
    }

    /// 公钥从 RFC x,y 解析（SEC1 点）后能验我方用对应 RFC 私钥不可得——改用 round-trip 间接覆盖（test_sk）。
    #[test]
    #[allow(clippy::expect_used)]
    fn es256_rfc_pubkey_parses_as_verifying_key() {
        const RFC_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        const RFC_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        let mut point = vec![0x04u8];
        point.extend_from_slice(&URL_SAFE_NO_PAD.decode(RFC_X).expect("x"));
        point.extend_from_slice(&URL_SAFE_NO_PAD.decode(RFC_Y).expect("y"));
        assert!(VerifyingKey::from_sec1_bytes(&point).is_ok());
    }

    // ── PII 边界回归：失败路径不记原始 token ───────────────────────────────────
    #[test]
    fn failure_does_not_log_raw_token() {
        capture::install();
        capture::reset();

        // 唯一可识别 marker，混进坏签名 token（走 bad_signature 失败路径）。
        let marker = "MARKER0xDEADBEEF_payload_secret";
        let token = mint_es256(
            &test_sk2(),
            &payload(NOW + 600, ISS, AUD, &format!(r#","note":"{marker}""#)),
        );
        let _ = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token.clone()),
        );

        let logged = capture::captured();
        assert!(!logged.is_empty(), "应有 warn 日志");
        assert!(!logged.contains(marker), "原始 token/claim 泄漏: {logged}");
        assert!(!logged.contains(&token), "原始 token 泄漏: {logged}");
        assert!(
            logged.contains("bad_signature"),
            "应记 reason 闭值标签: {logged}"
        );
    }

    // ── Finding 6: 补缺失测试 ──────────────────────────────────────────────────

    /// payload 不含 "sub" 键（其余 exp/iss/aud 齐）→ 反序列化失败 → InvalidSignature。
    #[test]
    fn missing_subject_rejected() {
        let body = format!(r#"{{"exp":{},"iss":"{ISS}","aud":"{AUD}"}}"#, NOW + 600);
        let token = mint_es256(&test_sk(), &body);
        let r = verify_credential(
            &es256_config(),
            &FixedClock(NOW),
            &RawCredential::rss_access(token),
        );
        assert!(matches!(r, Err(PdpError::InvalidSignature)), "got {r:?}");
    }

    /// leeway 精确边界：exp = NOW-60，leeway=60s → 仍在容忍窗内，应 Ok。
    #[test]
    #[allow(clippy::expect_used)]
    fn es256_at_leeway_boundary_accepted() {
        let config = VerifierConfigBuilder::<diport::RssAccessProfile>::new(ISS, AUD)
            .keys_static({
                AccessStaticKeySource::builder()
                    .add_es256_sec1("test-es256", &sec1_of(&test_sk()))
                    .expect("key")
                    .build()
            })
            .trust_kind("user")
            .leeway_secs(60)
            .build()
            .expect("config");
        // exp = NOW-60：now (1_700_000_000) > exp+leeway (NOW-60+60=NOW)? 不等式 NOW > NOW 为 false → 接受。
        let token = mint_es256(&test_sk(), &payload(NOW - 60, ISS, AUD, ""));
        let r = verify_credential(&config, &FixedClock(NOW), &RawCredential::rss_access(token));
        assert!(r.is_ok(), "leeway 边界内应接受: {r:?}");
    }

    /// leeway 精确边界外：exp = NOW-61，leeway=60s → 超出容忍窗，应 Expired。
    #[test]
    #[allow(clippy::expect_used)]
    fn es256_just_past_leeway_rejected() {
        let config = VerifierConfigBuilder::<diport::RssAccessProfile>::new(ISS, AUD)
            .keys_static({
                AccessStaticKeySource::builder()
                    .add_es256_sec1("test-es256", &sec1_of(&test_sk()))
                    .expect("key")
                    .build()
            })
            .trust_kind("user")
            .leeway_secs(60)
            .build()
            .expect("config");
        // exp = NOW-61：now (NOW) > exp+leeway (NOW-61+60=NOW-1)? NOW > NOW-1 = true → 过期。
        let token = mint_es256(&test_sk(), &payload(NOW - 61, ISS, AUD, ""));
        let r = verify_credential(&config, &FixedClock(NOW), &RawCredential::rss_access(token));
        assert!(matches!(r, Err(PdpError::Expired)), "got {r:?}");
    }

    /// nbf 在 leeway 内（nbf=NOW+30，leeway=60）→ 应 Ok。
    #[test]
    #[allow(clippy::expect_used)]
    fn es256_nbf_within_leeway_accepted() {
        let config = VerifierConfigBuilder::<diport::RssAccessProfile>::new(ISS, AUD)
            .keys_static({
                AccessStaticKeySource::builder()
                    .add_es256_sec1("test-es256", &sec1_of(&test_sk()))
                    .expect("key")
                    .build()
            })
            .trust_kind("user")
            .leeway_secs(60)
            .build()
            .expect("config");
        // nbf=NOW+30, leeway=60 → nbf-leeway=NOW-30 → now(NOW) >= NOW-30 → 接受。
        let body = format!(
            r#"{{"sub":"alice","iat":{NOW},"exp":{},"nbf":{},"token_use":"access","iss":"{ISS}","aud":"{AUD}","kind":"user","tenant_id":"{CANON_TENANT}"}}"#,
            NOW + 600,
            NOW + 30
        );
        let token = mint_es256(&test_sk(), &body);
        let r = verify_credential(&config, &FixedClock(NOW), &RawCredential::rss_access(token));
        assert!(r.is_ok(), "nbf 在 leeway 内应接受: {r:?}");
    }

    /// HS256 多 key 轮转：两把 secret，用第二把签发 → Ok。
    #[test]
    #[allow(clippy::expect_used)]
    fn hs256_multi_key_rotation_second_key_succeeds() {
        const HS_SECRET2: &[u8] = b"second-hs256-secret-for-rotation-test";
        let keys = ServiceTokenKeySource::builder()
            .add_hs256_secret(HS_KID, HS_SECRET)
            .expect("first secret")
            .add_hs256_secret(HS_KID2, HS_SECRET2)
            .expect("second secret")
            .build();
        let config = VerifierConfigBuilder::<diport::ServiceTokenProfile>::new(ISS, AUD)
            .keys_hs256(keys)
            .replay_store(replay_store(), Duration::from_secs(5))
            .build()
            .expect("config");
        // 用第二把 secret 签发 → 验签器遍历两把密钥，第二把命中 → Ok。
        let token = mint_hs256_bound_with_kid(
            HS_SECRET2,
            HS_KID2,
            &payload(NOW + 600, ISS, AUD, r#","kind":"service","jti":"nonce-k2""#),
            CANON_TENANT,
        );
        let r = verify_credential(
            &config,
            &FixedClock(NOW),
            &RawCredential::service_token(token, tenant_binding(CANON_TENANT)),
        );
        assert!(r.is_ok(), "第二把 key 应命中: {r:?}");
    }
}
