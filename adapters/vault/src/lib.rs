//! vault adapter —— RSS workspace（Transit 与 caller-owned CSR PKI transport）。See docs/rules/architecture.md.
//!
//! `VaultSigner` / `VaultKeyProvider`（sealed-marker）：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-12）。
//! - `backend` feature 开时增补 `impl diport::Signer`（HashiCorp Vault Transit `sign`，见 `transit` 模块）。
//! - `backend` feature 开时增补 `impl diport::KeyProvider`（HashiCorp Vault Transit `encrypt`/`decrypt`/
//!   `rewrap`，见 `transit` 模块）。
//! - `backend` feature 开时增补 concrete Vault PKI transport。它固定调用 Vault PKI
//!   `/sign/{role}`，并在返回 transport evidence 前本地验证 CSR、leaf、chain 与有效期。
//!   Evidence 不是 production authorization receipt；该层不接触 `/issue` 或私钥。
//!
//! **TLS-agnostic**（对标 s3 注入 aws `Client`）：adapter 只持有组合根注入的 `reqwest::Client`；TLS provider
//! （rustls+ring，对齐 sqlx，避开 deny.toml openssl/aws-lc-sys/ring-license ban）与 roots 由组合根在 Join
//! 阶段经 reqwest tls feature 选定后构造并注入——adapter 层不配 TLS。
//!
//! **签名授权双层收口**：Vault token ACL 限制 Transit key 路径；adapter 还保存 RSS profile-typed
//! binding，在发出 HTTP 前精确拒绝不匹配的 key/purpose。Vault 中真实 key material 与 JWKS 的一致性由
//! composition-root readiness 和 T2 round-trip 证明。
//!
//! **§签名表示**：`Signer::sign` 返回的 [`diport::Signature`] 是**原始签名字节**——adapter 解析 Vault Transit
//! `vault:v<N>:<base64url>` 响应、校验前缀+数字版本段后 base64url decode 出字节（符合
//! `diport::Signature` =「签名结果字节」契约，见 `crates/diport/src/signer.rs`）。Vault 的 `v<N>` 版本是验签元数据，
//! 对 provider-agnostic 的 `Signer` 无意义、剥离。若业务确需 Vault verify 的 tagged token，应拆独立 verify-capable
//! port，不复用 `Signer`（不把 provider-specific envelope 塞进 provider-agnostic 类型）。
//!
//! **传输安全**：`new_rss_access` 强制 `https`（fail-fast `InsecureScheme`）；本地 dev 的 `http` 必须经显式
//! `new_rss_access_allow_http` 具名构造器 opt-in。请求级 `timeout` 是构造器必填参数（防注入的 `Client`
//! 未配 timeout 时无限等待）。
//!
//! Raw marshaling construction is intentionally unavailable: JWT callers must supply the
//! profile-typed RSS signing binding and Transit is fixed to JWS marshaling.
//!
//! ```compile_fail
//! use std::time::Duration;
//! use vault::VaultSigner;
//!
//! let _ = VaultSigner::new(
//!     reqwest::Client::new(),
//!     "https://vault.example:8200",
//!     "token",
//!     "transit",
//!     Duration::from_secs(1),
//! );
//! ```
//!
//! **字段保护 AAD 映射**：`VaultKeyProvider` 把 RSS `secure::DerivedAad` 的 canonical bytes 经单一 funnel
//! base64 编码进 Vault Transit `context` 字段，**要求 Transit key `derived=true`，不使用 `associated_data`**。
//! Vault `/rewrap` 源码对 `context` 生效，但非 batch rewrap 不实际使用 `associated_data`；用 `context` 可保留
//! 原生 rewrap，避免 decrypt+encrypt fallback 把明文拉回 adapter。组合根启动 self-check 用 wrong-AAD 解密
//! fail-closed 证明生产 key 策略没有退化成 AAD-blind。
//!
//! **keyset / rotation 语义（#1474）**：`diport::KeyName` 对应 Vault Transit key name；`diport::KeyVersion`
//! 对应 Vault tagged ciphertext 的 `vault:vN:` version；`diport::KeyRef` 是调用方随密文持久化的稳定
//! envelope reference。encrypt / rewrap 请求显式传 `key_version = 0`，表示写入 Vault current-primary；
//! decrypt 不传 `key_version` override，而是用密文 `vault:vN:` + stored `KeyRef` 验证 previous-read 窗口。
//! 禁旧版本由运维提升 Vault `min_decryption_version` 完成，adapter 只把 Vault 拒绝收敛成 provider-agnostic
//! `Rejected`。
//!
//! crate 保持 forbid(unsafe_code)（继承 workspace lints）。

#[cfg(feature = "backend")]
mod transit;

#[cfg(feature = "backend")]
mod pki;

#[cfg(feature = "backend")]
mod secret_resolver;

#[cfg(feature = "backend")]
mod bundle;

#[cfg(feature = "backend")]
pub use bundle::{VaultDomain, VaultDomainDeps, VaultRuntimeDeps, caps};
#[cfg(feature = "backend")]
pub use pki::{
    VaultPkiArtifactEvidence, VaultPkiHttpClient, VaultPkiMount, VaultPkiRole, VaultPkiTransport,
    VaultPkiTransportConfig,
};
#[cfg(feature = "backend")]
pub use secret_resolver::{
    SECRET_RESOLVER_READINESS_KEY, SecretResolverReadinessTarget, StoreBinding,
    TenantStoreAllowlist, TenantStoreAllowlistError, VaultSecretResolver,
    VaultSecretResolverConfigError,
};

#[cfg(feature = "backend")]
use std::time::Duration;

use diport::{ManagedResource, ShutdownError};

/// Vault 认证 token（opaque newtype）。底层 `Zeroizing<String>` 在 drop 时清零密钥物料（F5，杜绝 token 残留
/// 进程内存）；`Debug` 恒输出 `VaultToken(<redacted>)`——即便 [`VaultSigner`] 将来误加 `#[derive(Debug)]` 也不
/// 泄漏（类型层 Hard，对标 `diport::Signature` / `secure::Redacted`）。
#[cfg(feature = "backend")]
struct VaultToken(zeroize::Zeroizing<String>);

#[cfg(feature = "backend")]
impl zeroize::ZeroizeOnDrop for VaultToken {}

#[cfg(feature = "backend")]
impl std::fmt::Debug for VaultToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultToken(<redacted>)")
    }
}

#[cfg(feature = "backend")]
impl VaultToken {
    fn new(token: String) -> Self {
        Self(zeroize::Zeroizing::new(token))
    }
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// HashiCorp Vault Transit 签名 adapter（sealed-marker）。raw 连接物料经 `backend` feature 门控、保持私有：
/// - `client`：组合根注入的预配置 TLS `reqwest::Client`（adapter TLS-agnostic，对标 s3 注入 aws `Client`）。
/// - `base`：构造期校验过 scheme（https / 经 `new_allow_http` 显式放行的 http）的 base `Url`；请求时 clone 后
///   `path_segments_mut` 追加 `v1`/`mount…`/`sign`/`key` 段（均 percent-encode，防路径段注入）。
/// - `token`：[`VaultToken`] opaque + zeroize 包装（永不进 `Debug` / 日志，drop 清零）。
/// - `mount_segments`：构造期按 `/` 拆分校验的 path 段（支持嵌套 mount `team/transit`，F3）。
/// - `timeout`：请求级超时（构造器必填，F4）。
pub struct VaultSigner {
    #[cfg(feature = "backend")]
    client: reqwest::Client,
    #[cfg(feature = "backend")]
    base: reqwest::Url,
    #[cfg(feature = "backend")]
    token: VaultToken,
    #[cfg(feature = "backend")]
    mount_segments: Vec<String>,
    #[cfg(feature = "backend")]
    timeout: Duration,
    #[cfg(feature = "backend")]
    signing_binding: diport::JwtSigningBinding<diport::RssAccessProfile>,
}

/// HashiCorp Vault Transit 字段级加解密 adapter（sealed-marker）。raw 连接物料经 `backend` feature 门控、保持私有。
///
/// 与 [`VaultSigner`] 共享构造安全边界：`https` 默认强制、`new_allow_http` 显式 opt-in、mount 分段校验、
/// token zeroize、请求级 timeout。`DerivedAad` 在执行体内只经 `transit::build_context` 编码为 Vault
/// `context`，请求体不生成 `associated_data` 字段。轮换时写路径使用 Vault current-primary，读路径依赖
/// Vault previous-read policy，rewrap 路径返回新的 `KeyRef` 供调用方原子替换。
pub struct VaultKeyProvider {
    #[cfg(feature = "backend")]
    client: reqwest::Client,
    #[cfg(feature = "backend")]
    base: reqwest::Url,
    #[cfg(feature = "backend")]
    token: VaultToken,
    #[cfg(feature = "backend")]
    mount_segments: Vec<String>,
    #[cfg(feature = "backend")]
    timeout: Duration,
}

/// 构造期配置校验错误（fail-fast，非静默 noop）。
#[cfg(feature = "backend")]
#[derive(Debug, thiserror::Error)]
pub enum VaultConfigError {
    /// Vault 地址为空。
    #[error("vault address must not be empty (expected base url, e.g. https://vault.example:8200)")]
    EmptyAddr,
    /// Vault 地址不是合法 URL。
    #[error("vault address is not a valid url (expected e.g. https://vault.example:8200)")]
    InvalidAddr,
    /// Vault 地址使用非 https scheme 且未经 adapter 的具名 allow-http 构造器显式放行。
    #[error(
        "vault address must use https; use the adapter's explicit allow-http constructor for local dev http opt-in"
    )]
    InsecureScheme,
    /// Transit mount 为空。
    #[error("vault transit mount must not be empty (e.g. transit or team/transit)")]
    EmptyMount,
    /// Transit mount 含非法 path 段（空段 / `.` / `..`）。
    #[error("vault transit mount has an invalid path segment (empty, '.', or '..')")]
    InvalidMountSegment,
    /// Vault token 为空。
    #[error(
        "vault token must not be empty (provide via composition root / Vault Agent, not hardcoded)"
    )]
    EmptyToken,
    /// PKI transport timeout must be non-zero.
    #[error("vault request timeout must be non-zero")]
    ZeroTimeout,
    /// PKI role is empty.
    #[error("vault PKI role must not be empty")]
    EmptyPkiRole,
    /// PKI role must be one safe URL path segment.
    #[error("vault PKI role has an invalid path segment")]
    InvalidPkiRole,
    /// At least one explicit PKI trust root is required.
    #[error("vault PKI trust roots must not be empty")]
    EmptyPkiTrustRoots,
    /// PKI trust root is malformed or is not a self-signed CA.
    #[error("vault PKI trust root is invalid")]
    InvalidPkiTrustRoot,
}

#[cfg(feature = "backend")]
impl VaultSigner {
    /// Construct an HTTPS-only RSS access JWT signer fixed to JWS marshaling.
    pub fn new_rss_access(
        client: reqwest::Client,
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        timeout: Duration,
        signing_binding: diport::JwtSigningBinding<diport::RssAccessProfile>,
    ) -> Result<Self, VaultConfigError> {
        let token = VaultToken::new(token.into());
        Self::build(
            client,
            addr.into(),
            token,
            mount.into(),
            timeout,
            false,
            signing_binding,
        )
    }

    /// Same as [`Self::new_rss_access`], with explicit plaintext HTTP opt-in for local tests.
    pub fn new_rss_access_allow_http(
        client: reqwest::Client,
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        timeout: Duration,
        signing_binding: diport::JwtSigningBinding<diport::RssAccessProfile>,
    ) -> Result<Self, VaultConfigError> {
        let token = VaultToken::new(token.into());
        Self::build(
            client,
            addr.into(),
            token,
            mount.into(),
            timeout,
            true,
            signing_binding,
        )
    }

    fn build(
        client: reqwest::Client,
        addr: String,
        token: VaultToken,
        mount: String,
        timeout: Duration,
        allow_http: bool,
        signing_binding: diport::JwtSigningBinding<diport::RssAccessProfile>,
    ) -> Result<Self, VaultConfigError> {
        let config = validate_vault_config(addr, token, mount, allow_http)?;
        Ok(Self {
            client,
            base: config.base,
            token: config.token,
            mount_segments: config.mount_segments,
            timeout,
            signing_binding,
        })
    }
}

#[cfg(feature = "backend")]
impl VaultKeyProvider {
    /// 构造 Transit KeyProvider adapter（**https-only**）。`client` 由组合根预配置 TLS 后注入；`addr`
    /// 是 Vault base URL；`mount` 是 Transit mount；`token` 是 Vault 认证 token；`timeout` 是请求级超时。
    pub fn new(
        client: reqwest::Client,
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, VaultConfigError> {
        let token = VaultToken::new(token.into());
        Self::build(client, addr.into(), token, mount.into(), timeout, false)
    }

    /// 同 [`new`](Self::new)，但**显式放行 http**——仅用于本地 dev / 集成测试对接 plaintext Vault。
    pub fn new_allow_http(
        client: reqwest::Client,
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, VaultConfigError> {
        let token = VaultToken::new(token.into());
        Self::build(client, addr.into(), token, mount.into(), timeout, true)
    }

    fn build(
        client: reqwest::Client,
        addr: String,
        token: VaultToken,
        mount: String,
        timeout: Duration,
        allow_http: bool,
    ) -> Result<Self, VaultConfigError> {
        let config = validate_vault_config(addr, token, mount, allow_http)?;
        Ok(Self {
            client,
            base: config.base,
            token: config.token,
            mount_segments: config.mount_segments,
            timeout,
        })
    }
}

#[cfg(feature = "backend")]
struct ValidatedVaultConfig {
    base: reqwest::Url,
    token: VaultToken,
    mount_segments: Vec<String>,
}

#[cfg(feature = "backend")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultBaseUrlError {
    Empty,
    Invalid,
    InsecureScheme,
}

#[cfg(feature = "backend")]
fn validate_vault_base_url(
    addr: &str,
    allow_http: bool,
) -> Result<reqwest::Url, VaultBaseUrlError> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(VaultBaseUrlError::Empty);
    }
    let base = reqwest::Url::parse(trimmed).map_err(|_| VaultBaseUrlError::Invalid)?;
    let authority_has_userinfo = trimmed.split_once("://").is_some_and(|(_, remainder)| {
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        remainder[..authority_end].contains('@')
    });
    if authority_has_userinfo
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(VaultBaseUrlError::Invalid);
    }
    match base.scheme() {
        "https" => Ok(base),
        "http" if allow_http => Ok(base),
        _ => Err(VaultBaseUrlError::InsecureScheme),
    }
}

#[cfg(feature = "backend")]
impl From<VaultBaseUrlError> for VaultConfigError {
    fn from(error: VaultBaseUrlError) -> Self {
        match error {
            VaultBaseUrlError::Empty => Self::EmptyAddr,
            VaultBaseUrlError::Invalid => Self::InvalidAddr,
            VaultBaseUrlError::InsecureScheme => Self::InsecureScheme,
        }
    }
}

#[cfg(feature = "backend")]
fn validate_vault_config(
    addr: String,
    token: VaultToken,
    mount: String,
    allow_http: bool,
) -> Result<ValidatedVaultConfig, VaultConfigError> {
    if token.as_str().trim().is_empty() {
        return Err(VaultConfigError::EmptyToken);
    }
    let base = validate_vault_base_url(&addr, allow_http)?;
    let mount_segments = parse_mount_segments(&mount)?;
    Ok(ValidatedVaultConfig {
        base,
        token,
        mount_segments,
    })
}

/// 把 `mount` 规范化为 path 段集（去首尾 `/` 后按 `/` 拆分），拒绝空段 / `.` / `..`（防嵌套 mount 被编成
/// 单段 `%2F`（F3）+ 路径穿越）。空 mount → `EmptyMount`。
#[cfg(feature = "backend")]
fn parse_mount_segments(mount: &str) -> Result<Vec<String>, VaultConfigError> {
    let trimmed = mount.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err(VaultConfigError::EmptyMount);
    }
    let mut segments = Vec::new();
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(VaultConfigError::InvalidMountSegment);
        }
        segments.push(segment.to_string());
    }
    Ok(segments)
}

/// INVARIANT: ADAPTER-PORT-FREEZE-12 { level = "Hard", exec = "native-compile", source = "code", native = "sealed ManagedResource implementation on the production provider" }.
impl ManagedResource for VaultSigner {
    fn name(&self) -> &str {
        "vault"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: reqwest::Client 无显式 close——连接池随 drop 静默释放。Vault Transit sign 是短暂 HTTP 调用
        // （无长连接 streaming / in-flight 长任务），无 graceful drain 需求，故 shutdown 即 Ok。
        Ok(())
    }
}

impl ManagedResource for VaultKeyProvider {
    fn name(&self) -> &str {
        "vault-key-provider"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: reqwest::Client 无显式 close；Transit encrypt/decrypt/rewrap 是短暂 HTTP 调用，无 drain 需求。
        Ok(())
    }
}

#[cfg(feature = "backend")]
impl ManagedResource for VaultPkiTransport {
    fn name(&self) -> &str {
        "vault-pki-transport"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Ok(())
    }
}

#[cfg(feature = "backend")]
impl diport::Signer for VaultSigner {
    async fn sign(
        &self,
        request: diport::SignRequest,
    ) -> Result<diport::Signature, diport::SignerError> {
        if !self.signing_binding.accepts(&request) {
            return Err(diport::SignerError::new(std::io::Error::other(
                "jwt signing request is outside the configured profile binding",
            )));
        }
        transit::sign_impl(
            &self.client,
            &self.base,
            self.token.as_str(),
            &self.mount_segments,
            self.timeout,
            request,
        )
        .await
    }

    async fn shutdown(&self) -> Result<(), diport::SignerError> {
        // reason: 同 ManagedResource::shutdown——reqwest::Client 无显式 close，短暂 HTTP 调用无 drain 需求。
        Ok(())
    }
}

#[cfg(feature = "backend")]
impl diport::KeyProvider for VaultKeyProvider {
    async fn encrypt(
        &self,
        key: diport::KeyName,
        plaintext: secure::Plaintext,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        transit::encrypt_impl(
            transit::TransitHttp::new(
                &self.client,
                &self.base,
                self.token.as_str(),
                &self.mount_segments,
                self.timeout,
            ),
            key,
            plaintext,
            aad,
        )
        .await
    }

    async fn decrypt(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        transit::decrypt_impl(
            transit::TransitHttp::new(
                &self.client,
                &self.base,
                self.token.as_str(),
                &self.mount_segments,
                self.timeout,
            ),
            ciphertext,
            key,
            aad,
        )
        .await
    }

    async fn rewrap(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        transit::rewrap_impl(
            transit::TransitHttp::new(
                &self.client,
                &self.base,
                self.token.as_str(),
                &self.mount_segments,
                self.timeout,
            ),
            ciphertext,
            key,
            aad,
        )
        .await
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        // reason: 同 ManagedResource::shutdown——reqwest::Client 无显式 close，短暂 HTTP 调用无 drain 需求。
        Ok(())
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait（PhantomData 绑定检查，
    //! 不构造、不执行 body）。
    //! ADAPTER-PORT-FREEZE-12 support：sealed-marker impl 冻结的 diport DI port trait（ManagedResource
    //! 始终；Signer 于 backend；SecretResolver + ManagedResource 于 backend）；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::VaultSigner>);
        #[cfg(feature = "backend")]
        assert_managed_resource(PhantomData::<super::VaultPkiTransport>);
    }

    #[cfg(feature = "backend")]
    fn assert_signer<T: diport::Signer>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_signer() {
        assert_signer(PhantomData::<super::VaultSigner>);
    }

    #[cfg(feature = "backend")]
    #[cfg(feature = "backend")]
    fn assert_secret_resolver<T: diport::SecretResolver>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn vault_secret_resolver_impls_secret_resolver() {
        assert_secret_resolver(PhantomData::<super::VaultSecretResolver>);
    }

    #[cfg(feature = "backend")]
    #[test]
    fn vault_secret_resolver_impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::VaultSecretResolver>);
    }

    #[cfg(feature = "backend")]
    fn assert_key_provider<T: diport::KeyProvider>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn vault_key_provider_impls_key_provider() {
        assert_key_provider(PhantomData::<super::VaultKeyProvider>);
    }

    #[cfg(feature = "backend")]
    #[test]
    fn vault_key_provider_impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::VaultKeyProvider>);
    }
}

#[cfg(all(test, feature = "backend"))]
mod backend_tests {
    //! 构造期 fail-fast（空值 / 非法 URL / 非 https scheme / 非法 mount 段）+ 生命周期（name + 双 shutdown），无 live 后端。
    use std::time::Duration;

    use super::{
        VaultConfigError, VaultKeyProvider, VaultSigner, VaultToken, validate_vault_config,
    };
    use diport::{KeyProvider, ManagedResource, Signer};

    const ADDR: &str = "https://vault.example:8200";
    const TOKEN: &str = "s.testtoken";
    const MOUNT: &str = "transit";
    const TIMEOUT: Duration = Duration::from_secs(30);

    // 构造 helper：合法配置的 VaultSigner。item-level expect carve-out 集中此一处
    // （error-handling.md §Carve-out 要求 item-level），测试体不散落 `expect`。
    #[allow(clippy::expect_used)]
    fn valid_signer() -> VaultSigner {
        VaultSigner::new_rss_access(
            reqwest::Client::new(),
            ADDR,
            TOKEN,
            MOUNT,
            TIMEOUT,
            diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key")),
        )
        .expect("valid config")
    }

    #[allow(clippy::expect_used)]
    fn valid_key_provider() -> VaultKeyProvider {
        VaultKeyProvider::new(reqwest::Client::new(), ADDR, TOKEN, MOUNT, TIMEOUT)
            .expect("valid config")
    }

    #[test]
    fn new_rejects_empty_addr() {
        assert!(matches!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                "",
                TOKEN,
                MOUNT,
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"))
            ),
            Err(VaultConfigError::EmptyAddr)
        ));
    }

    #[test]
    fn new_rejects_invalid_url() {
        assert!(matches!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                "not a url",
                TOKEN,
                MOUNT,
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"))
            ),
            Err(VaultConfigError::InvalidAddr)
        ));
    }

    #[test]
    fn new_rejects_sensitive_base_url_components_without_disclosure() {
        const MARKER: &str = "vault-url-secret-marker";
        for addr in [
            "https://vault-url-secret-marker@vault.example:8200",
            "https://vault.example:8200?token=vault-url-secret-marker",
            "https://vault.example:8200#vault-url-secret-marker",
        ] {
            let result = VaultSigner::new_rss_access(
                reqwest::Client::new(),
                addr,
                TOKEN,
                MOUNT,
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key")),
            );
            assert!(matches!(&result, Err(VaultConfigError::InvalidAddr)));
            if let Err(error) = result {
                let rendered = format!("{error:?} {error}");
                assert!(!rendered.contains(MARKER), "error must be value-free");
            }
        }
    }

    #[test]
    fn new_rejects_http_scheme() {
        // F2：默认 https-only；http 经 new() 被拒。
        assert!(matches!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                "http://vault.example:8200",
                TOKEN,
                MOUNT,
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key")),
            ),
            Err(VaultConfigError::InsecureScheme)
        ));
    }

    #[test]
    fn new_allow_http_accepts_http() {
        // F2：dev opt-in 具名构造器显式放行 http。
        assert!(
            VaultSigner::new_rss_access_allow_http(
                reqwest::Client::new(),
                "http://127.0.0.1:8200",
                TOKEN,
                MOUNT,
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key")),
            )
            .is_ok()
        );
    }

    #[test]
    fn new_rejects_empty_mount() {
        assert!(matches!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                "",
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"))
            ),
            Err(VaultConfigError::EmptyMount)
        ));
    }

    #[test]
    fn new_accepts_nested_mount() {
        // F3：嵌套 mount 拆成多段（不被编码成单段 `%2F`）。
        assert!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                "team/transit",
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"))
            )
            .is_ok()
        );
    }

    #[test]
    fn new_rejects_mount_path_traversal() {
        // F3：`.`/`..`/空段 拒绝（防路径穿越）。
        assert!(matches!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                "transit/..",
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"))
            ),
            Err(VaultConfigError::InvalidMountSegment)
        ));
        assert!(matches!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                "a//b",
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"))
            ),
            Err(VaultConfigError::InvalidMountSegment)
        ));
    }

    #[test]
    fn new_rejects_empty_token() {
        assert!(matches!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                ADDR,
                "",
                MOUNT,
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"))
            ),
            Err(VaultConfigError::EmptyToken)
        ));
    }

    #[test]
    fn new_rejects_whitespace_only_token() {
        assert!(matches!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                ADDR,
                "   ",
                MOUNT,
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"))
            ),
            Err(VaultConfigError::EmptyToken)
        ));
    }

    #[test]
    fn validation_failure_paths_own_zeroizing_token() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<VaultToken>();

        assert!(matches!(
            validate_vault_config(
                String::new(),
                VaultToken::new("vault-error-path-token".to_owned()),
                MOUNT.to_owned(),
                false,
            ),
            Err(VaultConfigError::EmptyAddr)
        ));
        assert!(matches!(
            validate_vault_config(
                ADDR.to_owned(),
                VaultToken::new("vault-error-path-token".to_owned()),
                "transit/..".to_owned(),
                false,
            ),
            Err(VaultConfigError::InvalidMountSegment)
        ));
        assert!(matches!(
            validate_vault_config(
                ADDR.to_owned(),
                VaultToken::new("   ".to_owned()),
                MOUNT.to_owned(),
                false,
            ),
            Err(VaultConfigError::EmptyToken)
        ));
    }

    #[test]
    fn new_accepts_valid_config() {
        assert!(
            VaultSigner::new_rss_access(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                MOUNT,
                TIMEOUT,
                diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"))
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn lifecycle_name_and_shutdowns() {
        let signer = valid_signer();
        assert_eq!(ManagedResource::name(&signer), "vault");
        assert!(ManagedResource::shutdown(&signer).await.is_ok());
        assert!(Signer::shutdown(&signer).await.is_ok());

        let key_provider = valid_key_provider();
        assert_eq!(ManagedResource::name(&key_provider), "vault-key-provider");
        assert!(ManagedResource::shutdown(&key_provider).await.is_ok());
        assert!(KeyProvider::shutdown(&key_provider).await.is_ok());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rss_binding_rejects_key_and_purpose_mismatch_before_http() {
        let server = wiremock::MockServer::start().await;
        let binding = diport::JwtSigningBinding::rss_access(diport::KeyId::new("rss-key"));
        let signer = VaultSigner::new_rss_access_allow_http(
            reqwest::Client::new(),
            server.uri(),
            TOKEN,
            MOUNT,
            TIMEOUT,
            binding,
        )
        .expect("valid loopback config");

        let invalid_requests = [
            diport::SignRequest {
                key: diport::KeyId::new("wrong-key"),
                purpose: diport::SigningPurpose::new("auth.rss-access"),
                message: b"payload".to_vec().into(),
            },
            diport::SignRequest {
                key: diport::KeyId::new("rss-key"),
                purpose: diport::SigningPurpose::new("wrong-purpose"),
                message: b"payload".to_vec().into(),
            },
            diport::SignRequest {
                key: diport::KeyId::new("wrong-key"),
                purpose: diport::SigningPurpose::new("wrong-purpose"),
                message: b"payload".to_vec().into(),
            },
        ];

        for request in invalid_requests {
            assert!(Signer::sign(&signer, request).await.is_err());
        }
        assert!(
            server
                .received_requests()
                .await
                .expect("request recording")
                .is_empty()
        );
    }
}
