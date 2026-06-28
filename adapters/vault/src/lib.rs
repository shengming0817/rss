//! vault adapter —— RSS workspace（W 阶段真身，#1011 Transit 签名切片）。See docs/rules/architecture.md.
//!
//! `VaultSigner` / `VaultKeyProvider`（sealed-marker）：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-12）。
//! - `backend` feature 开时增补 `impl diport::Signer`（HashiCorp Vault Transit `sign`，见 `transit` 模块）。
//! - `backend` feature 开时增补 `impl diport::KeyProvider`（HashiCorp Vault Transit `encrypt`/`decrypt`/
//!   `rewrap`，见 `transit` 模块）。
//!
//! **TLS-agnostic**（对标 s3 注入 aws `Client`）：adapter 只持有组合根注入的 `reqwest::Client`；TLS provider
//! （rustls+ring，对齐 sqlx，避开 deny.toml openssl/aws-lc-sys/ring-license ban）与 roots 由组合根在 Join
//! 阶段经 reqwest tls feature 选定后构造并注入——adapter 层不配 TLS。
//!
//! **签名授权委托 Vault token ACL/policy**（注入的 token 只授权允许的 transit 键路径）：本切片不在 adapter 内
//! 实现 key·purpose allowlist 或 ambient-ctx 租户 ABAC；`key`/`purpose` 仅作审计归因（tracing）。若判需
//! adapter 侧策略层 → follow-up issue。
//!
//! **§签名表示**：`Signer::sign` 返回的 [`diport::Signature`] 是**原始签名字节**——adapter 解析 Vault Transit
//! `vault:v<N>:<base64>` 响应、校验前缀+数字版本段后 base64 decode 出字节（符合 `diport::Signature` =「签名结果
//! 字节」契约，见 `crates/diport/src/signer.rs`；被 deviceloop 证书签发消费）。Vault 的 `v<N>` 版本是验签元数据，
//! 对 provider-agnostic 的 `Signer` 无意义、剥离。若业务确需 Vault verify 的 tagged token，应拆独立 verify-capable
//! port，不复用 `Signer`（不把 provider-specific envelope 塞进 provider-agnostic 类型）。
//!
//! **传输安全**：`new` 强制 `https`（fail-fast `InsecureScheme`）；本地 dev 的 `http` 必须经显式 `new_allow_http`
//! 具名构造器 opt-in。请求级 `timeout` 是构造器必填参数（防注入的 `Client` 未配 timeout 时无限等待）。
//!
//! **字段保护 AAD 映射**：`VaultKeyProvider` 把 RSS `secure::DerivedAad` 的 canonical bytes 经单一 funnel
//! base64 编码进 Vault Transit `context` 字段，**不使用 `associated_data`**。Vault `/rewrap` 源码对
//! `context` 生效，但非 batch rewrap 不实际使用 `associated_data`；用 `context` 可保留原生 rewrap，避免
//! decrypt+encrypt fallback 把明文拉回 adapter。
//!
//! crate 保持 forbid(unsafe_code)（继承 workspace lints）。

#[cfg(feature = "backend")]
mod transit;

#[cfg(feature = "backend")]
mod secret_resolver;

#[cfg(feature = "backend")]
mod bundle;

#[cfg(feature = "backend")]
pub use bundle::{VaultDomain, VaultDomainDeps, VaultRuntimeDeps, caps};
#[cfg(feature = "backend")]
pub use secret_resolver::{
    StoreBinding, TenantStoreAllowlist, VaultSecretResolver, VaultSecretResolverConfigError,
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

/// Vault Transit ECDSA 签名 marshaling（`marshaling_algorithm` 请求字段）。按消费用途显式构造：
/// - `Asn1`：ASN.1 DER（Vault 默认；X.509/证书签发；响应 `<b64>` 用 STANDARD base64）。
/// - `Jws`：raw r‖s（JWT/JWS 访问 token；响应 `<b64>` 用 URL-safe base64）。
///
/// 选错 ⇒ JWS verifier（期 64B raw r‖s）收到 DER 会验签失败（#1252）；X.509 消费方收到 raw r‖s 同理失败。
/// 此选择是**构造期决策**（newtype funnel），不可在运行期动态切换——确保 `VaultSigner` 实例行为单一且可审计。
#[cfg(feature = "backend")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMarshaling {
    /// ASN.1 DER 编码（X.509/证书签发消费）；Vault 响应 `<b64>` 为 STANDARD base64。
    Asn1,
    /// Raw r‖s 编码（JWT/JWS 消费）；Vault 响应 `<b64>` 为 URL-safe base64（无 padding）。
    Jws,
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
    /// 签名 marshaling：构造期决策，决定请求体 `marshaling_algorithm` 字段与响应签名 base64 解码引擎。
    #[cfg(feature = "backend")]
    marshaling: SignatureMarshaling,
}

/// HashiCorp Vault Transit 字段级加解密 adapter（sealed-marker）。raw 连接物料经 `backend` feature 门控、保持私有。
///
/// 与 [`VaultSigner`] 共享构造安全边界：`https` 默认强制、`new_allow_http` 显式 opt-in、mount 分段校验、
/// token zeroize、请求级 timeout。`DerivedAad` 在执行体内只经 `transit::build_context` 编码为 Vault
/// `context`，请求体不生成 `associated_data` 字段。
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
    /// Vault 地址使用非 https scheme 且未经 `new_allow_http` 显式放行。
    #[error("vault address must use https; use new_allow_http for local dev http opt-in")]
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
}

#[cfg(feature = "backend")]
impl VaultSigner {
    /// 构造 Transit 签名 adapter（**https-only**）。`client` 由组合根预配置 TLS 后注入；`addr` 是 base URL
    /// （形如 `https://vault.example:8200`，尾斜杠 / 含 path 均可）；`mount` 通常 `transit`（支持嵌套 `team/transit`）；
    /// `token` 是 Vault 认证 token；`timeout` 是请求级超时；`marshaling` 决定签名编码——JWT/JWS 用 `Jws`，
    /// X.509/证书签发用 `Asn1`（错选 ⇒ 验签失败，#1252）。非 https / 非法 URL / 空 mount 段 / 空值即 `Err`（fail-fast）。
    pub fn new(
        client: reqwest::Client,
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        timeout: Duration,
        marshaling: SignatureMarshaling,
    ) -> Result<Self, VaultConfigError> {
        Self::build(
            client,
            addr.into(),
            token.into(),
            mount.into(),
            timeout,
            false,
            marshaling,
        )
    }

    /// 同 [`new`](Self::new)，但**显式放行 http**——仅用于本地 dev / 集成测试对接 plaintext Vault；生产禁用
    /// （具名 typed opt-in，greppable；不降级 [`new`](Self::new) 的 https-only 强制）。
    pub fn new_allow_http(
        client: reqwest::Client,
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        timeout: Duration,
        marshaling: SignatureMarshaling,
    ) -> Result<Self, VaultConfigError> {
        Self::build(
            client,
            addr.into(),
            token.into(),
            mount.into(),
            timeout,
            true,
            marshaling,
        )
    }

    fn build(
        client: reqwest::Client,
        addr: String,
        token: String,
        mount: String,
        timeout: Duration,
        allow_http: bool,
        marshaling: SignatureMarshaling,
    ) -> Result<Self, VaultConfigError> {
        let config = validate_vault_config(addr, token, mount, allow_http)?;
        Ok(Self {
            client,
            base: config.base,
            token: config.token,
            mount_segments: config.mount_segments,
            timeout,
            marshaling,
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
        Self::build(
            client,
            addr.into(),
            token.into(),
            mount.into(),
            timeout,
            false,
        )
    }

    /// 同 [`new`](Self::new)，但**显式放行 http**——仅用于本地 dev / 集成测试对接 plaintext Vault。
    pub fn new_allow_http(
        client: reqwest::Client,
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, VaultConfigError> {
        Self::build(
            client,
            addr.into(),
            token.into(),
            mount.into(),
            timeout,
            true,
        )
    }

    fn build(
        client: reqwest::Client,
        addr: String,
        token: String,
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
fn validate_vault_config(
    addr: String,
    token: String,
    mount: String,
    allow_http: bool,
) -> Result<ValidatedVaultConfig, VaultConfigError> {
    if addr.trim().is_empty() {
        return Err(VaultConfigError::EmptyAddr);
    }
    if token.trim().is_empty() {
        return Err(VaultConfigError::EmptyToken);
    }
    let base = reqwest::Url::parse(addr.trim()).map_err(|_| VaultConfigError::InvalidAddr)?;
    match base.scheme() {
        "https" => {}
        "http" if allow_http => {}
        _ => return Err(VaultConfigError::InsecureScheme),
    }
    let mount_segments = parse_mount_segments(&mount)?;
    Ok(ValidatedVaultConfig {
        base,
        token: VaultToken::new(token),
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
impl diport::Signer for VaultSigner {
    async fn sign(
        &self,
        request: diport::SignRequest,
    ) -> Result<diport::Signature, diport::SignerError> {
        transit::sign_impl(
            &self.client,
            &self.base,
            self.token.as_str(),
            &self.mount_segments,
            self.timeout,
            self.marshaling,
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
    //! INVARIANT: ADAPTER-PORT-FREEZE-12 —— sealed-marker impl 冻结的 diport DI port trait（ManagedResource
    //! 始终；Signer 于 backend；SecretResolver + ManagedResource 于 backend）；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::VaultSigner>);
    }

    #[cfg(feature = "backend")]
    fn assert_signer<T: diport::Signer>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_signer() {
        assert_signer(PhantomData::<super::VaultSigner>);
    }

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

    use super::{SignatureMarshaling, VaultConfigError, VaultKeyProvider, VaultSigner};
    use diport::{KeyProvider, ManagedResource, Signer};

    const ADDR: &str = "https://vault.example:8200";
    const TOKEN: &str = "s.testtoken";
    const MOUNT: &str = "transit";
    const TIMEOUT: Duration = Duration::from_secs(30);

    // 构造 helper：合法配置的 VaultSigner。item-level expect carve-out 集中此一处
    // （error-handling.md §Carve-out 要求 item-level），测试体不散落 `expect`。
    #[allow(clippy::expect_used)]
    fn valid_signer() -> VaultSigner {
        VaultSigner::new(
            reqwest::Client::new(),
            ADDR,
            TOKEN,
            MOUNT,
            TIMEOUT,
            SignatureMarshaling::Jws,
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
            VaultSigner::new(
                reqwest::Client::new(),
                "",
                TOKEN,
                MOUNT,
                TIMEOUT,
                SignatureMarshaling::Asn1
            ),
            Err(VaultConfigError::EmptyAddr)
        ));
    }

    #[test]
    fn new_rejects_invalid_url() {
        assert!(matches!(
            VaultSigner::new(
                reqwest::Client::new(),
                "not a url",
                TOKEN,
                MOUNT,
                TIMEOUT,
                SignatureMarshaling::Asn1
            ),
            Err(VaultConfigError::InvalidAddr)
        ));
    }

    #[test]
    fn new_rejects_http_scheme() {
        // F2：默认 https-only；http 经 new() 被拒。
        assert!(matches!(
            VaultSigner::new(
                reqwest::Client::new(),
                "http://vault.example:8200",
                TOKEN,
                MOUNT,
                TIMEOUT,
                SignatureMarshaling::Asn1,
            ),
            Err(VaultConfigError::InsecureScheme)
        ));
    }

    #[test]
    fn new_allow_http_accepts_http() {
        // F2：dev opt-in 具名构造器显式放行 http。
        assert!(
            VaultSigner::new_allow_http(
                reqwest::Client::new(),
                "http://127.0.0.1:8200",
                TOKEN,
                MOUNT,
                TIMEOUT,
                SignatureMarshaling::Jws,
            )
            .is_ok()
        );
    }

    #[test]
    fn new_rejects_empty_mount() {
        assert!(matches!(
            VaultSigner::new(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                "",
                TIMEOUT,
                SignatureMarshaling::Asn1
            ),
            Err(VaultConfigError::EmptyMount)
        ));
    }

    #[test]
    fn new_accepts_nested_mount() {
        // F3：嵌套 mount 拆成多段（不被编码成单段 `%2F`）。
        assert!(
            VaultSigner::new(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                "team/transit",
                TIMEOUT,
                SignatureMarshaling::Asn1
            )
            .is_ok()
        );
    }

    #[test]
    fn new_rejects_mount_path_traversal() {
        // F3：`.`/`..`/空段 拒绝（防路径穿越）。
        assert!(matches!(
            VaultSigner::new(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                "transit/..",
                TIMEOUT,
                SignatureMarshaling::Asn1
            ),
            Err(VaultConfigError::InvalidMountSegment)
        ));
        assert!(matches!(
            VaultSigner::new(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                "a//b",
                TIMEOUT,
                SignatureMarshaling::Asn1
            ),
            Err(VaultConfigError::InvalidMountSegment)
        ));
    }

    #[test]
    fn new_rejects_empty_token() {
        assert!(matches!(
            VaultSigner::new(
                reqwest::Client::new(),
                ADDR,
                "",
                MOUNT,
                TIMEOUT,
                SignatureMarshaling::Asn1
            ),
            Err(VaultConfigError::EmptyToken)
        ));
    }

    #[test]
    fn new_rejects_whitespace_only_token() {
        assert!(matches!(
            VaultSigner::new(
                reqwest::Client::new(),
                ADDR,
                "   ",
                MOUNT,
                TIMEOUT,
                SignatureMarshaling::Asn1
            ),
            Err(VaultConfigError::EmptyToken)
        ));
    }

    #[test]
    fn new_accepts_valid_config() {
        assert!(
            VaultSigner::new(
                reqwest::Client::new(),
                ADDR,
                TOKEN,
                MOUNT,
                TIMEOUT,
                SignatureMarshaling::Jws
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
}

#[cfg(all(test, feature = "integration"))]
mod integration {
    //! Live HashiCorp Vault Transit round-trip（需真 Vault + transit 引擎已 mount + 一个签名 key）。
    //! env fail-closed（对标 adapters/amqp/tests/integration.rs）；`#[ignore]` 默认不跑。
    use super::{SignatureMarshaling, VaultKeyProvider, VaultSigner};
    use diport::{KeyId, KeyName, KeyProvider, KeyRef, SignRequest, Signer, SigningPurpose};
    use secure::{Plaintext, ProtectionContext};
    use vocab::tenant::TenantId;

    // env fail-closed：缺 ADDR/TOKEN 时 `.expect` 大声失败（不静默跳过），对标 amqp 集成测试。
    // item-level expect carve-out（error-handling.md §Carve-out）；`#[ignore]` 已挡默认运行。
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires live Vault + RSS_VAULT_TEST_ADDR/TOKEN (+ transit mount & key)"]
    #[allow(clippy::expect_used)]
    async fn sign_round_trip() {
        let addr = std::env::var("RSS_VAULT_TEST_ADDR")
            .expect("RSS_VAULT_TEST_ADDR must be set to run #[ignore] vault integration tests");
        let token = std::env::var("RSS_VAULT_TEST_TOKEN")
            .expect("RSS_VAULT_TEST_TOKEN must be set to run #[ignore] vault integration tests");
        let mount = std::env::var("RSS_VAULT_TEST_MOUNT").unwrap_or_else(|_| "transit".to_string());
        let key = std::env::var("RSS_VAULT_TEST_KEY").unwrap_or_else(|_| "rss-test".to_string());
        // dev Vault 多为 plaintext http → new_allow_http；必填 request timeout。
        // Jws：集成测试对接 JWT/JWS 签名用途（raw r‖s，URL-safe base64）。
        let signer = VaultSigner::new_allow_http(
            reqwest::Client::new(),
            addr,
            token,
            mount,
            std::time::Duration::from_secs(30),
            SignatureMarshaling::Jws,
        )
        .expect("valid config");
        let signature = signer
            .sign(SignRequest {
                key: KeyId::new(key),
                purpose: SigningPurpose::new("integration-test"),
                message: b"hello-rss".to_vec().into(),
            })
            .await
            .expect("transit sign");
        // adapter 已 decode 出原始签名字节（剥离 vault:vN: 前缀）；非空即签名成功。
        assert!(!signature.as_bytes().is_empty());
    }

    #[allow(clippy::expect_used)]
    fn field_aad(field: &str) -> secure::DerivedAad {
        let tenant =
            TenantId::parse("11111111-2222-4333-8444-555555555555").expect("canonical tenant");
        ProtectionContext::authenticated_request(tenant, "settings/db", field, 1)
            .expect("valid protection context")
            .derive()
    }

    #[allow(clippy::expect_used)]
    fn key_name(raw: String) -> KeyName {
        KeyName::try_new(raw).expect("non-empty key")
    }

    #[allow(clippy::expect_used)]
    fn key_provider_from_env() -> (VaultKeyProvider, KeyName) {
        let addr = std::env::var("RSS_VAULT_TEST_ADDR")
            .expect("RSS_VAULT_TEST_ADDR must be set to run #[ignore] vault integration tests");
        let token = std::env::var("RSS_VAULT_TEST_TOKEN")
            .expect("RSS_VAULT_TEST_TOKEN must be set to run #[ignore] vault integration tests");
        let mount = std::env::var("RSS_VAULT_TEST_MOUNT").unwrap_or_else(|_| "transit".to_string());
        let key = std::env::var("RSS_VAULT_TEST_KEY").unwrap_or_else(|_| "rss-test".to_string());
        let provider = VaultKeyProvider::new_allow_http(
            reqwest::Client::new(),
            addr,
            token,
            mount,
            std::time::Duration::from_secs(30),
        )
        .expect("valid config");
        (provider, key_name(key))
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires live Vault + RSS_VAULT_TEST_ADDR/TOKEN (+ transit mount & derived key)"]
    #[allow(clippy::expect_used)]
    async fn encrypt_decrypt_round_trip() {
        let (provider, key) = key_provider_from_env();
        let aad = field_aad("value");
        let encrypted = provider
            .encrypt(
                key,
                Plaintext::new(b"vault-field-secret".to_vec()),
                aad.clone(),
            )
            .await
            .expect("transit encrypt");
        let decrypted = provider
            .decrypt(
                encrypted.ciphertext().to_vec().into(),
                encrypted.key().clone(),
                aad,
            )
            .await
            .expect("transit decrypt");
        assert_eq!(decrypted.expose(), b"vault-field-secret");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires live Vault + RSS_VAULT_TEST_ADDR/TOKEN (+ transit mount & derived key)"]
    #[allow(clippy::expect_used)]
    async fn decrypt_with_different_aad_fails_closed() {
        let (provider, key) = key_provider_from_env();
        let aad = field_aad("value");
        let encrypted = provider
            .encrypt(key, Plaintext::new(b"vault-field-secret".to_vec()), aad)
            .await
            .expect("transit encrypt");
        let wrong_aad = field_aad("other-field");
        let err = provider
            .decrypt(
                encrypted.ciphertext().to_vec().into(),
                encrypted.key().clone(),
                wrong_aad,
            )
            .await
            .expect_err("AAD mismatch must fail closed");
        assert_eq!(
            err.kind(),
            diport::key_provider::KeyProviderErrorKind::Rejected
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires live Vault + RSS_VAULT_TEST_ADDR/TOKEN (+ transit mount & derived key)"]
    #[allow(clippy::expect_used)]
    async fn rewrap_round_trip_preserves_aad_binding() {
        let (provider, key) = key_provider_from_env();
        let aad = field_aad("value");
        let encrypted = provider
            .encrypt(
                key,
                Plaintext::new(b"vault-field-secret".to_vec()),
                aad.clone(),
            )
            .await
            .expect("transit encrypt");
        let rewrapped = provider
            .rewrap(
                encrypted.ciphertext().to_vec().into(),
                KeyRef::new(encrypted.key().name().clone(), encrypted.key().version()),
                aad.clone(),
            )
            .await
            .expect("transit rewrap");
        let decrypted = provider
            .decrypt(
                rewrapped.ciphertext().to_vec().into(),
                rewrapped.key().clone(),
                aad,
            )
            .await
            .expect("transit decrypt after rewrap");
        assert_eq!(decrypted.expose(), b"vault-field-secret");

        let wrong_aad = field_aad("other-field");
        let err = provider
            .decrypt(
                rewrapped.ciphertext().to_vec().into(),
                rewrapped.key().clone(),
                wrong_aad,
            )
            .await
            .expect_err("rewrapped ciphertext must remain AAD-bound");
        assert_eq!(
            err.kind(),
            diport::key_provider::KeyProviderErrorKind::Rejected
        );
    }
}
