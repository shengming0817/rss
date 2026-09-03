//! vault adapter —— RSS workspace（Transit 与 caller-owned CSR PKI transport）。See `Cargo.toml`、`xtask/src/layers.rs`、`deny.toml` 与 `cargo xtask layer-deps`.
//!
//! `VaultSigner` / `VaultKeyProvider`（sealed-marker）：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-12）。
//! - `backend` feature 开时增补 `impl diport::Signer`（HashiCorp Vault Transit `sign`，见 `transit` 模块）。
//! - `backend` feature 开时增补 `impl diport::KeyProvider`（HashiCorp Vault Transit `encrypt`/`decrypt`/
//!   `rewrap`，见 `transit` 模块）。
//! - `backend` feature 开时增补 concrete Vault PKI transport。它固定调用 Vault PKI
//!   `/sign/{role}`，并在返回 transport evidence 前本地验证 CSR、leaf、chain 与有效期。
//!   Evidence 不是 production authorization receipt；`VaultExternalPkiProviderClosure` 还须将它与
//!   current desired acquisition/receipt 精确 join 后才能 mint production artifact。该层不接触 `/issue` 或私钥。
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
mod secret_resolver;

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

/// HashiCorp Vault Transit 字段级加解密 adapter（sealed-marker）。raw 连接物料经 `backend` feature 门控、保持私有。
///
/// 构造安全边界强制 `https`，仅测试可显式 opt-in `http`；mount 分段校验，
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
mod tests {
    use super::*;

    fn assert_managed<T: diport::ManagedResource>() {}

    #[test]
    fn generic_key_provider_is_a_managed_resource() {
        assert_managed::<VaultKeyProvider>();
    }
}
