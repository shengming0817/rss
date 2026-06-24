//! softca — RSS workspace（W 阶段真身，#1010 dev-CA 签名切片）。See docs/rules/architecture.md.
//!
//! 单一 `SoftCaSigner`（sealed-marker）：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-11）。
//! - `backend` feature 开时增补 `impl diport::Signer`（**ECDSA P-256 软件 dev CA**：构造时生成 / 加载注入
//!   的 CA 私钥，对 deviceloop 递来的 TBS `message` 字节签名，输出 DER ECDSA 签名字节）。
//!
//! **provider 范式**：对标 `adapters/vault`（Transit `sign` 切片，#1011）——sealed-marker + `backend` feature +
//!   fail-fast 构造。`diport::Signer` 是 provider 无关「签字节」port（无 cert 授权 / X.509 组装语义）；X.509
//!   TBS 组装与签名嵌入是消费方 `deviceloop` 的职责，softca 只持 CA 私钥签字节。
//!
//! **撤销 / 两级 CA / Ledger 不在本切片**：需要 `diport` 尚不存在的 `RevocationStore` port（跨域 DI 架构），
//!   属独立 P0-2 epic（pri-P0）；#1010 是 cx-3 adapter，只实现已冻结的 `Signer`（详见 PR body）。
//!
//! **CA 私钥 custody（软件 CA 固有边界——诚实声明，勿夸大）**：
//!   - **进程内裸持是软件 CA 固有的**：CA 私钥 scalar 由 ring `EcdsaKeyPair` 持有**进程生命周期**，ring 不提供
//!     清零句柄（无 public API 暴露私钥，但也**无法**经 ring API zeroize）。`generate` 路径的瞬态 PKCS#8
//!     `Document`（含私钥）同样**不** zeroize-on-drop（ring 0.17 `src/pkcs8.rs` 限制）——drop ≠ 清零。两者皆
//!     无法在 softca 内消除。**故 softca 是 dev / demo CA**；生产签名应走 HSM/KMS 后端（`adapters/vault` 的
//!     `Signer`），不在进程内裸持 CA 私钥。`from_pkcs8` 注入路径中 softca 只借 `&[u8]`、不存副本，调用方负责其
//!     buffer 清零（见该构造器 rustdoc）。
//!   - **Debug 不泄漏私钥（SOFTCA-CA-KEY-NO-DEBUG-01，Medium）**：`EcdsaKeyPair` **虽 impl `Debug`**，但经 ring
//!     `derive_debug_via_field!(.., public_key)` **只渲染 public_key 字段**（私钥 scalar `d` / `nonce_key` 不进
//!     Debug，见 ring 0.17.14 `src/ec/suite_b/ecdsa/signing.rs`）——即便 `SoftCaSigner` 被 Debug-print 私钥也不
//!     泄漏；由 `ring_ecdsa_keypair_debug_excludes_private_key` runtime 测试 regression-lock（ring 升级改 Debug
//!     形态即告警）。
//!
//! crate 保持 forbid(unsafe_code)（继承 workspace lints；ring 的 unsafe 是其 def-site，不外溢本 crate）。

#[cfg(feature = "backend")]
use diport::{KeyId, SignRequest, Signature, Signer, SignerError, SigningPurpose};
use diport::{ManagedResource, ShutdownError};

/// ECDSA P-256 ASN.1（DER）签名算法——签名输出符合 X.509 期望的 DER ECDSA 形态，被 `deviceloop` 嵌入证书。
#[cfg(feature = "backend")]
const CA_ALG: &ring::signature::EcdsaSigningAlgorithm =
    &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;

/// 软件 CA 证书签发 adapter（sealed-marker）。raw key 物料经 `backend` feature 门控、保持私有：
/// - `key_id`：配置的 CA key 标识；`sign` 时与 `SignRequest.key` **fail-closed 精确匹配**（杜绝错 key 盲签）。
/// - `allowed_purposes`：构造期注入的签名用途**闭值集**；`sign` 时 `SignRequest.purpose` 不在集内即 fail-closed
///   拒绝（softca 是本地 CA 私钥持有者、无 Vault ACL 那样的外部授权层，purpose 授权必须由 adapter 自身承载）。
/// - `key_pair`：ring `EcdsaKeyPair`——**不透明持有** CA 私钥（其 `Debug` 只渲染 public_key、私钥不外泄，见 crate rustdoc custody 段）。
/// - `rng`：签名随机数源（ECDSA nonce）。
/// - `public_key`：缓存的 CA 公钥（SEC1 未压缩点，`0x04 ‖ X ‖ Y`）——供 trust-bundle 导出 / verify。
pub struct SoftCaSigner {
    #[cfg(feature = "backend")]
    key_id: KeyId,
    #[cfg(feature = "backend")]
    allowed_purposes: Vec<SigningPurpose>,
    #[cfg(feature = "backend")]
    key_pair: ring::signature::EcdsaKeyPair,
    #[cfg(feature = "backend")]
    rng: ring::rand::SystemRandom,
    #[cfg(feature = "backend")]
    public_key: Vec<u8>,
}

/// 构造期 fail-fast / 签名 fail-closed 错误（非静默 noop）。`#[error]` 为静态字面量，不含 runtime 数据。
#[cfg(feature = "backend")]
#[derive(Debug, thiserror::Error)]
pub enum SoftCaError {
    /// CA key 标识为空。
    #[error("softca key id must not be empty")]
    EmptyKeyId,
    /// CA 密钥对生成失败（RNG 故障等）。
    #[error("softca ca key generation failed")]
    KeyGenFailed,
    /// 注入的 PKCS#8 私钥物料非法（解析失败 / 非 P-256）。
    #[error("softca pkcs8 key material is invalid")]
    InvalidPkcs8,
    /// 允许的签名用途闭值集为空——CA 不允许任何 purpose 是配置错误（fail-fast，非静默放行所有）。
    #[error("softca allowed purpose set must not be empty")]
    EmptyPurposeAllowlist,
    /// 签名请求 key 与配置的 CA key 不匹配（fail-closed）。
    #[error("softca sign request key id does not match the configured ca key")]
    KeyIdMismatch,
    /// 签名请求 purpose 不在 CA 允许的闭值集内（fail-closed 授权拒绝）。
    #[error("softca sign request purpose is not in the configured allowlist")]
    PurposeNotAllowed,
    /// 签名运算失败。
    #[error("softca signing operation failed")]
    SignFailed,
}

#[cfg(feature = "backend")]
impl SoftCaSigner {
    /// 生成全新 ECDSA P-256 dev CA（**ephemeral**——进程重启即换信任锚，适合 demo / 集成测试 / smoke）。
    /// `key_id` 是该 CA key 的配置标识（`sign` 时 fail-closed 匹配）；`allowed_purposes` 是允许的签名用途闭值集
    /// （`sign` 时 fail-closed 授权）。空 `key_id` → `Err(EmptyKeyId)`，空用途集 → `Err(EmptyPurposeAllowlist)`。
    /// 与 [`from_pkcs8`](Self::from_pkcs8) 的区别：本构造器每次生成全新随机 CA，信任锚**不**跨进程稳定。
    ///
    /// **私钥 custody（软件 CA 固有边界，见 crate rustdoc custody 段）**：本路径经 ring `generate_pkcs8` 产生一份
    /// 瞬态 PKCS#8（含私钥），ring 的 `Document` **不** zeroize-on-drop（ring 0.17 `src/pkcs8.rs` 限制）；且生成的
    /// 私钥随后由 `EcdsaKeyPair` 持有进程生命周期、同样无法经 ring API 清零。两者皆软件 CA 固有——故 `generate` 仅
    /// 限 **dev / ephemeral**，生产签名应走 HSM/KMS 后端（`adapters/vault` 的 `Signer`），不在进程内裸持 CA 私钥。
    pub fn generate(
        key_id: impl Into<String>,
        allowed_purposes: impl IntoIterator<Item = SigningPurpose>,
    ) -> Result<Self, SoftCaError> {
        let key_id = Self::validated_key_id(key_id)?;
        let allowed_purposes = Self::validated_purposes(allowed_purposes)?;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(CA_ALG, &rng)
            .map_err(|_| SoftCaError::KeyGenFailed)?;
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(CA_ALG, pkcs8.as_ref(), &rng)
            .map_err(|_| SoftCaError::KeyGenFailed)?;
        let signer = Self::assemble(key_id, allowed_purposes, key_pair, rng);
        // PKI 信任锚变更可审计轨迹：仅记 key_id（非秘密标识），私钥物料不进 span。
        tracing::info!(
            key_id = signer.key_id.as_str(),
            "softca: generated ephemeral dev ca key pair"
        );
        Ok(signer)
    }

    /// 加载组合根注入的持久 PKCS#8（DER）CA 私钥。`key_id` / `allowed_purposes` 同 [`generate`](Self::generate)；
    /// 非法 DER / 非 P-256 即 `Err(InvalidPkcs8)`。
    ///
    /// **适用场景**：持久 dev CA——信任锚跨进程重启稳定（集成测试固定 anchor / 组合根注入 secret-stored
    /// PKCS#8 key）；ephemeral 场景用 [`generate`](Self::generate)。
    ///
    /// **调用方职责（私钥 custody）**：`pkcs8_der` 指向的内存含 CA 私钥物料；softca 仅借引用、不持有该 buffer 副本，
    /// 调用方应在本函数返回后立即清零其来源 buffer（`zeroize::Zeroize` 或手动覆写）。注意：加载后的私钥仍由
    /// `EcdsaKeyPair` 持有进程生命周期、无法经 ring API 清零——生产强 custody 须走 HSM/KMS（`adapters/vault`）。
    pub fn from_pkcs8(
        key_id: impl Into<String>,
        allowed_purposes: impl IntoIterator<Item = SigningPurpose>,
        pkcs8_der: &[u8],
    ) -> Result<Self, SoftCaError> {
        let key_id = Self::validated_key_id(key_id)?;
        let allowed_purposes = Self::validated_purposes(allowed_purposes)?;
        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(CA_ALG, pkcs8_der, &rng)
            .map_err(|_| SoftCaError::InvalidPkcs8)?;
        let signer = Self::assemble(key_id, allowed_purposes, key_pair, rng);
        tracing::info!(
            key_id = signer.key_id.as_str(),
            "softca: loaded pkcs8 dev ca key pair"
        );
        Ok(signer)
    }

    /// 借出 CA 公钥（SEC1 未压缩点）——供组合根 / `deviceloop` 组装 trust bundle、或验签。
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// key_id newtype funnel：去空校验（fail-fast，非静默）。
    fn validated_key_id(key_id: impl Into<String>) -> Result<KeyId, SoftCaError> {
        let key_id = key_id.into();
        if key_id.trim().is_empty() {
            return Err(SoftCaError::EmptyKeyId);
        }
        Ok(KeyId::new(key_id))
    }

    /// 用途闭值集校验：收集 + 去重，空集即 `Err(EmptyPurposeAllowlist)`（CA 不允许任何 purpose = 配置错误，
    /// fail-fast 而非静默放行所有）。
    fn validated_purposes(
        allowed_purposes: impl IntoIterator<Item = SigningPurpose>,
    ) -> Result<Vec<SigningPurpose>, SoftCaError> {
        let mut purposes: Vec<SigningPurpose> = Vec::new();
        for purpose in allowed_purposes {
            if !purposes.contains(&purpose) {
                purposes.push(purpose);
            }
        }
        if purposes.is_empty() {
            return Err(SoftCaError::EmptyPurposeAllowlist);
        }
        Ok(purposes)
    }

    /// 由已加载的密钥对组装 signer，缓存 SEC1 公钥点（两构造器单一汇聚点）。
    fn assemble(
        key_id: KeyId,
        allowed_purposes: Vec<SigningPurpose>,
        key_pair: ring::signature::EcdsaKeyPair,
        rng: ring::rand::SystemRandom,
    ) -> Self {
        use ring::signature::KeyPair;
        let public_key = key_pair.public_key().as_ref().to_vec();
        Self {
            key_id,
            allowed_purposes,
            key_pair,
            rng,
            public_key,
        }
    }
}

#[cfg(feature = "backend")]
impl Signer for SoftCaSigner {
    // 结构化 span（对标 adapters/vault transit sign）：`skip_all` 杜绝 self / request.message（敏感）进 span；
    // 仅记 key / purpose 等非秘密归因字段——私钥物料 / 签名字节永不进 span / 日志。
    #[tracing::instrument(
        name = "softca.sign",
        skip_all,
        fields(resource = "softca", operation = "sign", key = request.key.as_str(), purpose = request.purpose.as_str())
    )]
    async fn sign(&self, request: SignRequest) -> Result<Signature, SignerError> {
        // fail-closed：请求 key 必须精确匹配配置的 CA key——杜绝错 key 盲签。key-id 是非秘密配置标识
        // （非机密、值集有限），故 `PartialEq` 等值比较不需要常量时间；若将来 key-id 承载机密性，改用
        // `subtle::ConstantTimeEq`。INVARIANT: SOFTCA-SIGN-FAILCLOSED-KEYID-01（Medium，runtime 测试）。
        if request.key != self.key_id {
            // key-id 不匹配是潜在越权签名信号（安全相关）——warn 级留痕供运维 / 审计定位。
            tracing::warn!("softca: sign rejected — key id does not match configured ca key");
            return Err(SignerError::new(SoftCaError::KeyIdMismatch));
        }
        // fail-closed purpose 授权：softca 是本地 CA 私钥持有者、无 Vault ACL 那样的外部授权层，故 purpose
        // 必须由 adapter 自身按闭值集校验（`diport::Signer` port 契约：provider 据 key/purpose fail-closed
        // 校验，杜绝裸 message 盲签）。INVARIANT: SOFTCA-SIGN-FAILCLOSED-PURPOSE-01（Medium，runtime 测试）。
        if !self.allowed_purposes.contains(&request.purpose) {
            tracing::warn!("softca: sign rejected — purpose not in configured allowlist");
            return Err(SignerError::new(SoftCaError::PurposeNotAllowed));
        }
        // ring 内部 SHA-256(message) 后 ECDSA-P256 签名，输出 DER（ASN.1）签名字节。
        let signature = self
            .key_pair
            .sign(&self.rng, &request.message)
            .map_err(|_| {
                tracing::error!("softca: signing operation failed");
                SignerError::new(SoftCaError::SignFailed)
            })?;
        Ok(Signature::new(signature.as_ref().to_vec()))
    }

    async fn shutdown(&self) -> Result<(), SignerError> {
        // reason: 同 ManagedResource::shutdown——纯进程内、无外部资源可释放（对标 adapters/vault）。
        Ok(())
    }
}

impl ManagedResource for SoftCaSigner {
    fn name(&self) -> &str {
        "softca"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: 同 Signer::shutdown——纯进程内、无外部资源可释放。
        Ok(())
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait（PhantomData 绑定检查，
    //! 不构造、不执行 body）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-11 —— sealed-marker impl 冻结的 diport DI port trait（ManagedResource
    //! 始终；Signer 于 backend）；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::SoftCaSigner>);
    }

    #[cfg(feature = "backend")]
    fn assert_signer<T: diport::Signer>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_signer() {
        assert_signer(PhantomData::<super::SoftCaSigner>);
    }
}

#[cfg(all(test, feature = "backend"))]
mod backend_tests {
    //! 构造 fail-fast（空 key_id / 非法 PKCS#8）+ sign→verify round-trip（表驱动）+ fail-closed key 匹配 +
    //! 篡改签名拒绝 + 生命周期（name + 双 shutdown），全进程内、无外部 infra（无 `#[ignore]`）。
    use super::{SoftCaError, SoftCaSigner};
    use diport::{KeyId, ManagedResource, SignRequest, Signer, SigningPurpose};
    use ring::signature;

    const KEY_ID: &str = "softca-dev";
    const PURPOSE: &str = "device-cert";

    // 允许的签名用途闭值集（每次构造新副本——SigningPurpose 非 Copy）。
    fn allowlist() -> Vec<SigningPurpose> {
        vec![SigningPurpose::new(PURPOSE)]
    }

    // 构造 helper：合法 ephemeral dev CA。item-level expect carve-out 集中此处（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used)]
    fn dev_signer() -> SoftCaSigner {
        SoftCaSigner::generate(KEY_ID, allowlist()).expect("generate dev ca")
    }

    fn sign_request(key: &str, message: &[u8]) -> SignRequest {
        sign_request_for(key, PURPOSE, message)
    }

    fn sign_request_for(key: &str, purpose: &str, message: &[u8]) -> SignRequest {
        SignRequest {
            key: KeyId::new(key),
            purpose: SigningPurpose::new(purpose),
            message: message.to_vec(),
        }
    }

    // verify helper：用 CA 公钥（SEC1 点）按 ECDSA-P256-SHA256-ASN1 验签。
    fn verify(public_key: &[u8], message: &[u8], sig: &[u8]) -> bool {
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key)
            .verify(message, sig)
            .is_ok()
    }

    #[test]
    fn generate_rejects_empty_key_id() {
        assert!(matches!(
            SoftCaSigner::generate("   ", allowlist()),
            Err(SoftCaError::EmptyKeyId)
        ));
    }

    #[test]
    fn generate_rejects_empty_purpose_allowlist() {
        // fail-fast：CA 不允许任何 purpose = 配置错误（非静默放行所有）。
        let empty: Vec<SigningPurpose> = Vec::new();
        assert!(matches!(
            SoftCaSigner::generate(KEY_ID, empty),
            Err(SoftCaError::EmptyPurposeAllowlist)
        ));
    }

    #[test]
    fn from_pkcs8_rejects_invalid_der() {
        assert!(matches!(
            SoftCaSigner::from_pkcs8(KEY_ID, allowlist(), b"not-a-pkcs8-document"),
            Err(SoftCaError::InvalidPkcs8)
        ));
    }

    #[test]
    fn from_pkcs8_rejects_empty_key_id() {
        // 与 generate_rejects_empty_key_id 配对：两构造器共用 validated_key_id，但 from_pkcs8 路径独立覆盖。
        // key_id 先于 pkcs8 解析校验 ⇒ 空 key_id（即便 pkcs8 也无效）返回 EmptyKeyId 而非 InvalidPkcs8。
        assert!(matches!(
            SoftCaSigner::from_pkcs8("   ", allowlist(), b"dummy"),
            Err(SoftCaError::EmptyKeyId)
        ));
    }

    // multi_thread + spawn：boxed Signer future 须 Send（trait_variant Send 变体）才能跨 worker 调度。
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::expect_used)]
    async fn sign_verify_round_trip() {
        let signer = dev_signer();
        let public_key = signer.public_key().to_vec();
        let big = [0x42u8; 512];
        // 表驱动：空 / 短 / 二进制 / 大 message。
        let messages: [&[u8]; 4] = [b"", b"short", b"\xDE\xAD\xBE\xEF", &big];
        for message in messages {
            let sig = signer
                .sign(sign_request(KEY_ID, message))
                .await
                .expect("sign");
            assert!(
                verify(&public_key, message, sig.as_bytes()),
                "round-trip verify failed for {}-byte message",
                message.len()
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::expect_used)]
    async fn from_pkcs8_round_trips() {
        // 外部生成 PKCS#8 → from_pkcs8 加载 → sign→verify 通过（证明注入路径等价）。
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .expect("generate pkcs8");
        let signer =
            SoftCaSigner::from_pkcs8(KEY_ID, allowlist(), pkcs8.as_ref()).expect("load pkcs8");
        let sig = signer
            .sign(sign_request(KEY_ID, b"payload"))
            .await
            .expect("sign");
        assert!(verify(signer.public_key(), b"payload", sig.as_bytes()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_rejects_key_id_mismatch() {
        // fail-closed：请求 key != 配置 CA key → Err（杜绝错 key 盲签）。
        // INVARIANT: SOFTCA-SIGN-FAILCLOSED-KEYID-01（Medium，runtime 测试）。
        let signer = dev_signer();
        let result = signer.sign(sign_request("attacker-key", b"payload")).await;
        assert!(result.is_err(), "mismatched key id must be rejected");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_rejects_purpose_not_allowed() {
        // fail-closed：purpose 不在闭值集 → Err（softca 自身承载 purpose 授权，无外部 ACL 层）。
        // INVARIANT: SOFTCA-SIGN-FAILCLOSED-PURPOSE-01。anti-vacuity 配对：允许的 purpose 可签（见 round_trip）。
        let signer = dev_signer();
        let result = signer
            .sign(sign_request_for(KEY_ID, "unauthorized-purpose", b"payload"))
            .await;
        assert!(result.is_err(), "disallowed purpose must be rejected");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::expect_used)]
    async fn tampered_signature_fails_verify() {
        // anti-vacuity 配对：同一签名未篡改时 verify 通过（见 round_trip），篡改后失败。
        // 翻转**末字节**（DER ECDSA 签名的 s 值尾部，不动 SEQUENCE / INTEGER 长度字节）——确保覆盖
        // 「DER 结构完整但签名值错误」的 verify-failed 路径，而非 DER parse-failed 路径。
        let signer = dev_signer();
        let sig = signer
            .sign(sign_request(KEY_ID, b"payload"))
            .await
            .expect("sign");
        let mut bytes = sig.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // 翻转 s 值尾部一 bit → 结构完整、签名值无效。
        assert!(!verify(signer.public_key(), b"payload", &bytes));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn ring_ecdsa_keypair_debug_excludes_private_key() {
        // SOFTCA-CA-KEY-NO-DEBUG-01 regression lock（Medium）：ring `EcdsaKeyPair` 经
        // `derive_debug_via_field!(.., public_key)`（ring 0.17.14 src/ec/suite_b/ecdsa/signing.rs:68）
        // 只渲染 public_key 字段——私钥 scalar `d` / `nonce_key` 不进 Debug。若 ring 升级改 Debug 形态把
        // 私钥字段名带进来，下方断言失效告警（softca 据此确认「即便 SoftCaSigner Debug-print 也不漏私钥」）。
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .expect("generate pkcs8");
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .expect("load pkcs8");
        let dbg = format!("{key_pair:?}");
        // anti-vacuity：Debug 含类型名（断言非空转）；且不含私钥字段名 `d` / `nonce_key`。
        assert!(dbg.contains("EcdsaKeyPair"), "ring Debug 形态变更: {dbg}");
        assert!(
            !dbg.contains("nonce_key"),
            "ring Debug 泄漏 nonce_key: {dbg}"
        );
        assert!(
            !dbg.contains("Scalar"),
            "ring Debug 泄漏私钥 scalar 类型: {dbg}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lifecycle_name_and_shutdowns() {
        let signer = dev_signer();
        assert_eq!(ManagedResource::name(&signer), "softca");
        assert!(ManagedResource::shutdown(&signer).await.is_ok());
        assert!(Signer::shutdown(&signer).await.is_ok());
    }
}
