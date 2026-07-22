//! softca — RSS workspace（W 阶段真身，#1010 dev-CA 签名 + #1260 撤销 store 切片）。See docs/rules/architecture.md.
//!
//! 两个 provider（impl 真身均 `backend` feature 门控）：
//! - `SoftCaSigner`（sealed-marker）：始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-11）；
//!   `backend` 增补 `impl diport::Signer`（**ECDSA P-256 软件 dev CA**：构造时生成 / 加载注入的 CA 私钥，对
//!   deviceloop 递来的 TBS `message` 字节签名，输出 DER ECDSA 签名字节）。
//! - `InMemRevocationLedger`（#1260 P0-2 首切片）：`backend` 时 `impl diport::RevocationStore`——in-mem 撤销集，
//!   按 `(CertScope, CertSerial)` 键 correct-by-construction 租户 + 设备隔离，Clock 戳撤销时刻、`revoke` 幂等。
//!
//! **provider 范式**：对标 `adapters/vault`（Transit `sign` 切片，#1011）——sealed-marker + `backend` feature +
//!   fail-fast 构造。`diport::Signer` 是 provider 无关「签字节」port（无 cert 授权 / X.509 组装语义）；X.509
//!   TBS 组装与签名嵌入是消费方 `deviceloop` 的职责，softca 只持 CA 私钥签字节。
//!
//! **两级 CA / 共享 Ledger / CRL 仍不在本切片**：root→intermediate split、signer/revocation 同源共享 Ledger、
//!   DER CRL 单调 Number 导出 + `revoked_at` 生产读路径属 P0-2 后续 wave（epic #991）；本切片
//!   `InMemRevocationLedger` 是独立测试/开发用的非持久 store（重启清空）；runtime assembly 固定使用
//!   PostgreSQL 持久 provider。
//!   `InMemRevocationLedger` 不在 runtime provider catalog 中提供 constructor 或 fallback。
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
use diport::{
    CertNotAfter, CertScope, CertSerial, Clock, KeyId, RevocationStore, RevocationStoreError,
    SignRequest, Signature, Signer, SignerError, SigningPurpose,
};
use diport::{ManagedResource, ShutdownError};
#[cfg(feature = "backend")]
use std::collections::HashMap;
#[cfg(feature = "backend")]
use std::sync::{Mutex, PoisonError};
#[cfg(feature = "backend")]
use std::time::SystemTime;

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

/// In-memory revocation validation failures. Messages are static and are wrapped by
/// [`RevocationStoreError`], so provider details never cross the port boundary.
#[cfg(feature = "backend")]
#[derive(Debug, thiserror::Error)]
enum SoftCaRevocationError {
    #[error("certificate not-after is not in the future")]
    ExpiredNotAfter,
    #[error("certificate revocation expiry conflicts with the existing record")]
    ConflictingExpiry,
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
        // `subtle::ConstantTimeEq`。INVARIANT: SOFTCA-SIGN-FAILCLOSED-KEYID-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（Medium，runtime 测试）。
        if request.key != self.key_id {
            // key-id 不匹配是潜在越权签名信号（安全相关）——warn 级留痕供运维 / 审计定位。
            tracing::warn!("softca: sign rejected — key id does not match configured ca key");
            return Err(SignerError::new(SoftCaError::KeyIdMismatch));
        }
        // fail-closed purpose 授权：softca 是本地 CA 私钥持有者、无 Vault ACL 那样的外部授权层，故 purpose
        // 必须由 adapter 自身按闭值集校验（`diport::Signer` port 契约：provider 据 key/purpose fail-closed
        // 校验，杜绝裸 message 盲签）。INVARIANT: SOFTCA-SIGN-FAILCLOSED-PURPOSE-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（Medium，runtime 测试）。
        if !self.allowed_purposes.contains(&request.purpose) {
            tracing::warn!("softca: sign rejected — purpose not in configured allowlist");
            return Err(SignerError::new(SoftCaError::PurposeNotAllowed));
        }
        // ring 内部 SHA-256(message) 后 ECDSA-P256 签名，输出 DER（ASN.1）签名字节。
        let signature = self
            .key_pair
            .sign(&self.rng, request.message.as_bytes())
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

/// in-mem 证书撤销 Ledger（dev / demo `RevocationStore` provider）。
///
/// **correct-by-construction 隔离**：撤销记录按 `(CertScope, CertSerial)` 键存——`CertScope`（tenant + device）
/// 是键的一部分，跨租户 / 跨设备的 `is_revoked` 天然返回 `false`（webpki `find_serial` 未命中语义），无需运行期
/// scope gate。**幂等**：重复撤销同一 `(scope, serial)` 经 `entry().or_insert` 保留首次撤销时刻。
///
/// **测试 / 开发边界**：进程内、非持久（重启即清空撤销集），仅作为独立 adapter/conformance
/// 实现；runtime assembly 不提供可选 constructor 或 fallback，固定使用 PostgreSQL 持久 provider。
/// 与 [`SoftCaSigner`] 解耦（独立 struct）：本切片只落 store，signer / revocation 共享 Ledger（同源、两级 CA）
/// 属 P0-2 后续 wave。
#[cfg(feature = "backend")]
pub struct InMemRevocationLedger {
    clock: Box<dyn Clock>,
    // value = 首次撤销时刻（Clock 戳）。**CRL 前瞻**：本切片只记不经 port 暴露——`revoked_at` 读路径 + DER CRL
    // 单调 Number 导出由 P0-2 后续 wave 落地（届时 is_revoked 之外增 revocation-list 查询）。当前由
    // `#[cfg(test)]` 的 `revoked_at` 断言记录正确，非死状态。
    revoked: Mutex<HashMap<(CertScope, CertSerial), InMemRevocation>>,
}

#[cfg(feature = "backend")]
#[derive(Clone, Copy)]
struct InMemRevocation {
    revoked_at: SystemTime,
    not_after: CertNotAfter,
}

#[cfg(feature = "backend")]
impl InMemRevocationLedger {
    /// 构造空 Ledger。`clock` 是**必填构造器位置参**（rust-standards：Clock 禁 builder / 禁默认系统时钟）——
    /// revoke 据此戳撤销时刻；组合根注入 `SystemClock`，测试注入确定性替身。
    ///
    /// **⚠ 非持久（仅独立测试 / 开发）**：撤销集存进程内存，**重启即清空所有撤销记录**——退役 / 泄漏的证书在重启后
    /// 重新被判定为「未撤销」。runtime assembly 不允许选择该实现或回退到该实现。
    pub fn new(clock: Box<dyn Clock>) -> Self {
        Self {
            clock,
            revoked: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(feature = "backend")]
impl RevocationStore for InMemRevocationLedger {
    #[tracing::instrument(
        name = "softca.revoke",
        skip_all,
        fields(resource = "softca", operation = "revoke")
    )]
    async fn revoke(
        &self,
        serial: CertSerial,
        scope: CertScope,
        not_after: CertNotAfter,
    ) -> Result<(), RevocationStoreError> {
        let at = self.clock.now();
        if not_after.as_system_time() <= at {
            return Err(RevocationStoreError::new(
                SoftCaRevocationError::ExpiredNotAfter,
            ));
        }
        // lock poison 恢复（不 panic）：当前撤销集（HashMap）无跨操作一致性不变式，毒化的内层状态仍可安全续用
        // （unwrap_or_else，禁 unwrap）；若将来撤销集引入不变式（如 CRL 单调 Number），须重评此恢复语义。
        let mut guard = self.revoked.lock().unwrap_or_else(PoisonError::into_inner);
        // 同 expiry 幂等且保留首次时间；不同 expiry 是调用方数据冲突，禁止覆盖、延长或截短。
        match guard.entry((scope, serial)) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(InMemRevocation {
                    revoked_at: at,
                    not_after,
                });
            }
            std::collections::hash_map::Entry::Occupied(entry)
                if entry.get().not_after == not_after => {}
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(RevocationStoreError::new(
                    SoftCaRevocationError::ConflictingExpiry,
                ));
            }
        }
        // 撤销是安全相关事件——留审计轨迹；仅记 tenant / device 非机密标识（device 取 uuid，DeviceId 无 Display）。
        tracing::info!(
            tenant = %scope.tenant(),
            device = %scope.device().as_uuid(),
            "softca: certificate revoked"
        );
        Ok(())
    }

    // 撤销查询是证书校验热路径——debug 级 span（默认静默、开 debug 可观测查询轨迹）；仅记 tenant / device
    // 非机密标识，结果 `revoked` 入 span。skip_all 杜绝 serial / self 进 span。
    #[tracing::instrument(
        name = "softca.is_revoked",
        skip_all,
        level = "debug",
        fields(resource = "softca", operation = "is_revoked", tenant = %scope.tenant(), device = %scope.device().as_uuid())
    )]
    async fn is_revoked(
        &self,
        serial: CertSerial,
        scope: CertScope,
    ) -> Result<bool, RevocationStoreError> {
        let now = self.clock.now();
        let guard = self.revoked.lock().unwrap_or_else(PoisonError::into_inner);
        let revoked = guard
            .get(&(scope, serial))
            .is_some_and(|record| record.not_after.as_system_time() > now);
        tracing::debug!(revoked, "softca: revocation status checked");
        Ok(revoked)
    }

    async fn shutdown(&self) -> Result<(), RevocationStoreError> {
        // reason: 纯进程内 in-mem 撤销集，无外部资源可释放（同 SoftCaSigner::shutdown）。
        Ok(())
    }
}

// F2：与 `SoftCaSigner` 对称——撤销 Ledger 也 impl ManagedResource，使组合根可经 `bootstrap::ShutdownStack`
// 统一逆序编排关闭（当前 in-mem 无外部资源，shutdown 为 noop；持久 CRL/OCSP 替换后此路径承载真实 teardown）。
#[cfg(feature = "backend")]
impl ManagedResource for InMemRevocationLedger {
    fn name(&self) -> &str {
        "softca-revocation-ledger"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: 纯进程内 in-mem 撤销集，无外部资源可释放（同 RevocationStore::shutdown）。
        Ok(())
    }
}

#[cfg(all(test, feature = "backend"))]
impl InMemRevocationLedger {
    /// 测试支持：读回撤销时刻——断言 Clock 戳的时间被正确记录（让记录的时间在本切片即被测，非死状态）。
    /// `#[cfg(test)]`：生产读路径（CRL 导出）属 P0-2 后续 wave，不在本切片暴露。
    pub(crate) fn revoked_at(&self, serial: CertSerial, scope: CertScope) -> Option<SystemTime> {
        let guard = self.revoked.lock().unwrap_or_else(PoisonError::into_inner);
        guard.get(&(scope, serial)).map(|record| record.revoked_at)
    }

    /// 测试支持：故意毒化撤销集 `Mutex`（同线程持锁 `panic` + `catch_unwind` 同帧捕获，不外传）——驱动
    /// `revoke` / `is_revoked` 的 lock-poison 恢复分支（`unwrap_or_else(PoisonError::into_inner)`，F5）。
    /// 生产代码无任何路径在持 `self.revoked` 锁时 panic，故该恢复分支只能经本测试钩子驱动。
    #[allow(clippy::unwrap_used, clippy::panic)]
    pub(crate) fn poison_lock_for_test(&self) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.revoked.lock().unwrap();
            panic!("intentional poison for test");
        }));
        debug_assert!(outcome.is_err(), "poison helper 应捕获 panic");
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait（PhantomData 绑定检查，
    //! 不构造、不执行 body）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-11 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— sealed-marker impl 冻结的 diport DI port trait（`SoftCaSigner`：
    //! ManagedResource 始终 / Signer 于 backend；`InMemRevocationLedger`：RevocationStore + ManagedResource 于
    //! backend）；去掉任一 impl 即编译失败（anti-vacuity）。
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

    #[cfg(feature = "backend")]
    fn assert_revocation_store<T: diport::RevocationStore>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_revocation_store() {
        // InMemRevocationLedger 始终 impl RevocationStore（backend）；去掉即编译失败（anti-vacuity）。
        assert_revocation_store(PhantomData::<super::InMemRevocationLedger>);
    }

    #[cfg(feature = "backend")]
    #[test]
    fn ledger_impls_managed_resource() {
        // F2：撤销 Ledger 与 SoftCaSigner 对称 impl ManagedResource（backend）；去掉即编译失败（anti-vacuity）。
        assert_managed_resource(PhantomData::<super::InMemRevocationLedger>);
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
            message: message.to_vec().into(),
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
        // INVARIANT: SOFTCA-SIGN-FAILCLOSED-KEYID-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（Medium，runtime 测试）。
        let signer = dev_signer();
        let result = signer.sign(sign_request("attacker-key", b"payload")).await;
        assert!(result.is_err(), "mismatched key id must be rejected");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_rejects_purpose_not_allowed() {
        // fail-closed：purpose 不在闭值集 → Err（softca 自身承载 purpose 授权，无外部 ACL 层）。
        // INVARIANT: SOFTCA-SIGN-FAILCLOSED-PURPOSE-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。anti-vacuity 配对：允许的 purpose 可签（见 round_trip）。
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

#[cfg(all(test, feature = "backend"))]
mod revocation_tests {
    //! InMemRevocationLedger：revoke→is_revoked round-trip + (tenant,device) scope 隔离 + 幂等（保留首次
    //! 撤销时刻）+ Clock 戳撤销时间 + shutdown，全进程内、无外部 infra（无 `#[ignore]`）。
    use super::InMemRevocationLedger;
    use diport::{CertNotAfter, CertScope, CertSerial, Clock, RevocationStore};
    use ids::DeviceId;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime};
    use vocab::TenantId;

    // canonical lowercase-hyphenated（TenantId::parse fail-closed 只认 canonical）；DeviceId 同步用 canonical。
    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "a1a2a3a4-b1b2-4cc3-8dd4-e1e2e3e4e5e6";
    const DEVICE_1: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_2: &str = "22222222-2222-4222-8222-222222222222";
    // 确定性起始撤销时刻（非系统时钟，不触 disallowed_methods）。
    const REVOKED_AT_SECS: u64 = 1_700_000_000;

    // 单调推进 Clock 替身：每次 now() +1s。验「撤销时间被记 + 幂等保留**首次**时刻」——固定 clock 无法区分
    // 首 / 次插入，推进 clock 才能证明二次 revoke 的 or_insert 不覆盖首次戳。
    struct AdvancingClock {
        secs: AtomicU64,
    }
    impl AdvancingClock {
        fn starting_at(secs: u64) -> Self {
            Self {
                secs: AtomicU64::new(secs),
            }
        }
    }
    impl Clock for AdvancingClock {
        fn now(&self) -> SystemTime {
            let s = self.secs.fetch_add(1, Ordering::SeqCst);
            SystemTime::UNIX_EPOCH + Duration::from_secs(s)
        }
    }

    #[derive(Clone)]
    struct SharedClock {
        secs: std::sync::Arc<AtomicU64>,
    }

    impl Clock for SharedClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(self.secs.load(Ordering::SeqCst))
        }
    }

    struct ConformanceHarness {
        ledger: InMemRevocationLedger,
        clock: std::sync::Arc<AtomicU64>,
    }

    fn conformance_harness() -> ConformanceHarness {
        let clock = std::sync::Arc::new(AtomicU64::new(10));
        let ledger = InMemRevocationLedger::new(Box::new(SharedClock {
            secs: std::sync::Arc::clone(&clock),
        }));
        ConformanceHarness { ledger, clock }
    }

    fn ledger() -> InMemRevocationLedger {
        InMemRevocationLedger::new(Box::new(AdvancingClock::starting_at(REVOKED_AT_SECS)))
    }

    // unwrap carve-out 集中此 helper（item-level）：canonical 常量保证 parse 成功。
    #[allow(clippy::unwrap_used)]
    fn scope(tenant: &str, device: &str) -> CertScope {
        CertScope::new(
            TenantId::parse(tenant).unwrap(),
            DeviceId::parse(device).unwrap(),
        )
    }

    fn serial() -> CertSerial {
        serial_bytes(vec![0x01, 0x02, 0x03, 0x04])
    }

    #[allow(clippy::unwrap_used)]
    fn not_after() -> CertNotAfter {
        CertNotAfter::try_from_system_time(
            SystemTime::UNIX_EPOCH + Duration::from_secs(REVOKED_AT_SECS + 3_600),
        )
        .unwrap()
    }

    // unwrap carve-out 集中此 helper（item-level）：canonical 1–20 字节 serial 必构造成功。
    #[allow(clippy::unwrap_used)]
    fn serial_bytes(bytes: impl Into<Vec<u8>>) -> CertSerial {
        CertSerial::try_new(bytes).unwrap()
    }

    #[allow(clippy::unwrap_used)]
    fn expiry(seconds: u64) -> CertNotAfter {
        CertNotAfter::try_from_system_time(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn revocation_provider_conformance() {
        let cases = testkit::revocation::RevocationCases {
            primary_scope: scope(TENANT_A, DEVICE_1),
            other_tenant_scope: scope(TENANT_B, DEVICE_1),
            other_device_scope: scope(TENANT_A, DEVICE_2),
            primary_serial: serial_bytes(vec![0x01]),
            rotated_serial: serial_bytes(vec![0x02]),
            concurrent_serial: serial_bytes(vec![0x03]),
            concurrent_conflict_serial: serial_bytes(vec![0x04]),
            expired_serial: serial_bytes(vec![0x05]),
            valid_expiry: expiry(20),
            conflicting_expiry: expiry(21),
            expired_expiry: expiry(10),
        };
        let result = testkit::revocation::assert_revocation_semantics(
            conformance_harness,
            cases,
            |store, serial, scope, not_after| {
                Box::pin(store.ledger.revoke(serial, scope, not_after))
            },
            |store, serial, scope| Box::pin(store.ledger.is_revoked(serial, scope)),
            |store, serial, scope| {
                Box::pin(async move {
                    let marker = store.ledger.revoked_at(serial, scope);
                    Ok::<_, diport::RevocationStoreError>(testkit::revocation::RevocationEvidence {
                        record_count: usize::from(marker.is_some()),
                        first_revoked_marker: marker,
                    })
                })
            },
            |store| {
                Box::pin(async move {
                    store.clock.store(20, Ordering::SeqCst);
                })
            },
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn revoke_then_is_revoked_true() {
        let l = ledger();
        let s = scope(TENANT_A, DEVICE_1);
        // 撤销前：未命中（anti-vacuity 前置）。
        assert!(!l.is_revoked(serial(), s).await.unwrap());
        l.revoke(serial(), s, not_after()).await.unwrap();
        // 撤销后：命中。
        assert!(l.is_revoked(serial(), s).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn unrevoked_serial_is_false() {
        let l = ledger();
        // 从未撤销 → false（webpki find_serial 未命中语义）。
        assert!(
            !l.is_revoked(serial(), scope(TENANT_A, DEVICE_1))
                .await
                .unwrap()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn scope_isolation_tenant_and_device() {
        let l = ledger();
        let revoked_scope = scope(TENANT_A, DEVICE_1);
        l.revoke(serial(), revoked_scope, not_after())
            .await
            .unwrap();
        // anti-vacuity：同 (tenant, device, serial) 命中。
        assert!(l.is_revoked(serial(), revoked_scope).await.unwrap());
        // 异 device（同 tenant）→ 隔离，false。
        assert!(
            !l.is_revoked(serial(), scope(TENANT_A, DEVICE_2))
                .await
                .unwrap()
        );
        // 异 tenant（同 device）→ 隔离，false。
        assert!(
            !l.is_revoked(serial(), scope(TENANT_B, DEVICE_1))
                .await
                .unwrap()
        );
        // 异 serial（同 scope）→ false。
        assert!(
            !l.is_revoked(serial_bytes(vec![0xFF]), revoked_scope)
                .await
                .unwrap()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn revoke_is_idempotent_and_preserves_first_time() {
        let l = ledger();
        let s = scope(TENANT_A, DEVICE_1);
        l.revoke(serial(), s, not_after()).await.unwrap(); // 首次：戳 REVOKED_AT_SECS。
        l.revoke(serial(), s, not_after()).await.unwrap(); // 二次：不覆盖首次戳。
        assert!(l.is_revoked(serial(), s).await.unwrap());
        let first = SystemTime::UNIX_EPOCH + Duration::from_secs(REVOKED_AT_SECS);
        assert_eq!(
            l.revoked_at(serial(), s),
            Some(first),
            "幂等：二次撤销须保留首次撤销时刻"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn revoked_at_records_clock_time() {
        let l = ledger();
        let s = scope(TENANT_A, DEVICE_1);
        // 撤销前无记录。
        assert_eq!(l.revoked_at(serial(), s), None);
        l.revoke(serial(), s, not_after()).await.unwrap();
        // Clock 戳的首次时刻被正确记录（REVOKED_AT_SECS）。
        let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(REVOKED_AT_SECS);
        assert_eq!(l.revoked_at(serial(), s), Some(expected));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn shutdown_ok() {
        let l = ledger();
        assert!(l.shutdown().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    async fn recovers_from_poisoned_lock() {
        // F5：撤销集 Mutex 毒化后，revoke / is_revoked 仍正确（PoisonError::into_inner 恢复内层数据，
        // 不静默丢撤销记录、不 panic）——撤销是安全语义，毒化不得导致已撤销证书被误判未撤销。
        let l = ledger();
        let s = scope(TENANT_A, DEVICE_1);
        l.revoke(serial(), s, not_after()).await.unwrap();
        l.poison_lock_for_test();
        // 毒化后：已撤销记录仍可见。
        assert!(
            l.is_revoked(serial(), s).await.unwrap(),
            "poison 后已撤销记录须仍可见"
        );
        // 毒化后：仍可继续撤销新证书。
        let other = serial_bytes(vec![0x09, 0x09]);
        l.revoke(other.clone(), s, not_after()).await.unwrap();
        assert!(
            l.is_revoked(other, s).await.unwrap(),
            "poison 后须仍可继续撤销"
        );
    }
}
