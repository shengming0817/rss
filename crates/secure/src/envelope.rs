//! AEAD v2 密文 envelope + alg/mode 元数据。设计单源 **ADR-011 §D3/§D4**。
//!
//! envelope 自描述其 `version/alg/mode/kid/key_version/nonce/ciphertext/tag` + 存储的标识 AAD 坐标。
//! Debug 经 `#[derive(Redact)]`：密码字节材料（nonce/ciphertext/tag）脱敏为 `<redacted>`，结构化元数据明示。
//! 替换 v1 `Ciphertext` tuple（no-compat，零消费者）。本 crate 只立类型，真实加解密落 #1466 adapter。

use crate::protection::ProtectionAad;

/// 具体 AEAD 原语标识（`#[non_exhaustive]`：未来算法可扩展，消费方须留 fallback 分支）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CipherAlg {
    /// 随机化 AEAD（默认，ADR §D4）。
    Aes256Gcm,
    /// 确定性 AEAD（RFC 5297 AES-SIV，仅 #1467 blind-index opt-in）。
    Aes256Siv,
}

/// 加密语义类别。随 envelope 存储，使密文自描述其 mode。
///
/// 注：`FIELDPROT-DETERMINISTIC-OPTIN-01` 的 typed-choice **载体是 [`crate::Aead`] trait 接缝**
/// （唯一随机化入口、无 bool flag；deterministic 须另立 `DeterministicAead` trait，#1467），**不是**本枚举——
/// 本枚举只是 envelope 自描述元数据。合法的 alg/mode 配对由 [`CiphertextEnvelope::new`] 校验（见 `EnvelopeError`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionMode {
    /// 随机 nonce，相同明文 → 不同密文（默认，安全优先）。
    Randomized,
    /// 相同明文 + 相同 AAD → 相同密文（per-field opt-in，泄漏明文相等性，#1467 blind index）。
    Deterministic,
}

/// envelope 当前格式版本（AEAD v2，对标 Vault `vault:vN:` 密文版本前缀）。
pub const ENVELOPE_VERSION: u8 = 2;

/// envelope 构造错误（message const literal，no PII，fail-closed）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// `kid` 为空——密钥路由标识缺失，#1466 解密 key lookup 必失败；构造点 fail-closed 拒绝
    /// （对称 [`crate::AadError::EmptyDimension`] 的空维度防护）。
    #[error("ciphertext envelope kid is empty")]
    EmptyKeyId,
    /// alg 与 mode 语义矛盾（如 `Aes256Gcm`+`Deterministic` / `Aes256Siv`+`Randomized`）——
    /// envelope 自描述失真会让 #1466 rewrap/rotation 按 mode 选策略走错分支、审计失准；构造点拒绝。
    #[error("ciphertext envelope alg/mode mismatch")]
    AlgModeMismatch,
}

/// alg 与 mode 的合法配对（ADR §D4）：`Aes256Gcm` 随机化 / `Aes256Siv` 确定性。
/// `#[non_exhaustive]` 下未来新增 alg 必须在此登记其合法 mode，否则默认 fail-closed 拒绝。
fn alg_mode_consistent(alg: CipherAlg, mode: EncryptionMode) -> bool {
    matches!(
        (alg, mode),
        (CipherAlg::Aes256Gcm, EncryptionMode::Randomized)
            | (CipherAlg::Aes256Siv, EncryptionMode::Deterministic)
    )
}

/// AEAD v2 密文 envelope。
///
/// Debug 经 `#[derive(Redact)]`：`nonce`/`ciphertext`/`tag` 为密码字节材料 → `#[redact(sensitivity = secret)]`
/// （`<redacted>`，nonce 密码学非机密但 Debug 字节 dump 无审计价值，统一脱敏 = 防御纵深，对齐 v1 `Ciphertext`
/// 先例）；`version`/`alg`/`mode`/`kid`/`key_version`/`aad` 是结构化元数据 → `#[redact(sensitivity = public, mode = "show")]`。
/// 私有字段 + 受控构造 funnel [`CiphertextEnvelope::new`]（供 #1466 adapter 在 `seal` 中组装，外部不可直构）。
#[derive(Clone, PartialEq, Eq, secure::Redact)]
pub struct CiphertextEnvelope {
    #[redact(sensitivity = public, mode = "show")]
    version: u8,
    #[redact(sensitivity = public, mode = "show")]
    alg: CipherAlg,
    #[redact(sensitivity = public, mode = "show")]
    mode: EncryptionMode,
    #[redact(sensitivity = public, mode = "show")]
    kid: Box<str>,
    #[redact(sensitivity = public, mode = "show")]
    key_version: u32,
    // tradeoff: nonce 脱敏同时遮蔽日志侧 nonce 复用诊断；#1466 实现者须在 AEAD impl 层另行经单调计数器/
    // metrics 覆盖 D3 (DEK,nonce) 唯一性监控，不依赖日志中的 nonce 字节（nonce 本身密码学非机密）。
    #[redact(sensitivity = secret)]
    nonce: Vec<u8>,
    #[redact(sensitivity = secret)]
    ciphertext: Vec<u8>,
    #[redact(sensitivity = secret)]
    tag: Vec<u8>,
    /// 存储仅供标识/路由/审计（issue 的 `aad_schema` 槽）——是 [`ProtectionAad`]（非 `DerivedAad`），
    /// 类型层禁止回灌给 `open`。非机密、明示。
    #[redact(sensitivity = public, mode = "show")]
    aad: ProtectionAad,
}

impl CiphertextEnvelope {
    /// 受控构造 funnel——供 [`crate::Aead`] 实现方（#1466 adapter）在 `seal` 中组装。私有字段不可外部直构；
    /// `version` 由 [`ENVELOPE_VERSION`] 固定，不由调用方传入。
    ///
    /// fail-closed 校验（对称 [`crate::AadError`] 的入口防护）：`kid` 非空（[`EnvelopeError::EmptyKeyId`]）+
    /// alg/mode 语义一致（[`EnvelopeError::AlgModeMismatch`]，杜绝矛盾自描述 envelope）。
    #[allow(clippy::too_many_arguments)] // reason: envelope 字段集即 AEAD wire 形态，扁平 funnel 比 builder 更直白且字段私有受控。
    pub fn new(
        alg: CipherAlg,
        mode: EncryptionMode,
        kid: &str,
        key_version: u32,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        tag: Vec<u8>,
        aad: ProtectionAad,
    ) -> Result<Self, EnvelopeError> {
        if kid.is_empty() {
            return Err(EnvelopeError::EmptyKeyId);
        }
        if !alg_mode_consistent(alg, mode) {
            return Err(EnvelopeError::AlgModeMismatch);
        }
        Ok(Self {
            version: ENVELOPE_VERSION,
            alg,
            mode,
            kid: kid.into(),
            key_version,
            nonce,
            ciphertext,
            tag,
            aad,
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn alg(&self) -> CipherAlg {
        self.alg
    }

    pub fn mode(&self) -> EncryptionMode {
        self.mode
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// 存储的标识/审计 AAD（**[`ProtectionAad`] 非 `DerivedAad`**——类型层禁止回灌 `open`）。
    pub fn aad(&self) -> &ProtectionAad {
        &self.aad
    }
}

#[cfg(test)]
mod tests {
    use super::{CipherAlg, CiphertextEnvelope, ENVELOPE_VERSION, EncryptionMode, EnvelopeError};
    use crate::protection::ProtectionAad;
    use rss_request_context::TenantId;
    use rstest::rstest;

    const TENANT_A: &str = "11111111-2222-4333-8444-555555555555";

    #[allow(clippy::expect_used)] // reason: test helper——构造失败即测试设置错误，应 panic 暴露。
    fn sample_aad() -> ProtectionAad {
        let tenant = TenantId::parse(TENANT_A).expect("canonical tenant");
        ProtectionAad::new(tenant, "db.dsn", "password", 2).expect("valid aad")
    }

    #[allow(clippy::expect_used)] // reason: test helper——构造失败即测试设置错误，应 panic 暴露。
    fn sample_envelope() -> CiphertextEnvelope {
        CiphertextEnvelope::new(
            CipherAlg::Aes256Gcm,
            EncryptionMode::Randomized,
            "kid-7",
            4,
            vec![0xAA, 0xBB],       // nonce
            vec![0xCC, 0xDD, 0xEE], // ciphertext
            vec![0x11, 0x22],       // tag
            sample_aad(),
        )
        .expect("valid envelope")
    }

    #[test]
    fn new_sets_version_and_round_trips_accessors() {
        let env = sample_envelope();
        assert_eq!(env.version(), ENVELOPE_VERSION);
        assert_eq!(env.version(), 2);
        assert_eq!(env.alg(), CipherAlg::Aes256Gcm);
        assert_eq!(env.mode(), EncryptionMode::Randomized);
        assert_eq!(env.kid(), "kid-7");
        assert_eq!(env.key_version(), 4);
        assert_eq!(env.nonce(), &[0xAA, 0xBB]);
        assert_eq!(env.ciphertext(), &[0xCC, 0xDD, 0xEE]);
        assert_eq!(env.tag(), &[0x11, 0x22]);
        assert_eq!(*env.aad(), sample_aad());
    }

    #[test]
    fn debug_shows_metadata_and_redacts_crypto_material() {
        let env = sample_envelope();
        let dbg = format!("{env:?}");
        // 元数据明示。
        assert!(
            dbg.contains("kid-7"),
            "kid is identification metadata: {dbg}"
        );
        assert!(dbg.contains("Aes256Gcm"), "alg shown: {dbg}");
        assert!(dbg.contains("Randomized"), "mode shown: {dbg}");
        assert!(dbg.contains("db.dsn"), "aad coordinate shown: {dbg}");
        // 密码字节材料脱敏。
        assert!(
            dbg.contains("<redacted>"),
            "crypto material redacted: {dbg}"
        );
        // anti-vacuity：裸 Vec<u8> Debug 会把 0xCC=204 渲染为 "204"；envelope Debug 必须不含。
        assert!(format!("{:?}", vec![204u8]).contains("204"));
        assert!(
            !dbg.contains("204"),
            "ciphertext byte leaked into Debug: {dbg}"
        );
        assert!(
            !dbg.contains("170"),
            "nonce byte (0xAA=170) leaked into Debug: {dbg}"
        );
        assert!(
            !dbg.contains("34"),
            "tag byte (0x22=34) leaked into Debug: {dbg}"
        );
    }

    #[test]
    fn alg_mode_value_semantics() {
        assert_ne!(CipherAlg::Aes256Gcm, CipherAlg::Aes256Siv);
        assert_ne!(EncryptionMode::Randomized, EncryptionMode::Deterministic);
        assert_eq!(CipherAlg::Aes256Gcm, CipherAlg::Aes256Gcm);
        // Copy 语义 smoke。
        let m = EncryptionMode::Deterministic;
        let n = m;
        assert_eq!(m, n);
    }

    #[test]
    fn new_rejects_empty_kid() {
        let result = CiphertextEnvelope::new(
            CipherAlg::Aes256Gcm,
            EncryptionMode::Randomized,
            "", // empty kid
            1,
            vec![1],
            vec![2],
            vec![3],
            sample_aad(),
        );
        assert!(matches!(result, Err(EnvelopeError::EmptyKeyId)));
    }

    #[rstest]
    // 合法配对：Gcm↔Randomized / Siv↔Deterministic 构造成功。
    #[case(CipherAlg::Aes256Gcm, EncryptionMode::Randomized, true)]
    #[case(CipherAlg::Aes256Siv, EncryptionMode::Deterministic, true)]
    // 矛盾配对：构造 fail-closed（AlgModeMismatch）。
    #[case(CipherAlg::Aes256Gcm, EncryptionMode::Deterministic, false)]
    #[case(CipherAlg::Aes256Siv, EncryptionMode::Randomized, false)]
    fn new_enforces_alg_mode_consistency(
        #[case] alg: CipherAlg,
        #[case] mode: EncryptionMode,
        #[case] ok: bool,
    ) {
        let result =
            CiphertextEnvelope::new(alg, mode, "kid", 1, vec![1], vec![2], vec![3], sample_aad());
        match result {
            Ok(env) => {
                assert!(ok, "expected mismatch rejection for {alg:?}/{mode:?}");
                assert_eq!(env.alg(), alg);
                assert_eq!(env.mode(), mode);
            }
            Err(e) => {
                assert!(!ok, "expected accept for {alg:?}/{mode:?}");
                assert!(matches!(e, EnvelopeError::AlgModeMismatch));
            }
        }
    }
}
