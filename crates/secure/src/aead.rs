//! AEAD v2 加解密接缝（sync，静态分发，非 DI port——ADR-004 C1）。
//!
//! 字段级数据保护边界（observe-redaction vs storage-encryption 分层、AAD 必填 envelope、deterministic
//! opt-in、no-decrypt-in-debug）的设计单源见 **ADR-011**。本 crate 只立 v2 **基础类型 + trait 接缝**
//! （AAD 必填、envelope 自描述、解密产物 no-decrypt-in-debug），**不引入真实 crypto 后端**——真实
//! AES-GCM/SIV impl 落 #1466（`adapters/vault`），持久化落 #1467（`settings`）。
//!
//! Hard 不变式（类型层成立）：
//! - `FIELDPROT-AAD-MANDATORY-01`：[`Aead::seal`]/[`Aead::open`] 的 `aad: &DerivedAad` 是必填位置参（非 `Option`）。
//! - `FIELDPROT-AAD-DERIVE-FROM-CTX-01`：`aad` 类型是 [`crate::DerivedAad`]（只能经
//!   [`crate::ProtectionContext::derive`] 派生），envelope 存的 [`crate::ProtectionAad`] 回灌即类型错误。
//! - `FIELDPROT-DETERMINISTIC-OPTIN-01`：本 trait 仅表达**随机化**默认 AEAD，无 bool flag、无确定性入口；
//!   deterministic 是未来独立 trait（#1467），opt-in 须新增 typed API。
//! - `FIELDPROT-NODBG-DECRYPT-01`：[`Aead::open`] 返回 [`Plaintext`]（封 `secrecy`，Debug `<redacted>` +
//!   Drop-zeroize），明文永不可 `{:?}` 渲染。

use crate::envelope::CiphertextEnvelope;
use crate::protection::DerivedAad;
use secrecy::{ExposeSecret, SecretSlice};

/// 解密产物（`FIELDPROT-NODBG-DECRYPT-01`，Hard）。薄封 `secrecy::SecretSlice<u8>`：
/// `Debug` 渲染 `Plaintext(<redacted>)`（对齐 `OpaqueToken`/`Ciphertext` 先例）、`Drop` 时 zeroize 抹除明文
/// （直接对标 ADR §D5 引用的 `secrecy::Secret<T>` Drop-zeroize）。[`Aead::open`] 返回此而非 `Vec<u8>`，
/// 使明文**永不**可 `{:?}` 渲染；取明文只经显式审计出口 [`Plaintext::expose`]。
pub struct Plaintext(SecretSlice<u8>);

impl Plaintext {
    /// 由解密字节构造（受控 funnel）——供 [`Aead`] 实现方在 `open` 中返回。
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretSlice::from(bytes))
    }

    /// 受控借出明文（显式审计点，对标 `secrecy::ExposeSecret` / `OpaqueToken::expose`）。
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

// 故意脱敏 Debug（与 `OpaqueToken(<redacted>)` / `Ciphertext(<redacted>)` 先例同形）——明文永不进可观测面。
impl std::fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Plaintext(<redacted>)")
    }
}

/// AEAD v2 原语（sync）。`aad` 是**必填位置参**（非 `Option`）——缺失即编译错误
/// （`FIELDPROT-AAD-MANDATORY-01`）。本接缝只表达**随机化**默认 AEAD；deterministic 是未来独立 trait
/// （#1467），不在此加 bool/enum flag（`FIELDPROT-DETERMINISTIC-OPTIN-01`）。impl 落 #1466。
pub trait Aead {
    /// 加密：绑定 `aad`，产出自描述 [`CiphertextEnvelope`]（impl 写入 alg/mode/kid/nonce/tag + 存储 aad 坐标）。
    fn seal(&self, plaintext: &[u8], aad: &DerivedAad) -> Result<CiphertextEnvelope, AeadError>;

    /// 解密：`aad` 必须由调用方从**受信上下文新派生**（`&DerivedAad`，绝不回灌 `envelope.aad()`）。
    ///
    /// 调用方义务（#1466/#1467 落地）：
    /// - **tenant 必须取自受信源**——已鉴权请求经 `Principal`/JWT（如 `Principal::tenant_id()`），离线维护经
    ///   被解密记录的已知坐标（[`crate::ProtectionContext`] 两构造器）；**不可**由业务自由拼，否则跨租绑定静默失效
    ///   （`FIELDPROT-AAD-DERIVE-FROM-CTX-01` 在 L0 不可见 `Principal`，此约束落 #1466 call site governance）。
    /// - **错误诊断**：[`AeadError::Open`] 不携带任何上下文（防降级探测），故调用方须在 `Err` 分支自行记录
    ///   envelope 元数据，如 `tracing::error!(kid = envelope.kid(), key_version = envelope.key_version(),
    ///   "aead open failed")`，以保证生产可观测性。
    ///
    /// AAD/tag/version 任一不符 → fail-closed [`AeadError::Open`]（不泄漏哪一维失败，防降级探测）。
    fn open(&self, envelope: &CiphertextEnvelope, aad: &DerivedAad)
    -> Result<Plaintext, AeadError>;
}

/// AEAD 错误词汇（message const literal，no detail leakage，fail-closed）。
///
/// 不区分失败维度：`open` 的 AAD-mismatch / malformed-envelope / unsupported-version 全收敛 [`AeadError::Open`]
/// （告诉攻击者「哪一维不符」= 降级探测面）。AAD 构造校验是另一操作，归 [`crate::AadError`]。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AeadError {
    /// 加密失败——#1466 impl 将密钥获取失败（KeyProvider/KMS 不可达）、nonce 生成失败、底层 AEAD 原语错误
    /// 等**全部归此变体**（同 `Open` 的 no-detail-leakage 纪律；错误源脱敏在 #1466 的 KeyProvider 审计路径覆盖）。
    #[error("aead seal failed")]
    Seal,
    /// 解密失败——AAD-mismatch / malformed-envelope / unsupported-version 全收敛于此（不区分维度，防降级探测）。
    #[error("aead open failed")]
    Open,
}

#[cfg(test)]
mod tests {
    use super::{Aead, AeadError, Plaintext};
    use crate::envelope::{CipherAlg, CiphertextEnvelope, EncryptionMode};
    use crate::protection::{DerivedAad, ProtectionContext};
    use vocab::tenant::TenantId;

    const TENANT_A: &str = "11111111-2222-4333-8444-555555555555";
    const TENANT_B: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    /// 测试替身：identity「AEAD」——不做真实 crypto（真实 impl 落 #1466），只验证 trait 接缝 +
    /// AAD 绑定语义。seal 把 plaintext 原样放进 envelope.ciphertext、把 AAD canonical 字节放进 nonce 槽；
    /// open 仅当传入 `aad` 的 canonical 字节与 seal 时一致才还原，否则 fail-closed `Open`。
    struct IdentityAead;

    impl Aead for IdentityAead {
        fn seal(
            &self,
            plaintext: &[u8],
            aad: &DerivedAad,
        ) -> Result<CiphertextEnvelope, AeadError> {
            // 真实 impl 同此范式：envelope 构造失败（无效 alg/mode、空 kid）映射为 Seal。
            CiphertextEnvelope::new(
                CipherAlg::Aes256Gcm,
                EncryptionMode::Randomized,
                "test-kid",
                1,
                aad.as_canonical_bytes().to_vec(), // nonce 槽借用承载「seal 时 AAD」，供 open 比对
                plaintext.to_vec(),
                vec![],
                aad.coordinates().clone(),
            )
            .map_err(|_| AeadError::Seal)
        }

        fn open(
            &self,
            envelope: &CiphertextEnvelope,
            aad: &DerivedAad,
        ) -> Result<Plaintext, AeadError> {
            if envelope.nonce() == aad.as_canonical_bytes() {
                Ok(Plaintext::new(envelope.ciphertext().to_vec()))
            } else {
                Err(AeadError::Open)
            }
        }
    }

    // 测试 helper：派生失败即测试设置错误，应 panic 暴露（item-level carve-out，对齐 cookie/password 范式）。
    #[allow(clippy::expect_used)]
    fn derived(tenant: &str, key: &str, field: &str, ver: u32) -> DerivedAad {
        let tenant = TenantId::parse(tenant).expect("canonical tenant");
        ProtectionContext::authenticated_request(tenant, key, field, ver)
            .expect("ctx")
            .derive()
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: seal/open 失败即测试断言点，应 panic 暴露。
    fn seal_then_open_with_matching_aad_round_trips() {
        let aead = IdentityAead;
        let aad = derived(TENANT_A, "db.dsn", "password", 1);
        let env = aead.seal(b"super-secret", &aad).expect("seal");
        let pt = aead.open(&env, &aad).expect("open with matching aad");
        assert_eq!(pt.expose(), b"super-secret");
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: seal 成功是前提，open 须 fail-closed（expect_err 验证）。
    fn open_with_cross_dimension_aad_fails_closed() {
        let aead = IdentityAead;
        let env = aead
            .seal(b"super-secret", &derived(TENANT_A, "k", "f", 1))
            .expect("seal");
        // open AAD 与 seal AAD 在**任一**维度不符（tenant/config-key/field/schema-version）→ fail-closed，
        // 覆盖 ADR §D2「任一维度不匹配则 open fail-closed」全四维（杜绝跨租/跨键/跨字段/跨版本重放）。
        let cross_cases = [
            (TENANT_B, "k", "f", 1u32),    // cross-tenant
            (TENANT_A, "key-b", "f", 1),   // cross-config-key
            (TENANT_A, "k", "field-b", 1), // cross-field
            (TENANT_A, "k", "f", 2),       // cross-schema-version
        ];
        for (tn, key, field, ver) in cross_cases {
            let attacker = derived(tn, key, field, ver);
            let err = aead
                .open(&env, &attacker)
                .expect_err("cross-dimension open must fail");
            assert!(
                matches!(err, AeadError::Open),
                "dimension {tn}/{key}/{field}/{ver} must fail-closed"
            );
        }
    }

    #[test]
    fn aead_error_display_messages() {
        // 覆盖两个变体的 Display（const literal，no PII）；`Seal` 的 identity-fake 路径恒成功触不到，故直接构造。
        assert_eq!(AeadError::Seal.to_string(), "aead seal failed");
        assert_eq!(AeadError::Open.to_string(), "aead open failed");
    }

    #[test]
    fn plaintext_debug_redacts_content() {
        // anti-vacuity：裸 Vec<u8> Debug 把 42 渲染成 "42"，证明 "!contains(42)" 非空转。
        assert!(format!("{:?}", vec![42u8]).contains("42"));
        let pt = Plaintext::new(vec![42, 43]);
        let dbg = format!("{pt:?}");
        assert_eq!(dbg, "Plaintext(<redacted>)");
        assert!(!dbg.contains("42"), "Debug 泄漏明文字节: {dbg}");
    }

    #[test]
    fn plaintext_expose_round_trips() {
        let pt = Plaintext::new(vec![1, 2, 3, 255, 0]);
        assert_eq!(pt.expose(), &[1, 2, 3, 255, 0]);
    }
}
