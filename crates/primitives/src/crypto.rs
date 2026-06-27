//! 纯计算 crypto 原语（ADR-004 C1：L0 sync 纯计算，非 DI port）。
//!
//! 与 `secure` 边界划分：`secure` 持有 **密值封装 + provider 式 codec**（`Aead` seal/open、
//! `CookieCodec`、redaction）；`primitives::crypto` 只放**无密钥状态、provider-无关的纯计算**
//! ——digest / HMAC 验签 + 定长常数时间比较。
//! `KeyProvider` / `ValueTransformer`（provider-可换、持密钥）是 DI port → diport（设计单源 ADR-011
//! §D6，port 落地 #1466），不在此。

use subtle::ConstantTimeEq;

/// 摘要算法（闭值集；Copy）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// 不可逆摘要值（私有字段；定长字节）。`Debug` 不泄原值。
///
/// `PartialEq`/`Eq` 是结构性相等（`HashMap` key 等用途），**非常数时间**；
/// 认证比较（如 digest 校验）必须经 [`constant_time_eq`]，勿用 `==`。
#[derive(Clone, PartialEq, Eq)]
pub struct Digest(Vec<u8>);

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 摘要值脱敏输出，不泄原字节（同 secure redacted Debug 范式）。
        f.write_str("Digest(<redacted>)")
    }
}

impl Digest {
    /// 由摘要字节构造（受控 funnel；供算法实现方返回）。
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// 借出摘要字节。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// 摘要原语（sync 纯计算 trait；无密钥状态，故非 DI port）。
pub trait Digester {
    /// 对输入算摘要（纯计算，确定性）。
    fn digest(&self, algorithm: DigestAlgorithm, input: &[u8]) -> Digest;
}

/// MAC 算法（闭值集；Copy）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacAlgorithm {
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

/// MAC 密钥（sealed；私有字段 + redacted Debug，不泄密钥）。
#[derive(Clone)]
pub struct MacKey(Vec<u8>);

impl std::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 密钥脱敏，不泄原字节。
        f.write_str("MacKey(<redacted>)")
    }
}

impl MacKey {
    /// 由密钥字节构造（受控 funnel；密钥来源是 secure DI provider）。
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// 借出密钥字节（供 `MacVerifier` adapter 实现方算 HMAC 读取）。
    ///
    /// 公开 `MacVerifier::{sign,verify}` 由 crate 外 adapter 实现、需读密钥字节算 HMAC，故 key
    /// handle 必须可读出——签名层一并冻结此访问器，避免 adapter 落地时才发现 API 漂移。调用方
    /// 须在安全边界内使用、不外泄（`MacKey::Debug` 已脱敏，不经日志泄漏）。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// MAC 标签值（私有字段；`Debug` 不泄原值，避免泄签名）。
///
/// `PartialEq`/`Eq` 已移除——MAC 比较只经 `MacVerifier::verify`（常数时间）；
/// 禁止 `==` 绕开常数时间校验（防时序侧信道）。
#[derive(Clone)]
pub struct Mac(Vec<u8>);

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: MAC 标签脱敏输出，不泄签名字节。
        f.write_str("Mac(<redacted>)")
    }
}

impl Mac {
    /// 由 MAC 字节构造（受控 funnel；供签名实现方返回）。
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// 借出 MAC 字节。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// HMAC 验签原语（sync 纯计算 trait）。
///
/// reason: 密钥经 `MacKey` typed funnel 传入（防裸 `&[u8]` 密钥滥用）；
/// 算法绑定在签名 / 验签调用上，类型层杜绝算法混淆。
pub trait MacVerifier {
    /// 算 HMAC 标签（纯计算）。
    fn sign(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8]) -> Mac;

    /// 常数时间校验标签（防时序侧信道；唯一 tag 校验入口）。
    fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool;
}

/// 常数时间字节比较（纯函数；定长输入，防时序侧信道）。供 token / MAC 比较收口。
///
/// INVARIANT: CRYPTO-CONST-TIME-01 —— 实现必须常数时间（禁 `==` 短路）；Medium 守卫随 crypto W 行为 PR 落地。
pub fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    lhs.ct_eq(rhs).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Digest round-trip ─────────────────────────────────────────────────────
    #[test]
    fn digest_from_bytes_as_bytes_roundtrip() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let digest = Digest::from_bytes(bytes.clone());
        assert_eq!(digest.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn digest_empty_roundtrip() {
        let digest = Digest::from_bytes(vec![]);
        assert_eq!(digest.as_bytes(), &[] as &[u8]);
    }

    // ── Mac round-trip ────────────────────────────────────────────────────────
    #[test]
    fn mac_from_bytes_as_bytes_roundtrip() {
        let bytes = vec![0x01, 0x02, 0x03];
        let mac = Mac::from_bytes(bytes.clone());
        assert_eq!(mac.as_bytes(), bytes.as_slice());
    }

    // ── MacKey construction + as_bytes + redacted Debug ──────────────────────
    #[test]
    fn mac_key_from_bytes_as_bytes_roundtrip_and_debug_redacts() {
        let bytes = vec![7u8; 32];
        let key = MacKey::from_bytes(bytes.clone());
        // adapter 可读密钥字节算 HMAC……
        assert_eq!(key.as_bytes(), bytes.as_slice());
        // ……但 Debug 仍脱敏，不经日志泄漏。
        assert_eq!(format!("{key:?}"), "MacKey(<redacted>)");
    }

    // ── constant_time_eq ──────────────────────────────────────────────────────
    #[test]
    fn constant_time_eq_equal_slices_true() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different_content_same_length_false() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_length_false() {
        assert!(!constant_time_eq(b"hello", b"helloworld"));
    }

    #[test]
    fn constant_time_eq_empty_slices_true() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_one_empty_false() {
        assert!(!constant_time_eq(b"a", b""));
    }
}
