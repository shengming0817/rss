//! crypto-adapter — `primitives::MacVerifier` 的生产 RustCrypto 实现（`hmac` + `sha2`）。
//!
//! `primitives::crypto` 只放无密钥状态、provider-无关的纯计算 trait（[`primitives::MacVerifier`]）；具体
//! HMAC backend 属 adapter 层（与 `adapters/oidc` 用 RustCrypto 做 HS256 验签同范式）。本 crate 提供
//! [`RustCryptoMacVerifier`]，由组合根注入 `audit::ports::AuditChainHasher`（审计 keyed-HMAC 链）等消费点。
//!
//! ref: RustCrypto/MACs hmac/README.md@master（`Hmac<Sha256>` new_from_slice→update→finalize→into_bytes）
//! ref: RustCrypto/hashes sha2（Sha256/Sha384/Sha512 摘要后端）

// 工作区 [workspace.lints] 已全局 forbid(unsafe_code)；本 crate 经 `[lints] workspace = true` 继承。

use hmac::Hmac;
// `hmac::Mac` trait 提供 new_from_slice/update/finalize；用 `as _` 引入方法不绑定名（避免与 primitives::Mac 撞名）。
use hmac::Mac as _;
use sha2::{Sha256, Sha384, Sha512};

use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier, constant_time_eq};

/// buggy / 未知算法路径的 fail-closed 哨兵 tag（与任何真实 HMAC 输出不匹配 ⇒ verify fail-close，永不 panic）。
const FAIL_TAG: [u8; 32] = [0xFFu8; 32];

/// 生产 HMAC 验签 provider（RustCrypto `hmac` + `sha2`）。无状态单元类型（`Send + Sync` 自动成立）。
#[derive(Debug, Clone, Copy, Default)]
pub struct RustCryptoMacVerifier;

/// 按 concrete hash 类型算 HMAC tag（macro 按类型展开，规避 `Hmac<D>` 泛型 bound 复杂度）。
/// HMAC 接受任意长度 key（`new_from_slice` 对 HMAC 不会失败）；`Err` 支理论不可达，fail-closed `None`（不 panic）。
macro_rules! hmac_tag {
    ($hash:ty, $key:expr, $message:expr) => {{
        match Hmac::<$hash>::new_from_slice($key) {
            Ok(mut mac) => {
                mac.update($message);
                Some(mac.finalize().into_bytes().to_vec())
            }
            Err(_) => None,
        }
    }};
}

/// 据算法分发计算 HMAC tag。`MacAlgorithm` 是跨 crate `#[non_exhaustive]` ⇒ `_` 臂未知算法 fail-closed `None`。
fn compute_tag(key: &[u8], algorithm: MacAlgorithm, message: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        MacAlgorithm::HmacSha256 => hmac_tag!(Sha256, key, message),
        MacAlgorithm::HmacSha384 => hmac_tag!(Sha384, key, message),
        MacAlgorithm::HmacSha512 => hmac_tag!(Sha512, key, message),
        // reason: 跨 crate non_exhaustive，未知算法 fail-closed（不静默用错误算法、不 panic）。
        _ => None,
    }
}

impl MacVerifier for RustCryptoMacVerifier {
    fn sign(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8]) -> Mac {
        match compute_tag(key.as_bytes(), algorithm, message) {
            Some(bytes) => Mac::from_bytes(bytes),
            // 未知算法 / 不可达 key 错误 → fail-closed 哨兵（verify 必不匹配）。
            None => Mac::from_bytes(FAIL_TAG.to_vec()),
        }
    }

    fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
        // 常数时间比较（CRYPTO-CONST-TIME-01；禁 `==` 短路防时序侧信道）。未知算法 → false（fail-closed）。
        match compute_tag(key.as_bytes(), algorithm, message) {
            Some(bytes) => constant_time_eq(&bytes, tag.as_bytes()),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tag 字节 → 小写 hex（KAT 比对用）。
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // RFC/README known-answer：HMAC-SHA256(key, msg) 字节精确锚定（算法分发 + 输出布局冻结）。
    // ref: RustCrypto/MACs hmac/README.md@master。
    #[test]
    fn hmac_sha256_known_answer() {
        let key = MacKey::from_bytes(b"my secret and secure key".to_vec());
        let tag = RustCryptoMacVerifier.sign(&key, MacAlgorithm::HmacSha256, b"input message");
        assert_eq!(
            hex(tag.as_bytes()),
            "97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd9"
        );
    }

    // verify：正确 tag → true；任一 bit flip → false（anti-vacuity，证 verify 非恒真）。
    #[test]
    fn verify_accepts_correct_and_rejects_tampered_tag() {
        let v = RustCryptoMacVerifier;
        let key = MacKey::from_bytes(vec![0x42u8; 32]);
        let msg = b"audit chain message";
        let tag = v.sign(&key, MacAlgorithm::HmacSha256, msg);
        assert!(v.verify(&key, MacAlgorithm::HmacSha256, msg, &tag));

        // 篡改 tag 首字节 → verify false。
        let mut flipped = tag.as_bytes().to_vec();
        flipped[0] ^= 0x01;
        assert!(!v.verify(
            &key,
            MacAlgorithm::HmacSha256,
            msg,
            &Mac::from_bytes(flipped)
        ));
        // 错 key → verify false。
        let other = MacKey::from_bytes(vec![0x43u8; 32]);
        assert!(!v.verify(&other, MacAlgorithm::HmacSha256, msg, &tag));
        // 错 message → verify false。
        assert!(!v.verify(&key, MacAlgorithm::HmacSha256, b"different", &tag));
    }

    // verify 对长度不符的 tag fail-closed（constant_time_eq 定长比较 → false）。
    #[test]
    fn verify_rejects_wrong_length_tag() {
        let v = RustCryptoMacVerifier;
        let key = MacKey::from_bytes(vec![0u8; 32]);
        let short = Mac::from_bytes(vec![0u8; 16]);
        assert!(!v.verify(&key, MacAlgorithm::HmacSha256, b"x", &short));
    }

    // SHA-384 / SHA-512 分发：输出长度正确（48 / 64B）+ round-trip verify；证算法绑定无混淆。
    #[test]
    fn hmac_sha384_512_dispatch_lengths_and_roundtrip() {
        let v = RustCryptoMacVerifier;
        let key = MacKey::from_bytes(vec![0x7eu8; 32]);
        let msg = b"multi-algorithm dispatch";

        let t384 = v.sign(&key, MacAlgorithm::HmacSha384, msg);
        assert_eq!(t384.as_bytes().len(), 48);
        assert!(v.verify(&key, MacAlgorithm::HmacSha384, msg, &t384));

        let t512 = v.sign(&key, MacAlgorithm::HmacSha512, msg);
        assert_eq!(t512.as_bytes().len(), 64);
        assert!(v.verify(&key, MacAlgorithm::HmacSha512, msg, &t512));

        // 跨算法不混淆：256 的 tag 不被 384 verify 接受。
        let t256 = v.sign(&key, MacAlgorithm::HmacSha256, msg);
        assert!(!v.verify(&key, MacAlgorithm::HmacSha384, msg, &t256));
    }
}
