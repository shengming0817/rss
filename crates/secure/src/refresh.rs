//! secure::refresh — refresh-token 原语：CSPRNG 256-bit 不透明 secret + SHA-256 摘要（#1325）。
//!
//! refresh token 形态 = **高熵不透明 secret**（非 JWT）；持久化只存其 **SHA-256 摘要**（不存明文）——
//! 重放检测 / 轮换由消费方（identity `RefreshService`）据摘要查找。crypto 原语留基础层 `secure`
//! （已持 argon2/aead，base 层 L0 纯计算），域 crate 不做 crypto（域只持摘要 newtype）。
//!
//! 安全模型：secret 仅在签发瞬间经 [`OpaqueToken::expose`] 受控出口交 consumer；
//! 服务端永不持久化明文，只持 [`digest`] 的不可逆摘要。攻陷 store 不泄露可用 refresh token（摘要不可逆）。
//!
//! ref: ory/fosite handler/oauth2/flow_refresh.go@master（refresh token 摘要持久化 + rotation，概念谱系）
//! ref: RustCrypto/hashes sha2/src/lib.rs@master（SHA-256 摘要，工业对标）

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::Engine;
use sha2::{Digest, Sha256};

/// 不透明 refresh secret（256-bit CSPRNG，base64url-no-pad 编码）。
///
/// 私有内容、Debug 脱敏、不 derive `Serialize`（同 `redaction` 范式）——bearer 凭据，`{:?}` 不得回显明文。
/// 仅签发瞬间存在于内存：消费方 [`expose`](OpaqueToken::expose) 取串交客户端后即弃，服务端只存 [`digest`] 摘要。
pub struct OpaqueToken(String);

impl std::fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpaqueToken(<redacted>)")
    }
}

impl OpaqueToken {
    /// 生成 256-bit 不透明 secret（`OsRng` CSPRNG，base64url-no-pad）。不取系统时钟（满足 clock 纪律）。
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        // reason: OsRng 是 OS CSPRNG（同 secure::password 盐生成）；fill_bytes 不可失败（失败即 panic，
        // 与 argon2 盐生成一致的不可恢复 RNG 故障语义）。
        let mut rng = OsRng;
        rng.fill_bytes(&mut bytes);
        Self(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    /// 暴露 secret 串——**受控出口**：仅签发瞬间交 consumer 时调用，禁进日志。
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// 对 refresh secret 串算 SHA-256 摘要（32 字节，持久化查找键）。
///
/// 不可逆 ⇒ 服务端不存明文：签发存 `digest(secret)`，校验对呈递串重算 `digest` 后按摘要查找
/// （摘要是高熵 secret 的函数，查找按完整 32 字节匹配，无独立比较步骤的时序泄漏面）。
pub fn digest(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{OpaqueToken, digest};

    // 256-bit base64url-no-pad ⇒ 43 字符（ceil(32*8/6)）。
    #[test]
    fn generate_yields_43_char_token() {
        let tok = OpaqueToken::generate();
        assert_eq!(
            tok.expose().len(),
            43,
            "256-bit base64url-no-pad = 43 chars"
        );
    }

    #[test]
    fn generate_yields_distinct_tokens() {
        // CSPRNG：两次生成几乎不可能相等（碰撞概率 2^-256）。
        let a = OpaqueToken::generate();
        let b = OpaqueToken::generate();
        assert_ne!(a.expose(), b.expose(), "CSPRNG tokens must differ");
    }

    #[test]
    fn generate_is_base64url_no_pad() {
        // base64url 字母表（A-Za-z0-9-_）+ 无填充（无 `=`）+ 无标准 base64 的 `+`/`/`。
        let tok = OpaqueToken::generate();
        let s = tok.expose();
        assert!(
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "must be url-safe alphabet: {s}"
        );
        assert!(!s.contains('='), "no padding");
    }

    #[test]
    fn digest_is_deterministic_32_bytes() {
        let d1 = digest("token-abc");
        let d2 = digest("token-abc");
        assert_eq!(d1, d2, "same input → same digest");
        assert_eq!(d1.len(), 32, "SHA-256 = 32 bytes");
    }

    #[test]
    fn digest_differs_for_different_input() {
        assert_ne!(digest("token-abc"), digest("token-abd"));
    }

    #[test]
    fn digest_matches_known_sha256_vector() {
        // SHA-256("abc") 已知向量（RustCrypto/NIST），锁住摘要引擎语义（anti-vacuity）。
        let d = digest("abc");
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn debug_redacts_secret() {
        let tok = OpaqueToken::generate();
        let dbg = format!("{tok:?}");
        assert_eq!(dbg, "OpaqueToken(<redacted>)");
        assert!(
            !dbg.contains(tok.expose()),
            "Debug must not leak secret: {dbg}"
        );
    }
}
