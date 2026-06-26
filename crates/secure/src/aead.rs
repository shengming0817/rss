//! AEAD 加解密接缝。

/// AEAD 原语（sync）。
pub trait Aead {
    /// 加密明文。
    fn seal(&self, plaintext: &[u8]) -> Result<Ciphertext, AeadError>;
    /// 解密密文。
    fn open(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>, AeadError>;
}

/// 密文容器（私有字段）。`Debug` 经 `#[derive(Redact)]` 字段级脱敏（密文物料 → `<redacted>`，
/// 渲染 `Ciphertext(<redacted>)`），替换手写 impl（#1360）。
#[derive(Clone, PartialEq, Eq, secure::Redact)]
pub struct Ciphertext(#[redact(secret)] Vec<u8>);

impl Ciphertext {
    /// 由密文字节构造（受控 funnel）。供 [`Aead`] 实现方（adapter）在 `seal` 中返回密文容器。
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Ciphertext;

    #[test]
    fn from_bytes_as_bytes_roundtrip() {
        let data = vec![1u8, 2, 3, 255, 0];
        let ct = Ciphertext::from_bytes(data.clone());
        assert_eq!(ct.as_bytes(), data.as_slice());
    }

    #[test]
    fn from_bytes_empty() {
        let ct = Ciphertext::from_bytes(vec![]);
        assert_eq!(ct.as_bytes(), &[] as &[u8]);
    }

    #[test]
    fn debug_redacts_content() {
        // anti-vacuity：原始 Vec<u8> Debug 把 42 渲染成 "42"，证明 "!contains(42)" 非空转。
        assert!(format!("{:?}", vec![42u8]).contains("42"));
        let ct = Ciphertext::from_bytes(vec![42, 43]);
        let dbg = format!("{ct:?}");
        assert_eq!(dbg, "Ciphertext(<redacted>)");
        assert!(!dbg.contains("42"), "Debug 泄漏密文字节: {dbg}");
    }
}

/// AEAD 错误词汇（message const literal）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AeadError {
    #[error("aead seal failed")]
    Seal,
    #[error("aead open failed")]
    Open,
}
