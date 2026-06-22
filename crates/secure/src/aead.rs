//! AEAD 加解密接缝。

/// AEAD 原语（sync）。
pub trait Aead {
    /// 加密明文。
    fn seal(&self, plaintext: &[u8]) -> Result<Ciphertext, AeadError>;
    /// 解密密文。
    fn open(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>, AeadError>;
}

/// 密文容器（私有字段）。
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

impl std::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ciphertext(<redacted>)")
    }
}

impl Ciphertext {
    /// 由密文字节构造（受控 funnel）。供 [`Aead`] 实现方（adapter）在 `seal` 中返回密文容器。
    pub fn from_bytes(_bytes: Vec<u8>) -> Self {
        todo!()
    }

    pub fn as_bytes(&self) -> &[u8] {
        todo!()
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
