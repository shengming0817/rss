//! 纯计算 crypto 原语（ADR-004 C1：L0 sync 纯计算，非 DI port）。
//!
//! 与 `secure` 边界划分：`secure` 持有 **密值封装 + provider 式 codec**（`Aead` seal/open、
//! `CookieCodec`、redaction）；`primitives::crypto` 只放**无密钥状态、provider-无关的纯计算**
//! ——digest / HMAC 验签 + 定长常数时间比较。
//! `KeyProvider` / `ValueTransformer`（provider-可换、持密钥）是 DI port → diport，不在此。

/// 摘要算法（闭值集；Copy）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// 不可逆摘要值（私有字段；定长字节）。`Debug` 不泄原值。
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
    pub fn from_bytes(_bytes: Vec<u8>) -> Self {
        todo!()
    }

    /// 借出摘要字节。
    pub fn as_bytes(&self) -> &[u8] {
        todo!()
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
pub struct MacKey(
    // reason: 行为 PR 兑现前字段暂未读取（签名冻结态）。
    #[allow(dead_code)] Vec<u8>,
);

impl std::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 密钥脱敏，不泄原字节。
        f.write_str("MacKey(<redacted>)")
    }
}

impl MacKey {
    /// 由密钥字节构造（受控 funnel；密钥来源是 secure DI provider）。
    pub fn from_bytes(_bytes: Vec<u8>) -> Self {
        todo!()
    }
}

/// MAC 标签值（私有字段；`Debug` 不泄原值，避免泄签名）。
///
/// `PartialEq`/`Eq` 已移除——MAC 比较只经 `MacVerifier::verify`（常数时间）；
/// 禁止 `==` 绕开常数时间校验（防时序侧信道）。
#[derive(Clone)]
pub struct Mac(
    // reason: 行为 PR 兑现前字段暂未读取（签名冻结态）。
    #[allow(dead_code)] Vec<u8>,
);

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: MAC 标签脱敏输出，不泄签名字节。
        f.write_str("Mac(<redacted>)")
    }
}

impl Mac {
    /// 由 MAC 字节构造（受控 funnel；供签名实现方返回）。
    pub fn from_bytes(_bytes: Vec<u8>) -> Self {
        todo!()
    }

    /// 借出 MAC 字节。
    pub fn as_bytes(&self) -> &[u8] {
        todo!()
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
pub fn constant_time_eq(_lhs: &[u8], _rhs: &[u8]) -> bool {
    todo!()
}
