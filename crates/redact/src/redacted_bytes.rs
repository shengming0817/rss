//! `RedactedBytes` —— payload 字节字段的脱敏类型 funnel。
//!
//! 把「字节字段的 `Debug` 不展开原始字节」从各 DTO 散点手写 `impl Debug` 上移为**类型保证**（Hard）：
//! 动态 payload 使用 `RedactedBytes`；其 `Debug` / `Display` 固定脱敏。各语义 DTO/wrapper 持有该
//! carrier 后，derive(Debug) 也不会展开原始字节。
//!
//! **与 [`crate::RedactedSource`] 的关键差异**：`RedactedSource` 是 write-only containment（原始错误 owned 但不经
//! 任何接口暴露）；`RedactedBytes` 则**暴露受控字节访问**（[`RedactedBytes::as_bytes`] / [`RedactedBytes::into_bytes`]）
//! ——adapter / provider 需合法读 payload 收发字节，脱敏只作用于 `Debug` / `Display`（防日志 / tracing 泄漏），
//! 不阻断字节本身的程序化访问。对标 `secrecy::SecretBox`（redacted `Debug` `[REDACTED]` + `ExposeSecret::expose_secret`
//! 受控访问）。ref: secrecy secrecy/src/lib.rs@main。
//!
//! INVARIANT: REDACT-BYTES-OPAQUE-01 { level = "Hard", exec = "native-test", source = "code" }（`Debug` / `Display` 均不展开原始字节；
//! wrapper 自身由本模块单测验证。消费方是否采用该 wrapper 不由本 crate 的 lint 强制）。

/// 包装 DTO 字节 payload 的脱敏字段。私有字段 + 受控构造（[`RedactedBytes::new`]），`Debug` / `Display` 恒
/// `<redacted>`、不展开内层字节；经 [`RedactedBytes::as_bytes`] / [`RedactedBytes::into_bytes`] 受控读取原始字节
/// （与 [`crate::RedactedSource`] 的 write-only 不同——payload 需被 adapter 合法收发）。
///
/// 内层 `Vec<u8>` 是本 newtype 的**受控持有点**（脱敏边界本身），`Debug` / `Display` 已固定脱敏；
/// 本类型不宣称机器强制所有下游字节字段采用它。
// pub（非 pub(crate)）：`pub struct` DTO（如 `pub struct SignRequest { pub message: ... }`、`pub struct
// Signature(...)`）的 pub 字段须持 public 类型，否则「more private than item」privacy leak。re-export 于
// rss-redact crate root。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RedactedBytes(Vec<u8>);

impl RedactedBytes {
    /// 由字节构造脱敏 payload。原始字节经 [`RedactedBytes::as_bytes`] / [`RedactedBytes::into_bytes`] 受控读取，
    /// 但**不经 `Debug` / `Display`** 暴露（防日志 / tracing 泄漏）。
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// 借出原始字节（provider 收发 payload 用）。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// 取走原始字节（消费 payload，避免无谓 clone）。
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// payload 字节长度（可观测元数据，非 PII）。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// payload 是否为空。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for RedactedBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for RedactedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PII 边界（Hard）：不展开内层字节（payload 可能携敏感物料），只输出固定脱敏占位。裸 `<redacted>`
        // （非 `RedactedBytes(<redacted>)`）便于嵌套渲染：`Signature(<redacted>)` /
        // `SignRequest { message: <redacted> }`，与各处旧手写 Debug 输出一致。
        f.write_str("<redacted>")
    }
}

impl std::fmt::Display for RedactedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: Display 与 Debug 一致脱敏（fail-closed），防 `{}` 格式化意外泄漏字节。
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod redaction {
    //! `RedactedBytes` `Debug` / `Display` 不展开内层字节（payload 可能携敏感物料），但经 `as_bytes` /
    //! `into_bytes` 受控可读（provider 收发 payload）。INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
    use super::RedactedBytes;

    // 含 0xDE 字节：裸 `Vec<u8>` 的 `Debug` 把 0xDE 渲染成 "222"（十进制），redacted 后必不含。
    fn secret_bytes() -> Vec<u8> {
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    }

    #[test]
    fn debug_redacts_inner() {
        // anti-vacuity：裸 `Vec<u8>` 的 Debug 确实把 0xDE 渲染成 "222"，否则下方回归断言空转。
        assert!(
            format!("{:?}", secret_bytes()).contains("222"),
            "前提失效：裸字节 Debug 未含 222"
        );
        let r = RedactedBytes::new(secret_bytes());
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("222"), "Debug 泄漏内层字节: {dbg}");
        assert_eq!(dbg, "<redacted>");
    }

    #[test]
    fn display_redacts_inner() {
        let r = RedactedBytes::new(secret_bytes());
        assert_eq!(format!("{r}"), "<redacted>");
    }

    #[test]
    fn access_returns_bytes() {
        // 受控访问：与 `RedactedSource`（write-only）不同，字节经 as_bytes / into_bytes 可读（payload 需被收发）。
        let r = RedactedBytes::new(secret_bytes());
        assert_eq!(r.as_bytes(), secret_bytes().as_slice());
        assert_eq!(r.len(), 4);
        assert!(!r.is_empty());
        assert_eq!(r.into_bytes(), secret_bytes());
    }

    #[test]
    fn empty_payload() {
        let r = RedactedBytes::new(Vec::new());
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(format!("{r:?}"), "<redacted>");
    }

    #[test]
    fn from_vec_u8_is_redacted() {
        // `From<Vec<u8>>`（迁移期 callsite 经 `.into()` 大量使用）与 `new` 同样脱敏。
        let r: RedactedBytes = secret_bytes().into();
        assert_eq!(format!("{r:?}"), "<redacted>");
        assert_eq!(r.as_bytes(), secret_bytes().as_slice());
    }

    #[test]
    fn clone_preserves_redaction() {
        // `Clone`（derived）拷贝后仍脱敏——脱敏随值走，不因 clone 退化。
        let r = RedactedBytes::new(secret_bytes());
        let c = r.clone();
        assert_eq!(format!("{c:?}"), "<redacted>");
        assert_eq!(c, r);
        assert_eq!(c.as_bytes(), secret_bytes().as_slice());
    }
}
