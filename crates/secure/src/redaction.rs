//! 敏感值脱敏 + 统一脱敏 funnel。
//!
//! span error / tracing sink / last_error 一律经 [`redact_error`] / [`redact_field`]
//! 收口（`docs/rules/observability.md` §redaction）——敏感 key 判定与 free-form scrub 不散落在
//! 各 consumer。`bootstrap::shutdown` 等已把 `secure::redact_error` 当既定接缝引用。

/// 敏感 key 关键字白名单（小写包含匹配）。
const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "password",
    "secret",
    "token",
    "credential",
    "apikey",
    "api_key",
    "key",
    "authorization",
    "cookie",
    "jwt",
    "session",
    "bearer",
    "salt",
    "private",
];

/// 敏感字段脱敏占位符。
const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// 脱敏器（sync 纯计算 trait）。
pub trait Redactor {
    /// 对输入做脱敏，返回不可逆的脱敏值。
    fn redact(&self, input: &str) -> Redacted;
}

/// 脱敏后的值（私有字段，禁直接还原）。`Display` 输出已脱敏内容（安全），可直接进日志。
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted(String);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Redacted(<redacted>)")
    }
}

impl std::fmt::Display for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: Display 输出已脱敏内容（funnel 产物，安全可记录）；供 `warn!(error = %redact_error(..))`。
        f.write_str(&self.0)
    }
}

impl Redacted {
    /// 由已脱敏字符串构造（受控 funnel，**crate 内受信入口**）。
    ///
    /// `pub(crate)`：`Redacted::Display` 可直接进日志，故禁止 crate 外业务把**未脱敏**内容
    /// 包装成可打印「安全值」绕过 funnel（input-struct mint 收口，类型层 Hard）。crate 外只能经
    /// [`redact_error`] / [`redact_field`] 这两个 `pub` funnel 取得 `Redacted`；外部 [`Redactor`]
    /// 实现方的受信构造路径随 W-adapters redactor 落地（届时经 secure 边界 sanctioned 入口）。
    pub(crate) fn new(redacted: impl Into<String>) -> Self {
        Self(redacted.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 统一脱敏 funnel：把 error 的**顶层** `Display` 作为可记录的安全摘要。
/// span error / tracing sink / last_error 一律经此（observability.md §redaction），不裸打印 error。
///
/// # 安全性（fail-closed）
///
/// **只输出顶层 `error.to_string()`，不遍历 `source()` 链**——source 链可能来自第三方 error
/// （驱动 / 网络层），其 `Display` 可能携连接串 / 凭据 / 用户输入等 PII；默认不展开，从根上杜绝
/// 经 error 链泄漏（也顺带消除 source 链循环遍历风险）。RSS 自有 `vocab::CoreError` 的 message 是
/// `&'static str` const（安全），顶层摘要已足够定位；需要链路诊断的调用方走显式 verbose 通道，
/// 不在本默认安全 funnel。
pub fn redact_error(error: &dyn std::error::Error) -> Redacted {
    Redacted::new(error.to_string())
}

/// 统一脱敏 funnel：按敏感 key 判定清洗单个字段值（敏感 key → 脱敏，否则原样）。
pub fn redact_field(key: &str, value: &str) -> Redacted {
    let lower = key.to_lowercase();
    if SENSITIVE_KEY_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
    {
        Redacted::new(REDACTED_PLACEHOLDER)
    } else {
        Redacted::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{Redacted, redact_error, redact_field};

    #[test]
    fn redacted_new_and_as_str() {
        let r = Redacted::new("safe value");
        assert_eq!(r.as_str(), "safe value");
    }

    #[test]
    fn redacted_display_outputs_content() {
        let r = Redacted::new("visible");
        assert_eq!(r.to_string(), "visible");
    }

    #[test]
    fn redacted_debug_is_opaque() {
        let r = Redacted::new("secret");
        assert_eq!(format!("{r:?}"), "Redacted(<redacted>)");
    }

    #[test]
    fn redacted_clone_eq() {
        let r1 = Redacted::new("x");
        let r2 = r1.clone();
        assert_eq!(r1, r2);
    }

    // --- redact_error ---

    #[derive(Debug)]
    struct SimpleError(String);
    impl std::fmt::Display for SimpleError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for SimpleError {}

    #[derive(Debug)]
    struct WrappedError {
        msg: String,
        cause: SimpleError,
    }
    impl std::fmt::Display for WrappedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.msg)
        }
    }
    impl std::error::Error for WrappedError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.cause)
        }
    }

    #[test]
    fn redact_error_single_layer() {
        let e = SimpleError("io error".to_string());
        let r = redact_error(&e);
        assert_eq!(r.as_str(), "io error");
    }

    #[test]
    fn redact_error_emits_top_level_only_not_source_chain() {
        // fail-closed：source 链（可能含第三方 PII）不进摘要，只输出顶层 Display。
        let e = WrappedError {
            msg: "outer".to_string(),
            cause: SimpleError("inner-secret-dsn".to_string()),
        };
        let r = redact_error(&e);
        assert_eq!(r.as_str(), "outer");
        assert!(!r.as_str().contains("inner-secret-dsn"));
    }

    // --- redact_field ---

    #[test]
    fn redact_field_password_key() {
        let r = redact_field("password", "hunter2");
        assert_eq!(r.as_str(), "<redacted>");
    }

    #[test]
    fn redact_field_authorization_key() {
        let r = redact_field("Authorization", "Bearer abc");
        assert_eq!(r.as_str(), "<redacted>");
    }

    #[test]
    fn redact_field_token_key() {
        let r = redact_field("access_token", "tok123");
        assert_eq!(r.as_str(), "<redacted>");
    }

    #[test]
    fn redact_field_api_key_variant() {
        let r = redact_field("apiKey", "k-123");
        assert_eq!(r.as_str(), "<redacted>");
    }

    #[test]
    fn redact_field_cookie_key() {
        let r = redact_field("cookie", "session=abc");
        assert_eq!(r.as_str(), "<redacted>");
    }

    #[test]
    fn redact_field_normal_key_preserved() {
        let r = redact_field("username", "alice");
        assert_eq!(r.as_str(), "alice");
    }

    #[test]
    fn redact_field_user_id_preserved() {
        let r = redact_field("userId", "u-42");
        assert_eq!(r.as_str(), "u-42");
    }

    // --- Fix 2: 补敏感 key：jwt / session / bearer / salt / private ---

    #[test]
    fn redact_field_session_key_redacted() {
        let r = redact_field("session_id", "x");
        assert_eq!(r.as_str(), "<redacted>");
    }

    #[test]
    fn redact_field_jwt_key_redacted() {
        let r = redact_field("jwt", "eyJhbGciOiJIUzI1NiJ9");
        assert_eq!(r.as_str(), "<redacted>");
    }

    #[test]
    fn redact_field_bearer_value_redacted() {
        let r = redact_field("bearer_value", "some-token");
        assert_eq!(r.as_str(), "<redacted>");
    }

    #[test]
    fn redact_field_salt_redacted() {
        let r = redact_field("salt", "abc123");
        assert_eq!(r.as_str(), "<redacted>");
    }

    #[test]
    fn redact_field_private_redacted() {
        let r = redact_field("private_key", "BEGIN RSA PRIVATE KEY");
        assert_eq!(r.as_str(), "<redacted>");
    }
}
