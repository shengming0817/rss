//! Canonical domain-name vocabulary for internal typed identifiers.

/// `DomainName` 解析错误。空值 / 非法字符（非 crate-name 形）非法。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DomainNameError {
    #[error("domain name is empty")]
    Empty,
    #[error("domain name has invalid format")]
    Format,
}

/// 域名 newtype（私有字段，构造经 fallible funnel）。
///
/// 域名是契约归属路径段（crate-name 形）——冻结为可失败构造，拒绝空值 / 非法字符。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainName(String);

impl DomainName {
    /// 解析域名；拒绝空值 / 非法格式（crate-name 形 `[a-z][a-z0-9_]*`）。
    pub fn parse(raw: &str) -> Result<Self, DomainNameError> {
        if raw.is_empty() {
            return Err(DomainNameError::Empty);
        }
        if !crate::is_crate_name(raw) {
            return Err(DomainNameError::Format);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::DomainName;

    // --- DomainName ---

    #[test]
    fn domain_name_accepts_valid_crate_names() {
        let cases: &[&str] = &["identity", "settings", "a", "my_domain", "abc123", "x1_y2"];
        for &raw in cases {
            let result = DomainName::parse(raw);
            assert!(result.is_ok(), "expected Ok for raw={raw:?}");
            #[allow(clippy::unwrap_used)]
            let name = result.unwrap();
            assert_eq!(name.as_str(), raw);
        }
    }

    #[test]
    fn domain_name_rejects_empty() {
        assert!(
            matches!(DomainName::parse(""), Err(super::DomainNameError::Empty)),
            "expected Empty for empty input"
        );
    }

    #[test]
    fn domain_name_rejects_invalid_format() {
        let cases: &[&str] = &[
            "Identity",  // 首字母大写
            "1domain",   // 首字母数字
            "_domain",   // 首字母下划线
            "my-domain", // 含连字符
            "my domain", // 含空格
            "FOO",       // 全大写
            "foo.bar",   // 含点
        ];
        for &raw in cases {
            assert!(
                matches!(DomainName::parse(raw), Err(super::DomainNameError::Format)),
                "expected Format for raw={raw:?}"
            );
        }
    }

    #[test]
    fn domain_name_rejects_framework_sentinel() {
        // `_framework` 以下划线开头，守 sentinel 不被误解析为合法域名。
        assert!(
            matches!(
                DomainName::parse("_framework"),
                Err(super::DomainNameError::Format)
            ),
            "expected Format for _framework sentinel"
        );
    }
}
