//! 基础授权词汇。`Action`/`Decision` 已实现；perm 闭值集 accessor 按需 additive 添加。

/// `Action` 解析错误。空值 / 非法字符等非法。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ActionError {
    #[error("action is empty")]
    Empty,
    #[error("action has invalid format")]
    Format,
}

/// 授权动作 newtype（私有字段，构造经 fallible funnel）。
///
/// 冻结为可失败构造：未知 / 非法 action 在边界即拒。行为 PR 可在此基础上加 `perm_*()`
/// 闭值集 accessor（additive，非破坏式），故此处不预冻 sealed `Permission` 枚举。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action(String);

impl Action {
    /// 解析授权动作；格式 `domain:verb`（恰一个冒号，两段非空，每段 crate-name 形）。
    ///
    /// 空串 → `Empty`；格式不符 → `Format`。
    pub fn parse(raw: &str) -> Result<Self, ActionError> {
        if raw.is_empty() {
            return Err(ActionError::Empty);
        }
        let (domain, verb) = raw.split_once(':').ok_or(ActionError::Format)?;
        // 确保只有一个冒号：verb 段不得再含 ':'
        if verb.contains(':') {
            return Err(ActionError::Format);
        }
        if !crate::is_crate_name(domain) || !crate::is_crate_name(verb) {
            return Err(ActionError::Format);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 授权裁决。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    Allow,
    Deny,
}

#[cfg(test)]
mod tests {
    use super::Action;

    #[test]
    fn action_accepts_valid_format() {
        let cases: &[&str] = &[
            "foo:bar",
            "identity:read",
            "settings:write",
            "my_domain:my_verb",
            "a:b",
            "abc123:xyz_op",
        ];
        for &raw in cases {
            let result = Action::parse(raw);
            assert!(result.is_ok(), "expected Ok for raw={raw:?}");
            #[allow(clippy::unwrap_used)]
            let action = result.unwrap();
            assert_eq!(action.as_str(), raw);
        }
    }

    #[test]
    fn action_rejects_empty() {
        assert!(
            matches!(Action::parse(""), Err(super::ActionError::Empty)),
            "expected Empty variant"
        );
    }

    #[test]
    fn action_rejects_format_errors() {
        let cases: &[&str] = &[
            "nodomain",    // 无冒号
            "foo:bar:baz", // 两个冒号
            ":verb",       // 空 domain
            "domain:",     // 空 verb
            ":",           // 两段都空
            "Foo:bar",     // domain 首字母大写
            "foo:Bar",     // verb 首字母大写
            "1foo:bar",    // domain 首字母数字
            "foo:1bar",    // verb 首字母数字
            "_foo:bar",    // domain 首字母下划线
            "FOO:BAR",     // 全大写
            "foo bar:baz", // 含空格
            "foo-bar:baz", // 含连字符
        ];
        for &raw in cases {
            assert!(
                matches!(Action::parse(raw), Err(super::ActionError::Format)),
                "expected Format for raw={raw:?}"
            );
        }
    }
}
