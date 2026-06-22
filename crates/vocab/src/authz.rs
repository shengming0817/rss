//! 基础授权词汇（领头类型，行为 PR 再扩）。

/// `Action` 解析错误。空值 / 非法字符等非法（校验在行为 PR 兑现）。
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
    /// 解析授权动作；拒绝空值 / 非法格式（校验在行为 PR 兑现）。
    pub fn parse(_raw: &str) -> Result<Self, ActionError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 授权裁决。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    Allow,
    Deny,
}
