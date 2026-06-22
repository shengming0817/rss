//! 基础查询/分页词汇（领头类型，行为 PR 再扩）。limit 上限语义见 rust-standards（≤500）。

/// 分页上限校验错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LimitError {
    #[error("limit exceeds maximum of 500")]
    TooLarge,
}

/// 分页游标解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CursorError {
    #[error("cursor is malformed")]
    Malformed,
}

/// 分页游标 newtype（私有字段，构造经 fallible funnel）。
///
/// 入站游标是不透明 token，解码可失败——冻结为可失败构造，拒绝畸形游标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(String);

impl Cursor {
    /// 解析不透明游标 token；畸形即拒（解码在行为 PR 兑现）。
    pub fn parse(_raw: &str) -> Result<Self, CursorError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 分页上限 newtype（私有字段，构造时校验 ≤500）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit(u16);

impl Limit {
    /// 构造，上限 500（校验在行为 PR 实现）。
    pub fn new(_value: u16) -> Result<Self, LimitError> {
        todo!()
    }

    pub fn get(&self) -> u16 {
        todo!()
    }
}
