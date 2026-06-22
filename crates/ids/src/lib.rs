//! ids — RSS 强类型标识 newtype（基础层，仅 std+uuid）。
//!
//! 每个 ID 字段私有（ADR-004 C7），构造只经 `new`/`parse` funnel；不 derive serde（C6）。

/// ID 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdParseError {
    #[error("invalid id format")]
    Invalid,
}

/// 用户标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(uuid::Uuid);

impl UserId {
    /// 由已校验的 uuid 构造（funnel）。
    pub fn new(_raw: uuid::Uuid) -> Self {
        todo!()
    }

    /// 解析字符串为 ID。
    pub fn parse(_s: &str) -> Result<Self, IdParseError> {
        todo!()
    }

    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        todo!()
    }
}

/// 会话标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(uuid::Uuid);

impl SessionId {
    /// 由已校验的 uuid 构造（funnel）。
    pub fn new(_raw: uuid::Uuid) -> Self {
        todo!()
    }

    /// 解析字符串为 ID。
    pub fn parse(_s: &str) -> Result<Self, IdParseError> {
        todo!()
    }

    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        todo!()
    }
}

/// 设备标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(uuid::Uuid);

impl DeviceId {
    /// 由已校验的 uuid 构造（funnel）。
    pub fn new(_raw: uuid::Uuid) -> Self {
        todo!()
    }

    /// 解析字符串为 ID。
    pub fn parse(_s: &str) -> Result<Self, IdParseError> {
        todo!()
    }

    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        todo!()
    }
}
