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
    pub fn new(raw: uuid::Uuid) -> Self {
        Self(raw)
    }

    /// 解析字符串为 ID。
    pub fn parse(s: &str) -> Result<Self, IdParseError> {
        uuid::Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| IdParseError::Invalid)
    }

    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }
}

/// 会话标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(uuid::Uuid);

impl SessionId {
    /// 由已校验的 uuid 构造（funnel）。
    pub fn new(raw: uuid::Uuid) -> Self {
        Self(raw)
    }

    /// 解析字符串为 ID。
    pub fn parse(s: &str) -> Result<Self, IdParseError> {
        uuid::Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| IdParseError::Invalid)
    }

    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }
}

/// 设备标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(uuid::Uuid);

impl DeviceId {
    /// 由已校验的 uuid 构造（funnel）。
    pub fn new(raw: uuid::Uuid) -> Self {
        Self(raw)
    }

    /// 解析字符串为 ID。
    pub fn parse(s: &str) -> Result<Self, IdParseError> {
        uuid::Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| IdParseError::Invalid)
    }

    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const INVALID_UUID: &str = "not-a-uuid";

    // UserId
    #[allow(clippy::unwrap_used)]
    #[test]
    fn user_id_new_and_as_uuid_roundtrip() {
        let raw = uuid::Uuid::parse_str(VALID_UUID).unwrap();
        let id = UserId::new(raw);
        assert_eq!(id.as_uuid(), raw);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn user_id_parse_valid() {
        let id = UserId::parse(VALID_UUID).unwrap();
        let raw = uuid::Uuid::parse_str(VALID_UUID).unwrap();
        assert_eq!(id.as_uuid(), raw);
    }

    #[test]
    fn user_id_parse_invalid() {
        assert!(matches!(
            UserId::parse(INVALID_UUID),
            Err(IdParseError::Invalid)
        ));
    }

    #[test]
    fn user_id_parse_empty() {
        assert!(matches!(UserId::parse(""), Err(IdParseError::Invalid)));
    }

    // SessionId
    #[allow(clippy::unwrap_used)]
    #[test]
    fn session_id_new_and_as_uuid_roundtrip() {
        let raw = uuid::Uuid::parse_str(VALID_UUID).unwrap();
        let id = SessionId::new(raw);
        assert_eq!(id.as_uuid(), raw);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn session_id_parse_valid() {
        let id = SessionId::parse(VALID_UUID).unwrap();
        let raw = uuid::Uuid::parse_str(VALID_UUID).unwrap();
        assert_eq!(id.as_uuid(), raw);
    }

    #[test]
    fn session_id_parse_invalid() {
        assert!(matches!(
            SessionId::parse(INVALID_UUID),
            Err(IdParseError::Invalid)
        ));
    }

    #[test]
    fn session_id_parse_empty() {
        assert!(matches!(SessionId::parse(""), Err(IdParseError::Invalid)));
    }

    // DeviceId
    #[allow(clippy::unwrap_used)]
    #[test]
    fn device_id_new_and_as_uuid_roundtrip() {
        let raw = uuid::Uuid::parse_str(VALID_UUID).unwrap();
        let id = DeviceId::new(raw);
        assert_eq!(id.as_uuid(), raw);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn device_id_parse_valid() {
        let id = DeviceId::parse(VALID_UUID).unwrap();
        let raw = uuid::Uuid::parse_str(VALID_UUID).unwrap();
        assert_eq!(id.as_uuid(), raw);
    }

    #[test]
    fn device_id_parse_invalid() {
        assert!(matches!(
            DeviceId::parse(INVALID_UUID),
            Err(IdParseError::Invalid)
        ));
    }

    #[test]
    fn device_id_parse_empty() {
        assert!(matches!(DeviceId::parse(""), Err(IdParseError::Invalid)));
    }

    // 跨类型独立性：同一 uuid 构造不同 ID 类型不相等（类型隔离，编译期即守）
    #[allow(clippy::unwrap_used)]
    #[test]
    fn different_id_types_are_distinct_at_type_level() {
        let raw = uuid::Uuid::parse_str(VALID_UUID).unwrap();
        let uid = UserId::new(raw);
        let sid = SessionId::new(raw);
        // 类型不同，无法直接比较；验证各自 as_uuid 等于同一 raw
        assert_eq!(uid.as_uuid(), sid.as_uuid());
    }
}
