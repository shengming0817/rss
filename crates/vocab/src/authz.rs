//! Minimal provider-neutral authorization vocabulary retained for runtime governance.

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PermissionParseError {
    #[error("permission is unknown")]
    Unknown,
}

/// The sole retained framework permission; business-owned permissions were removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoutePermissionId {
    RuntimeInventoryRead,
}

impl RoutePermissionId {
    pub const ALL: &'static [Self] = &[Self::RuntimeInventoryRead];
    pub fn parse(raw: &str) -> Result<Self, PermissionParseError> {
        match raw {
            "runtime:inventory:read" => Ok(Self::RuntimeInventoryRead),
            _ => Err(PermissionParseError::Unknown),
        }
    }
    pub const fn as_str(self) -> &'static str {
        "runtime:inventory:read"
    }
    pub const fn variant_name(self) -> &'static str {
        "RuntimeInventoryRead"
    }
}

impl std::fmt::Display for RoutePermissionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_runtime_permission_is_retained() {
        assert_eq!(
            RoutePermissionId::ALL,
            &[RoutePermissionId::RuntimeInventoryRead]
        );
        assert!(RoutePermissionId::parse("runtime:unknown:read").is_err());
    }
}
