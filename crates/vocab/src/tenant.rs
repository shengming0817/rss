//! Internal authorization carriers built from public Foundation values.

use rss_request_context::{RowScope, TenantId};

/// Internal visibility projection. `All` is absent from the public Foundation `RowScope` and can
/// only be produced by the cross-tenant capability funnel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VisibilityScope {
    SelfOnly,
    Device,
    Tenant,
    All,
}

impl VisibilityScope {
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::SelfOnly => "self-only",
            Self::Device => "device",
            Self::Tenant => "tenant",
            Self::All => "all",
        }
    }
}

impl From<RowScope> for VisibilityScope {
    fn from(value: RowScope) -> Self {
        match value {
            RowScope::SelfOnly => Self::SelfOnly,
            RowScope::Device => Self::Device,
            RowScope::Tenant => Self::Tenant,
        }
    }
}

pub struct RowVisibility {
    scope: VisibilityScope,
    tenant: Option<TenantId>,
}

impl RowVisibility {
    #[must_use]
    pub fn new(scope: RowScope, tenant: TenantId) -> Self {
        Self {
            scope: scope.into(),
            tenant: Some(tenant),
        }
    }
    #[must_use]
    pub fn new_cross_tenant(_marker: CrossTenantVisibility) -> Self {
        Self {
            scope: VisibilityScope::All,
            tenant: None,
        }
    }
    #[must_use]
    pub const fn scope(&self) -> VisibilityScope {
        self.scope
    }
    #[must_use]
    pub const fn tenant(&self) -> Option<TenantId> {
        self.tenant
    }
}

pub struct CrossTenantCapability {
    _seal: (),
}
impl CrossTenantCapability {
    #[must_use]
    pub fn issue_for_verified_super_admin() -> Self {
        Self { _seal: () }
    }
}

pub struct CrossTenantVisibility {
    _seal: (),
}
impl CrossTenantVisibility {
    #[must_use]
    pub fn authorize(_capability: CrossTenantCapability) -> Self {
        Self { _seal: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scoped_and_cross_tenant_paths_are_disjoint() {
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let scoped = RowVisibility::new(RowScope::Tenant, tenant);
        assert_eq!(scoped.scope(), VisibilityScope::Tenant);
        assert_eq!(scoped.tenant(), Some(tenant));
        let marker = CrossTenantVisibility::authorize(
            CrossTenantCapability::issue_for_verified_super_admin(),
        );
        let global = RowVisibility::new_cross_tenant(marker);
        assert_eq!(global.scope(), VisibilityScope::All);
        assert_eq!(global.tenant(), None);
    }
}
