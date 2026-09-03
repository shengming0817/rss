//! Tenant-only ambient execution scope.

#[derive(Clone, PartialEq, Eq, rss_redact::Redact)]
pub struct RequestCtx<T> {
    #[redact(sensitivity = internal)]
    tenant: T,
}

impl<T> RequestCtx<T> {
    #[must_use]
    pub const fn new(tenant: T) -> Self {
        Self { tenant }
    }

    #[must_use]
    pub const fn tenant(&self) -> &T {
        &self.tenant
    }
}

pub type AppCtx = RequestCtx<rss_request_context::TenantId>;

#[cfg(feature = "test-support")]
pub mod test_support {
    use super::{AppCtx, RequestCtx};
    use rss_request_context::TenantId;

    #[must_use]
    pub const fn app_ctx(tenant: TenantId) -> AppCtx {
        RequestCtx::new(tenant)
    }
}
