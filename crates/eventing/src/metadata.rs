//! Closed provider-neutral metadata carried by an event envelope.

/// Canonical tenant, occurrence time, and optional audit correlation for one L2 event.
///
/// The private representation and complete constructor make partial metadata unrepresentable.
/// This type deliberately implements neither `Debug` nor `Display`; callers must access each
/// field explicitly instead of logging the complete metadata value.
pub struct EventMetadata {
    tenant_id: rss_request_context::TenantId,
    occurred_at: rss_contract::Timepoint,
    audit_correlation: Option<rss_diag_context::CorrelationId>,
}

impl EventMetadata {
    /// Constructs the complete closed metadata set.
    #[must_use]
    pub fn new(
        tenant_id: rss_request_context::TenantId,
        occurred_at: rss_contract::Timepoint,
        audit_correlation: Option<rss_diag_context::CorrelationId>,
    ) -> Self {
        Self {
            tenant_id,
            occurred_at,
            audit_correlation,
        }
    }

    /// Returns the canonical tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> rss_request_context::TenantId {
        self.tenant_id
    }

    /// Returns the authority-free canonical event time.
    #[must_use]
    pub const fn occurred_at(&self) -> rss_contract::Timepoint {
        self.occurred_at
    }

    /// Borrows the optional audit correlation identifier.
    #[must_use]
    pub fn audit_correlation(&self) -> Option<&rss_diag_context::CorrelationId> {
        self.audit_correlation.as_ref()
    }
}
