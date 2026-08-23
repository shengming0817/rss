//! Provider-neutral L2 event metadata candidate.
//!
//! This module intentionally exposes one flat value type. Transport bags, provider sources,
//! payloads, receipts, stores, transaction outcomes, and L3/L4 implementation types stay outside
//! this surface. The candidate moves atomically to `rss-eventing` in #2159; no compatibility path
//! is provided from the crate root.
//!
//! ref: CloudEvents context attributes are separate from event data; unlike cqrs-es
//! `EventEnvelope`, this type does not expose an open metadata map or a `Debug` implementation.

/// Canonical tenant, occurrence time, and optional audit correlation for one L2 event.
///
/// Private representation plus the single typed constructor make additional public metadata
/// impossible for downstream callers to express. This type deliberately implements neither
/// `Debug` nor `Display`: event metadata must be accessed explicitly rather than logged wholesale.
pub struct EventMetadata {
    tenant_id: rss_request_context::TenantId,
    occurred_at: rss_contract::Timepoint,
    audit_correlation: Option<rss_diag_context::CorrelationId>,
}

impl EventMetadata {
    /// Constructs the complete closed metadata set.
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

    /// Borrows the optional canonical audit correlation identifier.
    #[must_use]
    pub fn audit_correlation(&self) -> Option<&rss_diag_context::CorrelationId> {
        self.audit_correlation.as_ref()
    }
}
