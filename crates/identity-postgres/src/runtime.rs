//! Shared host resources. No tenant admission or pool lifecycle is owned here.
use rss_transactional_messaging_postgres::PgRuntime;
use std::sync::Arc;
pub(crate) struct RuntimeBundle {
    pub runtime: Arc<PgRuntime>,
    pub audit: rss_audit_postgres::Integrity,
    pub audit_budget: rss_audit_postgres::WriteBudget,
    pub instance: rss_identity_core::InstanceId,
}
