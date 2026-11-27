//! Shared source revalidation for every session path.
//! ref: tokio tokio/src/time/clock.rs (test-only, explicitly scoped time control).
#[derive(Clone)]
pub(crate) struct SessionChecks {
    pub(crate) timer: rss_request_context::SharedExecutionTimer,
    pub(crate) platform: Option<std::sync::Arc<dyn crate::platform::PlatformVerifier>>,
}
