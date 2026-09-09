pub struct TokioTimer;
impl rss_request_context::Clock for TokioTimer {
    #[allow(clippy::disallowed_methods)] // reason: this concrete test clock owns the Tokio time domain.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl rss_request_context::ExecutionTimer for TokioTimer {
    async fn sleep_until(&self, deadline: rss_request_context::Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
