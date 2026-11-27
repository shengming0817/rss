use rss_request_context::{Clock, Deadline, ExecutionTimer};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

struct FrozenClock(Instant);
impl Clock for FrozenClock {
    fn now(&self) -> Instant {
        self.0
    }
}
impl ExecutionTimer for FrozenClock {
    async fn sleep_until(&self, deadline: Deadline) {
        if !deadline.is_expired(self.now()) {
            // This clock stays at its initial instant.
            std::future::pending::<()>().await;
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let clock = FrozenClock(Instant::now());
    let timeout = Duration::from_secs(3);
    let deadline = Deadline::from_timeout(&clock, timeout)?;
    let cancel = CancellationToken::new();
    let control = rss_ledger_postgres::Control::new(&clock, deadline, &cancel);
    assert_eq!(control.remaining(), timeout);

    let chain = rss_ledger::ChainId::parse("standalone-ledger")?;
    assert_eq!(chain.as_str(), "standalone-ledger");
    let _bound = rss_ledger_postgres::ReadLimit::new(1, 1024)?;
    #[cfg(feature = "messaging")]
    {
        let error = rss_transactional_messaging_postgres::PgError::from(
            rss_ledger_postgres::Error::Conflict,
        );
        assert_eq!(
            error.kind(),
            rss_transactional_messaging::error::MessagingErrorKind::Conflict
        );
    }
    println!("ledger consumer passed");
    Ok(())
}
