use rss_transactional_messaging_recovery::archive::{Error, Retention};

#[test]
fn retention_preserves_database_safety_floor_and_strict_boundary() -> Result<(), Error> {
    let policy = Retention::new(20, 30)?;
    assert_eq!(policy.minimum_lock_until(100, 40)?, 140);
    assert!(policy.validate_hot_floor(10, 10).is_ok());
    assert_eq!(policy.validate_hot_floor(11, 10), Err(Error::Retention));
    assert_eq!(
        policy.minimum_lock_until(i64::MAX, 40),
        Err(Error::Retention)
    );
    assert!(Retention::new(0, 30).is_err());
    Ok(())
}

use rss_request_context::{Clock, Deadline, ExecutionTimer};
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_recovery::archive::*;
use std::{
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: injected test timer owns the paused Tokio clock.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, cutoff: Deadline) {
        tokio::time::sleep_until(cutoff.instant().into()).await;
    }
}
struct Authority {
    calls: AtomicUsize,
    behavior: u8,
}
impl Authorizer for Authority {
    async fn authorize(
        &self,
        c: Challenge<'_>,
        deadline: OperationDeadline,
    ) -> Result<Authorization, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.behavior {
            1 => Err(Error::Unauthorized),
            2 => std::future::pending().await,
            3 => {
                tokio::time::sleep(deadline.timeout()).await;
                Ok(c.authorized())
            }
            _ => Ok(c.authorized()),
        }
    }
}
fn request() -> Result<Request, Box<dyn std::error::Error>> {
    use rss_transactional_messaging_recovery::{DeadLetterId, OperationId, Version};
    Ok(Request::new(
        rss_request_context::TenantId::parse("11111111-1111-1111-1111-111111111111")?,
        DeadLetterId::new(),
        OperationId::new(),
        Version::new(1)?,
        Retention::new(20, 30)?,
        Hold::Release,
    ))
}
#[tokio::test(start_paused = true)]
async fn archive_authority_enforces_cutoff_before_business_access()
-> Result<(), Box<dyn std::error::Error>> {
    for (behavior, expired, expected) in [
        (0, false, None),
        (1, false, Some(Error::Unauthorized)),
        (2, false, Some(Error::Deadline)),
        (3, false, Some(Error::Deadline)),
        (0, true, Some(Error::Deadline)),
    ] {
        let authority = Authority {
            calls: AtomicUsize::new(0),
            behavior,
        };
        let cutoff = Deadline::from_timeout(&Timer, Duration::from_millis(10))?;
        if expired {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut business_calls = 0;
        let result = tokio::time::timeout(Duration::from_secs(1), async {
            let authorized = authorize(
                &authority,
                request().map_err(|_| Error::Invalid)?,
                &Timer,
                cutoff,
            )
            .await?;
            business_calls += 1;
            Ok::<_, Error>(authorized)
        })
        .await?;
        assert_eq!(result.err(), expected);
        assert_eq!(
            authority.calls.load(Ordering::SeqCst),
            usize::from(!expired)
        );
        assert_eq!(business_calls, usize::from(expected.is_none()));
    }
    Ok(())
}
struct Cached(Mutex<Option<Authorization>>);
impl Authorizer for Cached {
    async fn authorize(
        &self,
        _: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        self.0
            .lock()
            .map_err(|_| Error::Unavailable)?
            .take()
            .ok_or(Error::Unauthorized)
    }
}
#[tokio::test(start_paused = true)]
async fn archive_authority_rejects_a_different_request_proof()
-> Result<(), Box<dyn std::error::Error>> {
    // Capture a real challenge-issued proof and offer it for another immutable request.
    struct Capture(Mutex<Option<Authorization>>);
    impl Authorizer for Capture {
        async fn authorize(
            &self,
            c: Challenge<'_>,
            _: OperationDeadline,
        ) -> Result<Authorization, Error> {
            *self.0.lock().map_err(|_| Error::Unavailable)? = Some(c.authorized());
            Err(Error::Unauthorized)
        }
    }
    let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(1))?;
    let capture = Capture(Mutex::new(None));
    assert!(matches!(
        authorize(&capture, request()?, &Timer, cutoff).await,
        Err(Error::Unauthorized)
    ));
    let cached = Cached(capture.0);
    assert!(matches!(
        authorize(&cached, request()?, &Timer, cutoff).await,
        Err(Error::Unauthorized)
    ));
    Ok(())
}
