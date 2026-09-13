//! One caller budget covers admission and retires interrupted probe connections.
use super::*;
use anyhow::Context as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::watch;

const DEADLINE: Duration = Duration::from_secs(10);
const GUARD: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct ManualTimer(watch::Sender<Duration>);
impl ManualTimer {
    fn new() -> Self {
        Self(watch::channel(Duration::ZERO).0)
    }
    fn advance(&self, now: Duration) {
        self.0.send_replace(now);
    }
}
impl Timer for ManualTimer {
    fn now(&self) -> Duration {
        *self.0.borrow()
    }
    async fn sleep_until(&self, deadline: Duration) {
        let mut time = self.0.subscribe();
        while *time.borrow_and_update() < deadline {
            if time.changed().await.is_err() {
                // The Timer retains the sender for the entire borrowed operation.
                return;
            }
        }
    }
}

fn pool_options() -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .test_before_acquire(false)
}

pub(crate) async fn verify(owner: &PgPool, options: &PgConnectOptions) -> anyhow::Result<()> {
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = attempts.clone();
    let pool = pool_options()
        .before_acquire(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(true) })
        })
        .connect_with(options.clone())
        .await?;
    preflight(&pool, &attempts).await?;
    acquire_wait(&pool).await?;
    stage_boundary(options).await?;
    for stop in [Stop::Cancel, Stop::Deadline, Stop::Drop] {
        probe_wait(&pool, owner, stop).await?;
    }
    pool.close().await;
    Ok(())
}

fn error_kind(result: Result<PgStore, Error>) -> Option<ErrorKind> {
    result.err().map(|error| error.kind())
}

async fn preflight(pool: &PgPool, attempts: &AtomicUsize) -> anyhow::Result<()> {
    for (cancelled, expired, expected) in [
        (true, false, ErrorKind::Cancelled),
        (false, true, ErrorKind::Deadline),
        (true, true, ErrorKind::Cancelled),
    ] {
        let timer = ManualTimer::new();
        let cancel = CancellationToken::new();
        if cancelled {
            cancel.cancel();
        }
        if expired {
            timer.advance(DEADLINE);
        }
        let control = Control::new(&timer, DEADLINE, &cancel);
        let before = attempts.load(Ordering::SeqCst);
        assert_eq!(
            error_kind(PgStore::new(pool.clone(), &control).await),
            Some(expected)
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            before,
            "rejected startup acquired a connection"
        );
    }
    fresh_admission(pool).await
}

async fn fresh_admission(pool: &PgPool) -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, clock.now() + GUARD, &cancel);
    PgStore::new(pool.clone(), &control).await?;
    assert!(
        !pool.is_closed(),
        "failed admission closed another pool owner"
    );
    Ok(())
}

async fn acquire_wait(pool: &PgPool) -> anyhow::Result<()> {
    for expected in [ErrorKind::Cancelled, ErrorKind::Deadline] {
        let held = pool.acquire().await?;
        let timer = ManualTimer::new();
        let cancel = CancellationToken::new();
        let control = Control::new(&timer, DEADLINE, &cancel);
        let mut startup = Box::pin(PgStore::new(pool.clone(), &control));
        assert!(futures::poll!(startup.as_mut()).is_pending());
        if expected == ErrorKind::Cancelled {
            cancel.cancel();
        } else {
            timer.advance(DEADLINE);
        }
        let result = tokio::time::timeout(GUARD, startup).await?;
        assert_eq!(error_kind(result), Some(expected));
        drop(held);
        fresh_admission(pool).await?;
    }
    Ok(())
}

async fn stage_boundary(options: &PgConnectOptions) -> anyhow::Result<()> {
    let timer = ManualTimer::new();
    let expire = timer.clone();
    let armed = Arc::new(AtomicBool::new(false));
    let trigger = armed.clone();
    let pool = pool_options()
        .before_acquire(move |_, _| {
            if trigger.load(Ordering::SeqCst) {
                expire.advance(DEADLINE);
            }
            Box::pin(async { Ok(true) })
        })
        .connect_with(options.clone())
        .await?;
    let cancel = CancellationToken::new();
    let control = Control::new(&timer, DEADLINE, &cancel);
    armed.store(true, Ordering::SeqCst);
    let result = tokio::time::timeout(GUARD, PgStore::new(pool.clone(), &control)).await?;
    assert_eq!(error_kind(result), Some(ErrorKind::Deadline));
    armed.store(false, Ordering::SeqCst);
    fresh_admission(&pool).await?;
    pool.close().await;
    Ok(())
}

#[derive(Clone, Copy)]
enum Stop {
    Cancel,
    Deadline,
    Drop,
}
impl Stop {
    fn signal(self, timer: &ManualTimer, cancel: &CancellationToken) -> Option<ErrorKind> {
        match self {
            Self::Cancel => {
                cancel.cancel();
                Some(ErrorKind::Cancelled)
            }
            Self::Deadline => {
                timer.advance(DEADLINE);
                Some(ErrorKind::Deadline)
            }
            // Dropping the future must retire its connection without either control signal.
            Self::Drop => None,
        }
    }
}

async fn probe_wait(pool: &PgPool, owner: &PgPool, stop: Stop) -> anyhow::Result<()> {
    let mut held = pool.acquire().await?;
    let original: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await?;
    let mut blocker = owner.begin().await?;
    sqlx::query("LOCK TABLE pg_catalog.pg_policy IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let timer = ManualTimer::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&timer, DEADLINE, &cancel);
    let mut startup = Box::pin(PgStore::new(pool.clone(), &control));
    assert!(futures::poll!(startup.as_mut()).is_pending());
    // Spend part of the original budget waiting for the sole checkout.
    timer.advance(Duration::from_secs(6));
    drop(held);
    tokio::time::timeout(GUARD, async {
        tokio::select! {
            result = &mut startup => anyhow::bail!("probe did not block: {:?}", error_kind(result)),
            result = wait_for_probe(owner, original) => result,
        }
    })
    .await??;
    if let Some(expected) = stop.signal(&timer, &cancel) {
        assert_eq!(
            error_kind(tokio::time::timeout(GUARD, startup).await?),
            Some(expected)
        );
    } else {
        drop(startup);
    }
    assert_replacement(pool, original).await?;
    blocker.rollback().await?;
    wait_for_retirement(owner, original).await?;
    fresh_admission(pool).await
}

async fn assert_replacement(pool: &PgPool, original: i32) -> anyhow::Result<()> {
    // Keep the lock: default return-to-pool ping would wait for the original query and
    // retain the only permit. Quarantine instead allows a replacement backend now.
    let mut replacement = tokio::time::timeout(GUARD, pool.acquire())
        .await
        .context("interrupted probe retained the only pool permit")??;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *replacement)
        .await?;
    assert_ne!(pid, original, "interrupted probe connection was reused");
    Ok(())
}

async fn wait_for_retirement(owner: &PgPool, original: i32) -> anyhow::Result<()> {
    tokio::time::timeout(GUARD, async {
        while sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(original)
        .fetch_one(owner)
        .await?
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await?
}

async fn wait_for_probe(owner: &PgPool, pid: i32) -> anyhow::Result<()> {
    loop {
        let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND state='active' AND wait_event_type='Lock' AND query LIKE '%WITH reachable AS%')")
            .bind(pid).fetch_one(owner).await?;
        if waiting {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
