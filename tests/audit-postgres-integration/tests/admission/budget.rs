use super::*;
use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;

pub(super) async fn run(pool: &PgPool) -> anyhow::Result<()> {
    for ledger in [false, true] {
        let clock = TestClock;
        let cancel = CancellationToken::new();
        let total = Deadline::from_timeout(&clock, Duration::from_secs(10))?;
        let expired = Deadline::at(clock.now());
        let control = Control::new(&clock, total, expired, &cancel);
        let integrity = if ledger {
            Integrity::Ledger(auth()?)
        } else {
            Integrity::Plain
        };
        // Both startup entrypoints use the owner cutoff even after Operation expired.
        let store = PgAudit::new(pool.clone(), integrity, write_budget()?, &control).await?;
        let mut actual = pool.acquire().await?;
        store.validate_connection(&mut actual, &control).await?;
        expired_owner(pool, &store, &mut actual, ledger).await?;
        let result = store
            .read_page(
                Cursor::start(tenant()?),
                ReadLimit::new(1, 131072)?,
                &control,
            )
            .await;
        rolled_back(result, |e| matches!(e, Error::Deadline(Stage::Operation)));
    }
    Ok(())
}

async fn expired_owner(
    pool: &PgPool,
    store: &PgAudit,
    actual: &mut sqlx::PgConnection,
    ledger: bool,
) -> anyhow::Result<()> {
    let clock = TestClock;
    let cancel = CancellationToken::new();
    let expired = Deadline::at(clock.now());
    let control = Control::new(&clock, expired, expired, &cancel);
    let integrity = if ledger {
        Integrity::Ledger(auth()?)
    } else {
        Integrity::Plain
    };
    assert!(matches!(
        PgAudit::new(pool.clone(), integrity, write_budget()?, &control).await,
        Err(Error::Deadline(Stage::Acquire))
    ));
    assert!(matches!(
        store.validate_connection(actual, &control).await,
        Err(Error::Deadline(Stage::Setup))
    ));
    Ok(())
}
