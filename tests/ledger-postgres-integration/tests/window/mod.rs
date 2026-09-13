//! Public read behavior and the exact production SQL's pre-transfer boundary.
use super::*;
use sqlx::{Row, postgres::PgRow};

const SQL: &str = include_str!("../../../../crates/ledger-postgres/src/window.sql");

fn query(
    sql: &'static str,
    ledger: &LedgerId,
    start: i64,
    count: u16,
    budget: i64,
) -> sqlx::query::Query<'static, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(sql)
        .bind(ledger.tenant().to_string())
        .bind(ledger.chain().as_str().to_owned())
        .bind(start)
        .bind(start.saturating_add(i64::from(count) - 1))
        .bind(budget)
        .bind("fixture-key")
        .bind(rss_ledger::V1_ENTRY_FIXED_BYTES as i64)
        .bind(rss_ledger::MAX_PAYLOAD_BYTES as i64)
}

async fn raw_window(
    pool: &PgPool,
    ledger: &LedgerId,
    start: i64,
    count: u16,
    budget: i64,
) -> anyhow::Result<Vec<PgRow>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(ledger.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    let rows = query(SQL, ledger, start, count, budget)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn run(
    store: &PgLedger,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    // Incompressible enough to exercise externally stored bytea, not just inline tiny rows.
    let mut bytes = vec![0; rss_ledger::MAX_PAYLOAD_BYTES];
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("fixture random bytes unavailable"))?;
    let ledger = request("预算链", "前驱", &bytes)?.ledger().clone();
    let first = committed(
        store
            .append(&request("预算链", "前驱", &bytes)?, control)
            .await,
    )?;
    let second = committed(
        store
            .append(&request("预算链", "记录", &bytes)?, control)
            .await,
    )?;
    let one = first.entry().encoded_len() as u64;
    let total = one + second.entry().encoded_len() as u64;
    admitted_windows(store, &ledger, one, total, control).await?;
    rejected_windows(store, &ledger, one, total, control).await?;
    empty_windows(store, &ledger, control).await?;
    pre_transfer(pool, &ledger, total).await?;
    corruption(store, owner, control).await?;
    snapshot(store, pool, owner, control).await?;
    Ok(())
}

async fn admitted_windows(
    store: &PgLedger,
    ledger: &LedgerId,
    one: u64,
    total: u64,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for (start, count, budget, expected, predecessor) in [
        (0, 1, one, 1, false),
        (0, 1024, total, 2, false),
        (1, 1, total, 1, true),
        (2, 1, total - one, 0, true),
    ] {
        let page = committed(
            store
                .read_window(
                    ledger,
                    Sequence::new(start),
                    ReadLimit::new(count, budget)?,
                    control,
                )
                .await,
        )?;
        assert_eq!(page.entries().len(), expected);
        assert_eq!(page.predecessor().is_some(), predecessor);
        assert_eq!(page.observed_tail(), Some(Sequence::new(1)));
        auth()?.verify_window(ledger, page.predecessor(), page.entries())?;
    }
    Ok(())
}

async fn rejected_windows(
    store: &PgLedger,
    ledger: &LedgerId,
    one: u64,
    total: u64,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for (start, count, budget) in [
        (0, 1, 1),
        (0, 1, one - 1),
        (0, 2, total - 1),
        (1, 1, total - one),
        (2, 1, one - 1),
    ] {
        assert!(matches!(
            observe(
                store
                    .read_window(
                        ledger,
                        Sequence::new(start),
                        ReadLimit::new(count, budget)?,
                        control
                    )
                    .await
            ),
            Observed::RolledBack(Error::ReadBudgetExceeded)
        ));
    }
    Ok(())
}

async fn empty_windows(
    store: &PgLedger,
    ledger: &LedgerId,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    assert!(matches!(
        observe(
            store
                .read_window(ledger, Sequence::new(3), ReadLimit::new(1, 1)?, control)
                .await
        ),
        Observed::RolledBack(Error::Protocol(rss_ledger::Error::SequenceGap))
    ));
    let absent = request("absent-window", "r", b"")?.ledger().clone();
    let page = committed(
        store
            .read_window(&absent, Sequence::new(0), ReadLimit::new(1, 1)?, control)
            .await,
    )?;
    assert!(page.entries().is_empty());
    assert!(page.observed_tail().is_none());
    assert!(matches!(
        observe(
            store
                .read_window(&absent, Sequence::new(1), ReadLimit::new(1, 1)?, control)
                .await
        ),
        Observed::RolledBack(Error::Protocol(rss_ledger::Error::SequenceGap))
    ));
    Ok(())
}

async fn pre_transfer(pool: &PgPool, ledger: &LedgerId, total: u64) -> anyhow::Result<()> {
    let rejected = raw_window(pool, ledger, 0, 1024, total as i64 - 1).await?;
    assert_status_only(&rejected, 5)?;
    assert_eq!(
        rejected[0].try_get::<i64, _>("required_bytes")?,
        total as i64
    );
    let allowed = raw_window(pool, ledger, 0, 1024, total as i64).await?;
    assert_eq!(allowed.len(), 3);
    let mut payloads = 0;
    for row in allowed {
        if !row.try_get::<bool, _>("header")? {
            assert_eq!(
                row.try_get::<Vec<u8>, _>("payload")?.len(),
                rss_ledger::MAX_PAYLOAD_BYTES
            );
            payloads += 1;
        }
    }
    assert_eq!(payloads, 2, "same SQL must actually emit admitted payloads");
    Ok(())
}

fn assert_status_only(rows: &[PgRow], status: i32) -> anyhow::Result<()> {
    assert_eq!(rows.len(), 1);
    let header = &rows[0];
    assert!(header.try_get::<bool, _>("header")?);
    assert_eq!(header.try_get::<i32, _>("status")?, status);
    for column in ["payload", "previous_tag", "tag"] {
        assert!(header.try_get::<Option<Vec<u8>>, _>(column)?.is_none());
    }
    for column in ["tenant_text", "chain_id", "record_id", "key_id"] {
        assert!(header.try_get::<Option<String>, _>(column)?.is_none());
    }
    assert!(header.try_get::<Option<i64>, _>("seq")?.is_none());
    assert!(
        header
            .try_get::<Option<i16>, _>("encoding_version")?
            .is_none()
    );
    Ok(())
}

async fn corruption(
    store: &PgLedger,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let original = request("window-corruption", "first", b"payload")?;
    committed(store.append(&original, control).await)?;
    let next = request("window-corruption", "next", b"next")?;
    committed(store.append(&next, control).await)?;
    sqlx::query("UPDATE rss_ledger.entries SET payload='changed'::bytea WHERE chain_id='window-corruption' AND seq=0")
        .execute(owner).await?;
    // Rejection cannot claim to have authenticated the payload it deliberately did not fetch.
    assert!(matches!(
        observe(
            store
                .read_window(
                    original.ledger(),
                    Sequence::new(0),
                    ReadLimit::new(1, 1)?,
                    control
                )
                .await
        ),
        Observed::RolledBack(Error::ReadBudgetExceeded)
    ));
    verify_tamper(store, original.ledger(), control).await?;
    sqlx::query("DELETE FROM rss_ledger.entries WHERE chain_id='window-corruption' AND seq=0")
        .execute(owner)
        .await?;
    assert!(matches!(
        observe(
            store
                .read_window(
                    original.ledger(),
                    Sequence::new(1),
                    ReadLimit::new(1, 1)?,
                    control
                )
                .await
        ),
        Observed::RolledBack(Error::Protocol(rss_ledger::Error::SequenceGap))
    ));
    malformed(store, owner, control).await?;
    Ok(())
}

async fn verify_tamper(
    store: &PgLedger,
    ledger: &LedgerId,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for start in [0, 1] {
        assert!(matches!(
            observe(
                store
                    .read_window(
                        ledger,
                        Sequence::new(start),
                        ReadLimit::new(1, 4096)?,
                        control
                    )
                    .await
            ),
            Observed::RolledBack(Error::Protocol(rss_ledger::Error::Authentication))
        ));
    }
    Ok(())
}

async fn malformed(
    store: &PgLedger,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let r = request("window-malformed", "r", b"original")?;
    let first = committed(store.append(&r, control).await)?;
    // Existing live owner; mutate after admission, then restore each fixture before asserting.
    for (change, restore, expected) in [
        (
            "ALTER TABLE rss_ledger.entries DROP CONSTRAINT entries_tag_check; UPDATE rss_ledger.entries SET tag=decode(repeat('aa',1048577),'hex') WHERE chain_id='window-malformed';",
            "UPDATE rss_ledger.entries SET tag=$1 WHERE chain_id='window-malformed'",
            3,
        ),
        (
            "UPDATE rss_ledger.entries SET key_id='different' WHERE chain_id='window-malformed';",
            "UPDATE rss_ledger.entries SET key_id='fixture-key' WHERE chain_id='window-malformed' AND $1::bytea IS NOT NULL",
            1,
        ),
        (
            "ALTER TABLE rss_ledger.entries DROP CONSTRAINT entries_encoding_version_check; UPDATE rss_ledger.entries SET encoding_version=2 WHERE chain_id='window-malformed';",
            "UPDATE rss_ledger.entries SET encoding_version=1 WHERE chain_id='window-malformed' AND $1::bytea IS NOT NULL",
            2,
        ),
    ] {
        sqlx::raw_sql(change).execute(owner).await?;
        let result = observe(
            store
                .read_window(r.ledger(), Sequence::new(0), ReadLimit::new(1, 1)?, control)
                .await,
        );
        let raw = raw_window(owner, r.ledger(), 0, 1, 1).await?;
        sqlx::query(restore)
            .bind(first.entry().tag().as_bytes().as_slice())
            .execute(owner)
            .await?;
        assert_status_only(&raw, expected)?;
        restore_constraint(owner, result, expected).await?;
    }
    Ok(())
}

async fn restore_constraint(
    owner: &PgPool,
    result: Observed<Window>,
    expected: i32,
) -> anyhow::Result<()> {
    match expected {
        3 => {
            sqlx::raw_sql("ALTER TABLE rss_ledger.entries ADD CONSTRAINT entries_tag_check CHECK(octet_length(tag)=32)").execute(owner).await?;
            assert!(matches!(
                result,
                Observed::RolledBack(Error::StorageContract)
            ));
        }
        1 => assert!(matches!(
            result,
            Observed::RolledBack(Error::Protocol(rss_ledger::Error::UnsupportedKey))
        )),
        _ => {
            sqlx::raw_sql("ALTER TABLE rss_ledger.entries ADD CONSTRAINT entries_encoding_version_check CHECK(encoding_version=1)").execute(owner).await?;
            assert!(matches!(
                result,
                Observed::RolledBack(Error::Protocol(rss_ledger::Error::UnsupportedEncoding))
            ));
        }
    }
    Ok(())
}

async fn snapshot(
    store: &PgLedger,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let first = committed(
        store
            .append(&request("window-snapshot", "first", b"first")?, control)
            .await,
    )?;
    let ledger = first.entry().ledger().clone();
    let mut blocker = owner.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock(2424)")
        .execute(&mut *blocker)
        .await?;
    let reader_pool = pool.clone();
    let reader_ledger = ledger.clone();
    let reader = tokio::spawn(async move {
        let mut tx = reader_pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(TENANT)
            .execute(&mut *tx)
            .await?;
        // The wrapper establishes a snapshot and blocks the same production statement; no
        // fixture hook or transaction isolation change is added to the library.
        const SNAPSHOT_SQL: &str = concat!(
            "WITH gate AS MATERIALIZED (SELECT pg_advisory_xact_lock($9)) SELECT w.* FROM gate CROSS JOIN LATERAL (",
            include_str!("../../../../crates/ledger-postgres/src/window.sql"),
            ") w"
        );
        let rows = query(SNAPSHOT_SQL, &reader_ledger, 0, 10, 4096)
            .bind(2424i64)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(rows)
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND objid=2424 AND NOT granted)")
                .fetch_one(owner).await?;
            if waiting { break Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    committed(
        store
            .append(&request("window-snapshot", "second", b"second")?, control)
            .await,
    )?;
    sqlx::query("SELECT pg_advisory_unlock(2424)")
        .execute(&mut *blocker)
        .await?;
    let rows = tokio::time::timeout(Duration::from_secs(5), reader).await???;
    assert_snapshot_rows(rows, first.entry())?;
    let next = committed(
        store
            .read_window(
                &ledger,
                Sequence::new(0),
                ReadLimit::new(10, 4096)?,
                control,
            )
            .await,
    )?;
    assert_eq!(next.observed_tail(), Some(Sequence::new(1)));
    assert_eq!(next.entries().len(), 2);
    Ok(())
}

fn assert_snapshot_rows(rows: Vec<PgRow>, first: &rss_ledger::Entry) -> anyhow::Result<()> {
    assert_eq!(rows.len(), 2);
    for row in rows {
        if row.try_get::<bool, _>("header")? {
            assert_eq!(row.try_get::<i64, _>("observed_tail")?, 0);
        } else {
            assert_eq!(row.try_get::<i64, _>("seq")?, 0);
            assert_eq!(row.try_get::<Vec<u8>, _>("tag")?, first.tag().as_bytes());
            assert_eq!(row.try_get::<Vec<u8>, _>("payload")?, b"first");
        }
    }
    Ok(())
}
