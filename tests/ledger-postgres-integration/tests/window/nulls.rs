//! NULLs introduced after admission must not turn SUM/BOOL_OR into a fail-open boundary.
use super::*;

pub(super) async fn run(
    store: &PgLedger,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let request = request(
        "window-nulls",
        "first",
        &vec![7; rss_ledger::MAX_PAYLOAD_BYTES],
    )?;
    committed(store.append(&request, control).await)?;
    for (damage, restore) in [
        (
            "ALTER TABLE rss_ledger.entries ALTER COLUMN record_id DROP NOT NULL; UPDATE rss_ledger.entries SET record_id=NULL WHERE chain_id='window-nulls'",
            "UPDATE rss_ledger.entries SET record_id='first' WHERE chain_id='window-nulls'; ALTER TABLE rss_ledger.entries ALTER COLUMN record_id SET NOT NULL",
        ),
        (
            "ALTER TABLE rss_ledger.entries ALTER COLUMN key_id DROP NOT NULL; UPDATE rss_ledger.entries SET key_id=NULL WHERE chain_id='window-nulls'",
            "UPDATE rss_ledger.entries SET key_id='fixture-key' WHERE chain_id='window-nulls'; ALTER TABLE rss_ledger.entries ALTER COLUMN key_id SET NOT NULL",
        ),
        (
            "ALTER TABLE rss_ledger.heads ALTER COLUMN key_id DROP NOT NULL; UPDATE rss_ledger.heads SET key_id=NULL WHERE chain_id='window-nulls'",
            "UPDATE rss_ledger.heads SET key_id='fixture-key' WHERE chain_id='window-nulls'; ALTER TABLE rss_ledger.heads ALTER COLUMN key_id SET NOT NULL",
        ),
        (
            "ALTER TABLE rss_ledger.heads ALTER COLUMN encoding_version DROP NOT NULL; UPDATE rss_ledger.heads SET encoding_version=NULL WHERE chain_id='window-nulls'",
            "UPDATE rss_ledger.heads SET encoding_version=1 WHERE chain_id='window-nulls'; ALTER TABLE rss_ledger.heads ALTER COLUMN encoding_version SET NOT NULL",
        ),
    ] {
        sqlx::raw_sql(damage).execute(owner).await?;
        let raw = raw_window(pool, request.ledger(), 0, 1, 1).await;
        let result = observe(
            store
                .read_window(
                    request.ledger(),
                    Sequence::new(0),
                    ReadLimit::new(1, 1)?,
                    control,
                )
                .await,
        );
        sqlx::raw_sql(restore).execute(owner).await?;
        assert_status_only(&raw?, 3)?;
        assert!(matches!(
            result,
            Observed::RolledBack(Error::StorageContract)
        ));
    }
    // Restoring the exact data/contract restores a valid, authenticated window.
    let page = committed(
        store
            .read_window(
                request.ledger(),
                Sequence::new(0),
                ReadLimit::new(1, 2 * 1024 * 1024)?,
                control,
            )
            .await,
    )?;
    assert_eq!(page.entries().len(), 1);
    Ok(())
}
