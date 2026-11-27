use super::*;

pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let empty = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d483")?;
    for store in [plain, ledger] {
        committed(
            store
                .read_tx_with_context(empty, control, (), |_, tx| {
                    Box::pin(async move {
                        let page = tx
                            .read_page(Cursor::start(empty), ReadLimit::new(1, 131072)?)
                            .await?;
                        assert!(page.records().is_empty());
                        tx.with_connection(|c| {
                            Box::pin(async move {
                                let readonly: String =
                                    sqlx::query_scalar("SHOW transaction_read_only")
                                        .fetch_one(c)
                                        .await?;
                                assert_eq!(readonly, "on");
                                Ok::<_, Error>(())
                            })
                        })
                        .await
                    })
                })
                .await,
        )?;
        rolled_back(store.read_tx_with_context(empty, control, (), |_, tx| Box::pin(async move {
            tx.with_connection(|c| Box::pin(async move {
                sqlx::query("INSERT INTO public.business_changes VALUES ('forbidden-read-write')").execute(c).await
            })).await
        })).await, |e| matches!(e, TransactionError::Operation(sql)
            if sql.as_database_error().and_then(|e| e.code()).as_deref()==Some("25006")));
    }
    let untouched: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM rss_audit.records WHERE tenant_id=$1::uuid) AND NOT EXISTS(SELECT FROM rss_ledger.heads WHERE tenant_id=$1::uuid) AND NOT EXISTS(SELECT FROM public.business_changes WHERE id='forbidden-read-write')")
        .bind(empty.to_string()).fetch_one(admin).await?;
    assert!(
        untouched,
        "reads cannot create heads or persist trusted business writes"
    );
    Ok(())
}
