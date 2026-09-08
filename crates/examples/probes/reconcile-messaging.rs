use rss_reconcile::*;
pub struct BorrowedBusiness<'a> {
    pub store: &'a rss_reconcile_postgres::PgStore,
    pub label: &'a str,
}
impl Reconciler<rss_reconcile_postgres::PgClaim> for BorrowedBusiness<'_> {
    type State = u8;
    async fn observe<T: Timer>(
        &self,
        _: &rss_reconcile_postgres::PgClaim,
        _: &Control<'_, T>,
    ) -> Result<ReconcileDiff<u8>, Error> {
        Ok(ReconcileDiff::between(
            DesiredState::present(1),
            ActualState::present(1),
        ))
    }
    async fn apply<T: Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<u8>,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store
            .protect(claim, c, &self.label, |label, tx| {
                Box::pin(async move {
                    tx.with_connection(|conn| {
                        Box::pin(async move {
                            sqlx::query("SELECT 1").execute(conn).await?;
                            Ok(())
                        })
                    })
                    .await?;
                    let _borrow_after_await = label.len();
                    Ok(())
                })
            })
            .await
    }
}
pub async fn messages<T: Timer>(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    claim: &rss_reconcile_postgres::PgClaim,
    c: &Control<'_, T>,
    outbox: rss_transactional_messaging_postgres::PgOutboxStore<()>,
    message: rss_transactional_messaging::outbox::PendingMessage<Vec<u8>>,
) -> rss_transactional_messaging::transaction::LocalTxAttempt<
    (),
    rss_transactional_messaging_postgres::PgError,
> {
    use rss_transactional_messaging::outbox::OutboxStore;
    rss_reconcile_postgres::messaging::protect(runtime, claim, c, (), move |_, tx| {
        Box::pin(async move {
            outbox.append(tx, message).await?;
            Ok(())
        })
    })
    .await
}
