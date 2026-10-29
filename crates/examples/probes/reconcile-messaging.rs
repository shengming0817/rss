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
    ) -> Result<ReconcileStep<ReconcileDiff<u8>>, Error> {
        let observed = async {
        Ok(ReconcileDiff::between(
            DesiredState::present(1),
            ActualState::present(1),
        ))

        }.await;
        observed.map(ReconcileStep::Ready)
    }
    async fn apply<T: Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        _: ReconcileDiff<u8>,
        c: &Control<'_, T>,
    ) -> Result<ReconcileStep<()>, Error> {
        self.store
            .protect(claim, c, &self.label, |label, tx| {
                Box::pin(async move { (async move {
                    tx.with_connection(|conn| {
                        Box::pin(async move {
                            sqlx::query("SELECT 1").execute(conn).await?;
                            Ok(())
                        })
                    })
                    .await?;
                    let _borrow_after_await = label.len();
                    Ok(())
                }).await.map(rss_reconcile_postgres::ProtectedStep::Ready) })
            })
            .await
    }
}
pub async fn messages<T: Timer>(
    store: &rss_reconcile_postgres::PgMessagingStore,
    claim: &rss_reconcile_postgres::PgClaim,
    c: &Control<'_, T>,
    outbox: rss_transactional_messaging_postgres::PgOutboxWriter,
    message: rss_transactional_messaging::outbox::PendingMessage<Vec<u8>>,
) -> rss_transactional_messaging::transaction::LocalTxAttempt<
    ReconcileStep<()>,
    rss_transactional_messaging_postgres::PgError,
> {
    use rss_transactional_messaging::outbox::OutboxWriter;
    store.protect(claim, c, (), move |_, tx| {
        Box::pin(async move { (async move {
            tx.prepare_outbox_partitions(&message.partition().cloned().into_iter().collect::<Vec<_>>()).await?;
            outbox.append(tx, message).await?;
            Ok(())
        }).await.map(rss_reconcile_postgres::ProtectedStep::Ready) })
    })
    .await
}
