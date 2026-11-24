//! Observe committed preparation transactions before the first broker call in the isolated PG suite.
use super::*;
use rss_transactional_messaging::transport::Publisher;
use std::sync::Mutex;

pub(super) async fn install(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(r"
        CREATE TABLE public.relay_lease_trace(seq bigint, xid xid8);
        GRANT INSERT ON public.relay_lease_trace TO tmsg_runtime,rss_tmsg_relay;
        ALTER FUNCTION rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid)
            RENAME TO fixture_original_outbox_lease;
        CREATE FUNCTION rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid)
            RETURNS TABLE(lease_us bigint,remaining_us bigint,delivery_us bigint)
            LANGUAGE plpgsql AS $probe$
            BEGIN
                INSERT INTO public.relay_lease_trace VALUES ($2,pg_current_xact_id());
                RETURN QUERY SELECT * FROM rss_transactional_messaging.fixture_original_outbox_lease($1,$2,$3,$4,$5,$6);
            END $probe$;
        REVOKE ALL ON FUNCTION rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid) TO tmsg_runtime,rss_tmsg_relay;
    ").execute(owner).await?;
    Ok(())
}

pub(super) async fn remove(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(r"
        DROP FUNCTION rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid);
        ALTER FUNCTION rss_transactional_messaging.fixture_original_outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid)
            RENAME TO outbox_lease;
        DROP TABLE public.relay_lease_trace;
    ").execute(owner).await?;
    Ok(())
}

pub(super) struct PublisherProbe<'a> {
    pub owner: &'a sqlx::PgPool,
    pub transactions: Mutex<Vec<String>>,
}

impl Publisher<Vec<u8>> for PublisherProbe<'_> {
    type Receipt = ();
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> PublishOutcome<()> {
        let transactions = sqlx::query_scalar("SELECT DISTINCT t.xid::text FROM public.relay_lease_trace t JOIN rss_transactional_messaging.outbox o USING(seq) WHERE o.message_id=$1 ORDER BY 1")
            .bind(message.id().as_str()).fetch_all(self.owner).await.expect("observe committed preparation at publish");
        *self.transactions.lock().expect("fixture observation") = transactions;
        PublishOutcome::Confirmed(())
    }
}
