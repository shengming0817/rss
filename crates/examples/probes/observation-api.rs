use rss_observation::{Clock, Error, ObservationStore, ReceiveOutcome, VerifiedBatch};
use rss_observation_postgres::PgStore;
use rss_request_context::Deadline;
pub async fn receive<C: Clock>(
    pool: sqlx::PgPool,
    clock: C,
    input: &VerifiedBatch,
    deadline: Deadline,
) -> Result<ReceiveOutcome, Error> {
    let store = PgStore::new(pool, clock, deadline).await?;
    let result = store.receive(input, deadline).await;
    store.close(deadline).await?;
    result
}
#[cfg(feature = "observation-projection")]
pub fn source<C: Clock>(
    store: std::sync::Arc<PgStore<C>>,
    grant: rss_observation::JournalReadGrant,
    scope: rss_projection::SourceScope,
    page_bytes: u32,
) -> Result<rss_observation_postgres::PgSource<C>, Error> {
    rss_observation_postgres::PgSource::new(store, grant, scope, page_bytes)
}
pub async fn reclaim<C: Clock>(
    maintenance: &rss_observation_postgres::PgMaintenance<C>,
    grant: rss_observation::MaintenanceGrant,
    window: rss_observation::ScanWindow,
    deadline: Deadline,
) -> Result<rss_observation::RetentionPage, Error> {
    use rss_observation::ObservationMaintenance;
    maintenance.reclaim(grant, window, deadline).await
}
fn main() {}

#[cfg(feature = "observation-projection")]
pub async fn read_source<C: Clock,T: rss_projection::Timer>(
    source: &rss_observation_postgres::PgSource<C>, control: &rss_projection::Control<'_,T>,
) -> Result<(),rss_projection::Error> {
    use rss_projection::{Event, PageBudget, ReadPage, Source};
    source.high_water(source.scope(),control).await?;
    let page = source.read(source.scope(),None,PageBudget::new(1,Event::MAX_PAYLOAD_BYTES)?,control).await?;
    let ReadPage::Events(events) = page else {
        // A budget large enough for any legal single reference must admit the first.
        return Err(rss_projection::ErrorKind::SourceContract.into());
    };
    for event in events {
        source.resolve(&event,control).await?;
    }
    Ok(())
}
