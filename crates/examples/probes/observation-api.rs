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
) -> Result<rss_observation_postgres::PgSource<C>, Error> {
    rss_observation_postgres::PgSource::new(store, grant, scope)
}
fn main() {}

#[cfg(feature = "observation-projection")]
pub async fn read_source<C: Clock,T: rss_projection::Timer>(
    source: &rss_observation_postgres::PgSource<C>, control: &rss_projection::Control<'_,T>,
) -> Result<(),rss_projection::Error> {
    use rss_projection::Source;
    source.high_water(source.scope(),control).await?;
    for event in source.read(source.scope(),None,rss_projection::BatchLimit::new(1)?,control).await? {
        source.resolve(&event,control).await?;
    }
    Ok(())
}
