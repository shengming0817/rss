//! Real object PUT/inspection racing the same persisted tenant fence used by DR.
pub mod upgrade;
use super::*;
struct SwitchAfterInspection<'a> {
    real: &'a rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &'a sqlx::PgPool,
}
impl ArchiveObjectStore for SwitchAfterInspection<'_> {
    async fn put(&self, p: &Prepared, d: OperationDeadline) -> Result<Object, Error> {
        self.real.put(p, d).await
    }
    async fn inspect(
        &self,
        o: &Object,
        b: bool,
        d: OperationDeadline,
    ) -> Result<Option<Observation>, Error> {
        let actual = self.real.inspect(o, b, d).await?;
        // Isolate the archive race: DR's full atomic apply is proved by postgres-integration/dr.
        sqlx::query(
            "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
        )
        .bind(tenant().to_string())
        .execute(self.owner)
        .await
        .map_err(|_| Error::Unavailable)?;
        Ok(actual)
    }
}
#[allow(clippy::cognitive_complexity)] // reason: real object inspection and persisted fence race assertions share one archive job.
pub async fn run(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
    config: &PgConfig,
) -> anyhow::Result<()> {
    let id = seed(owner, "dr-race").await?;
    let r = request(id, 1, Hold::Release).await?;
    let raced = invoke(
        repository,
        &SwitchAfterInspection { real: store, owner },
        &r,
    )
    .await;
    assert!(
        raced.fold(
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| true
        ),
        "verified object cannot bypass the newly committed epoch"
    );
    assert!(is_hot(owner, id).await?);
    assert!(
        repository.receipt(&r, deadline()).await.is_err(),
        "old runtime must not settle through historical receipts"
    );
    let binding = rss_transactional_messaging::fence::ExecutionBinding::new(
        fence_fixture::binding().storage(),
        vec![(tenant(), rss_transactional_messaging::fence::Epoch::new(2)?)],
    )?;
    let next = PgArchiveRepository::connect(config.clone(), Timer::new(), binding).await?;
    assert!(
        next.receipt(&r, deadline()).await?.is_none(),
        "old job receipt does not authorize current-lineage cleanup"
    );
    let outcome = settled(invoke(&next, store, &r).await)?;
    assert_eq!(
        outcome,
        Outcome::Purged,
        "new claim reinspects the immutable object before purge"
    );
    assert!(!is_hot(owner, id).await?);
    let verified:i64=sqlx::query_scalar("SELECT o.verified_epoch FROM rss_transactional_messaging.archive_objects o JOIN rss_transactional_messaging.archive_jobs j ON j.tenant_id=o.tenant_id AND j.generation=o.generation WHERE j.dead_letter_id=$1::uuid").bind(id.to_string()).fetch_one(owner).await?;
    assert_eq!(verified, 2);
    next.close().await;
    Ok(())
}
