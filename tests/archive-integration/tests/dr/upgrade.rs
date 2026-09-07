//! Load genuine verified object evidence into the 0006 schema, then upgrade it in place.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
struct CountInspection<'a> {
    store: &'a rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    count: AtomicUsize,
}
impl ArchiveObjectStore for CountInspection<'_> {
    async fn put(&self, p: &Prepared, d: OperationDeadline) -> Result<Object, Error> {
        self.store.put(p, d).await
    }
    async fn inspect(
        &self,
        o: &Object,
        body: bool,
        d: OperationDeadline,
    ) -> Result<Option<Observation>, Error> {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.store.inspect(o, body, d).await
    }
}
#[allow(clippy::cognitive_complexity)] // reason: ordered real object evidence export, 0006 upgrade and fenced cleanup assertions share one fixture.
pub async fn run(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
    options: PgConnectOptions,
    config: PgConfig,
) -> anyhow::Result<()> {
    let id = seed(owner, "upgrade-archive").await?;
    let r = request(id, 1, Hold::Release).await?;
    // Interrupt cleanup after real encryption, PUT, inspection and durable record. No proof is forged.
    sqlx::raw_sql("CREATE FUNCTION public.stop_upgrade_purge() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture cut' USING ERRCODE='PZ001'; END $$; CREATE TRIGGER stop_upgrade_purge BEFORE UPDATE OF capsule ON rss_transactional_messaging.consumer_dead_letter FOR EACH ROW WHEN (OLD.message_id='upgrade-archive' AND NEW.capsule IS NULL) EXECUTE FUNCTION public.stop_upgrade_purge()").execute(owner).await?;
    let result = invoke(repository, store, &r).await;
    sqlx::raw_sql("DROP TRIGGER stop_upgrade_purge ON rss_transactional_messaging.consumer_dead_letter; DROP FUNCTION public.stop_upgrade_purge()").execute(owner).await?;
    assert!(result.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true
    ));
    assert!(is_hot(owner, id).await?);
    let source: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(d) FROM rss_transactional_messaging.consumer_dead_letter d WHERE id=$1::uuid").bind(id.to_string()).fetch_one(owner).await?;
    let job: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(j)-'claim_epoch'-'claim_lineage' FROM rss_transactional_messaging.archive_jobs j WHERE operation_id=$1::uuid").bind(r.request().operation().to_string()).fetch_one(owner).await?;
    let object: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(o)-'verified_epoch'-'verified_lineage' FROM rss_transactional_messaging.archive_objects o WHERE operation_id=$1::uuid AND verified").bind(r.request().operation().to_string()).fetch_one(owner).await?;
    sqlx::raw_sql("CREATE DATABASE archive_upgrade")
        .execute(owner)
        .await?;
    let upgraded = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(options.database("archive_upgrade"))
        .await?;
    let old_schema = MIGRATION_SQL
        .strip_suffix(DR_UPGRADE_SQL)
        .ok_or_else(|| anyhow::anyhow!("0006 boundary"))?;
    sqlx::raw_sql(old_schema).execute(&upgraded).await?;
    for (table, value) in [
        ("consumer_dead_letter", &source),
        ("archive_jobs", &job),
        ("archive_objects", &object),
    ] {
        // Table identifiers come only from the fixed fixture list above.
        let sql = format!(
            "INSERT INTO rss_transactional_messaging.{table} SELECT * FROM jsonb_populate_record(NULL::rss_transactional_messaging.{table},$1)"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(value)
            .execute(&upgraded)
            .await?;
    }
    sqlx::raw_sql(DR_UPGRADE_SQL).execute(&upgraded).await?;
    for (table, value) in [
        ("consumer_dead_letter", &source),
        ("archive_jobs", &job),
        ("archive_objects", &object),
    ] {
        // Table identifiers come only from the fixed fixture list above.
        let sql = format!(
            "SELECT to_jsonb(v)-'claim_epoch'-'claim_lineage'-'verified_epoch'-'verified_lineage' FROM rss_transactional_messaging.{table} v"
        );
        let after: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&upgraded)
            .await?;
        assert_eq!(
            &after, value,
            "0006 {table} evidence is unchanged by upgrade"
        );
    }
    fence_fixture::provision(&upgraded).await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO archive_worker; GRANT SELECT ON rss_transactional_messaging.consumer_dead_letter,rss_transactional_messaging.archive_jobs,rss_transactional_messaging.archive_objects TO archive_worker; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.archive_claim(uuid,uuid,bigint,bytea,bigint,bigint,boolean,bigint),rss_transactional_messaging.archive_prepare(uuid,uuid,bytea,jsonb,bytea),rss_transactional_messaging.archive_record(uuid,uuid,bytea,uuid,jsonb),rss_transactional_messaging.archive_purge(uuid,uuid,bytea,jsonb),rss_transactional_messaging.archive_missing(uuid,uuid,bytea,uuid,jsonb),rss_transactional_messaging.archive_fault(uuid,uuid,bytea,text) TO archive_worker").execute(&upgraded).await?;
    let next = Box::pin(PgArchiveRepository::connect(
        config,
        Timer::new(),
        fence_fixture::binding(),
    ))
    .await?;
    assert!(
        next.receipt(&r, deadline()).await?.is_none(),
        "pre-upgrade verified evidence supplies no current execution authority"
    );
    let denied =
        sqlx::query("SELECT rss_transactional_messaging.archive_purge($1::uuid,$2::uuid,$3,$4)")
            .bind(r.request().operation().to_string())
            .bind(job["lease_token"].as_str())
            .bind(r.request().digest().as_slice())
            .bind(&object["object"])
            .execute(&upgraded)
            .await;
    assert!(
        matches!(denied, Err(sqlx::Error::Database(ref e)) if e.code().as_deref()==Some("PZ001")),
        "old lease must be fenced"
    );
    assert!(is_hot(&upgraded, id).await?);
    let counted = CountInspection {
        store,
        count: AtomicUsize::new(0),
    };
    assert_eq!(settled(invoke(&next, &counted, &r).await)?, Outcome::Purged);
    assert!(
        counted.count.load(Ordering::Relaxed) > 0,
        "current worker reinspects the old exact object version"
    );
    assert!(!is_hot(&upgraded, id).await?);
    let current: bool = sqlx::query_scalar("SELECT verified AND verified_epoch=1 AND verified_lineage=decode(repeat('02',16),'hex') FROM rss_transactional_messaging.archive_objects").fetch_one(&upgraded).await?;
    assert!(current);
    next.close().await;
    upgraded.close().await;
    Ok(())
}
