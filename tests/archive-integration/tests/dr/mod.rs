//! Real object PUT/inspection racing the same persisted tenant fence used by DR.
use super::*;
struct SwitchAfterInspection<'a> {
    real: &'a rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &'a sqlx::PgPool,
    change: Change,
}
enum Change {
    Epoch,
    Retention,
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
        match self.change {
            Change::Epoch => sqlx::query("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid")
                .bind(tenant().to_string()).execute(self.owner).await,
            Change::Retention => sqlx::query("UPDATE rss_transactional_messaging.policy SET receipt_retention_seconds=3*604800")
                .execute(self.owner).await,
        }.map_err(|_| Error::Unavailable)?;
        Ok(actual)
    }
}
#[allow(clippy::cognitive_complexity)] // reason: real object inspection and persisted fence race assertions share one archive job.
pub async fn run(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
    _config: &PgConfig,
) -> anyhow::Result<()> {
    Box::pin(retention_change(repository, store, owner)).await?;
    let recorded = recorded_before_switch(repository, store, owner).await?;
    let id = seed(owner, "dr-race").await?;
    let r = request(id, 1, Hold::Release).await?;
    let raced = invoke(
        repository,
        crate::execution(r.request().tenant(), 1),
        &SwitchAfterInspection {
            real: store,
            owner,
            change: Change::Epoch,
        },
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
        repository
            .receipt(crate::execution(r.request().tenant(), 1), &r, deadline())
            .await
            .is_err(),
        "old runtime must not settle through historical receipts"
    );
    let next = repository;
    resume_recorded(next, store, owner, recorded).await?;
    assert!(
        next.receipt(crate::execution(r.request().tenant(), 2), &r, deadline())
            .await?
            .is_none(),
        "old job receipt does not authorize current-lineage cleanup"
    );
    let outcome = settled(
        invoke(
            repository,
            crate::execution(r.request().tenant(), 2),
            store,
            &r,
        )
        .await,
    )?;
    assert_eq!(
        outcome,
        Outcome::Purged,
        "new claim reinspects the immutable object before purge"
    );
    assert!(!is_hot(owner, id).await?);
    let verified:i64=sqlx::query_scalar("SELECT o.verified_epoch FROM rss_transactional_messaging.archive_objects o JOIN rss_transactional_messaging.archive_jobs j ON j.tenant_id=o.tenant_id AND j.generation=o.generation WHERE j.dead_letter_id=$1::uuid").bind(id.to_string()).fetch_one(owner).await?;
    assert_eq!(verified, 2);
    Ok(())
}

async fn retention_change(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let id = seed(owner, "archive-policy-change").await?;
    let r = request(id, 1, Hold::Release).await?;
    let binding = crate::execution(tenant(), 1);
    let result = invoke(
        repository,
        binding,
        &SwitchAfterInspection {
            real: store,
            owner,
            change: Change::Retention,
        },
        &r,
    )
    .await;
    assert_eq!(
        result.fold(|_| None, Some, Some, Some, Some, Some),
        Some(Error::Retention)
    );
    assert!(is_hot(owner, id).await?);
    let fault: Option<String> = sqlx::query_scalar(
        "SELECT fault FROM rss_transactional_messaging.archive_jobs WHERE operation_id=$1::uuid",
    )
    .bind(r.request().operation().to_string())
    .fetch_one(owner)
    .await?;
    assert!(fault.is_none());
    expire(owner, &r).await?;
    sqlx::query("UPDATE rss_transactional_messaging.policy SET receipt_retention_seconds=604800")
        .execute(owner)
        .await?;
    assert_eq!(
        settled(invoke(repository, binding, store, &r).await)?,
        Outcome::Purged
    );
    let covered: bool=sqlx::query_scalar("SELECT (o.object->>'retainUntil')::bigint > extract(epoch FROM p.receipt_floor_until)
         FROM rss_transactional_messaging.archive_jobs j JOIN rss_transactional_messaging.archive_objects o USING(tenant_id,generation)
         CROSS JOIN rss_transactional_messaging.policy p WHERE j.operation_id=$1::uuid")
        .bind(r.request().operation().to_string()).fetch_one(owner).await?;
    assert!(covered);
    Ok(())
}

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

async fn recorded_before_switch(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
) -> anyhow::Result<(DeadLetterId, AuthorizedRequest)> {
    let id = seed(owner, "recorded-resume").await?;
    let r = request(id, 1, Hold::Release).await?;
    // Interrupt cleanup after real encryption, PUT, inspection and durable record. No proof is forged.
    sqlx::raw_sql("CREATE FUNCTION public.stop_recorded_purge() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture cut' USING ERRCODE='PZ001'; END $$; CREATE TRIGGER stop_recorded_purge BEFORE UPDATE OF capsule ON rss_transactional_messaging.consumer_dead_letter FOR EACH ROW WHEN (OLD.message_id='recorded-resume' AND NEW.capsule IS NULL) EXECUTE FUNCTION public.stop_recorded_purge()").execute(owner).await?;
    let result = invoke(
        repository,
        crate::execution(r.request().tenant(), 1),
        store,
        &r,
    )
    .await;
    sqlx::raw_sql("DROP TRIGGER stop_recorded_purge ON rss_transactional_messaging.consumer_dead_letter; DROP FUNCTION public.stop_recorded_purge()").execute(owner).await?;
    assert!(result.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true
    ));
    assert!(is_hot(owner, id).await?);
    Box::pin(expire_while_policy_locked(owner, &r)).await?;
    assert!(is_hot(owner, id).await?);
    Ok((id, r))
}

async fn resume_recorded(
    next: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
    (id, r): (DeadLetterId, AuthorizedRequest),
) -> anyhow::Result<()> {
    assert!(
        next.receipt(crate::execution(r.request().tenant(), 2), &r, deadline())
            .await?
            .is_none()
    );
    reject_old_proof(owner, &r).await?;
    let counted = CountInspection {
        store,
        count: AtomicUsize::new(0),
    };
    assert_eq!(
        settled(
            invoke(
                next,
                crate::execution(r.request().tenant(), 2),
                &counted,
                &r
            )
            .await
        )?,
        Outcome::Purged
    );
    assert!(
        counted.count.load(Ordering::Relaxed) > 0,
        "resume reinspects the exact durable object"
    );
    assert!(!is_hot(owner, id).await?);
    Ok(())
}

async fn recorded_proof(
    owner: &sqlx::PgPool,
    r: &AuthorizedRequest,
) -> anyhow::Result<(String, serde_json::Value)> {
    Ok(sqlx::query_as("SELECT j.lease_token::text,o.object FROM rss_transactional_messaging.archive_jobs j JOIN rss_transactional_messaging.archive_objects o USING(tenant_id,generation) WHERE j.operation_id=$1::uuid AND o.verified")
        .bind(r.request().operation().to_string()).fetch_one(owner).await?)
}

// Let the owner expire a recorded lease while the cleanup transaction waits on a policy update.
async fn expire_while_policy_locked(
    owner: &sqlx::PgPool,
    r: &AuthorizedRequest,
) -> anyhow::Result<()> {
    let (token, object) = recorded_proof(owner, r).await?;
    let mut update = owner.begin().await?;
    let writer: i32 = sqlx::query_scalar(
        "SELECT pg_backend_pid() FROM rss_transactional_messaging.policy FOR UPDATE",
    )
    .fetch_one(&mut *update)
    .await?;
    let mut cleanup = owner.acquire().await?;
    let reader: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *cleanup)
        .await?;
    let operation = r.request().operation().to_string();
    let expire = async {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT $1=ANY(pg_blocking_pids($2))")
                    .bind(writer)
                    .bind(reader)
                    .fetch_one(&mut *update)
                    .await?;
                if waiting {
                    return anyhow::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        // Policy precedes the job lock in both archive claim and purge.
        sqlx::query("SELECT 1 FROM rss_transactional_messaging.archive_jobs WHERE operation_id=$1::uuid FOR UPDATE NOWAIT")
            .bind(&operation).execute(&mut *update).await?;
        sqlx::query("UPDATE rss_transactional_messaging.archive_jobs SET lease_until=clock_timestamp() WHERE operation_id=$1::uuid")
            .bind(&operation).execute(&mut *update).await?;
        update.commit().await?;
        anyhow::Ok(())
    };
    let purge =
        sqlx::query("SELECT rss_transactional_messaging.archive_purge($1::uuid,$2::uuid,$3,$4)")
            .bind(&operation)
            .bind(token)
            .bind(r.request().digest().to_vec())
            .bind(object);
    let (result, released) = tokio::join!(purge.execute(&mut *cleanup), expire);
    released?;
    assert!(
        matches!(result,Err(sqlx::Error::Database(ref e)) if e.code().as_deref()==Some("PZ001"))
    );
    Ok(())
}

async fn reject_old_proof(owner: &sqlx::PgPool, r: &AuthorizedRequest) -> anyhow::Result<()> {
    let (token, object) = recorded_proof(owner, r).await?;
    let mut tx = owner.begin().await?;
    sqlx::query("SET LOCAL rss.execution_epoch='2'")
        .execute(&mut *tx)
        .await?;
    let denied =
        sqlx::query("SELECT rss_transactional_messaging.archive_purge($1::uuid,$2::uuid,$3,$4)")
            .bind(r.request().operation().to_string())
            .bind(token)
            .bind(r.request().digest().as_slice())
            .bind(object)
            .execute(&mut *tx)
            .await;
    tx.rollback().await?;
    assert!(
        matches!(denied, Err(sqlx::Error::Database(ref e)) if e.code().as_deref()==Some("PZ001")),
        "recorded proof and old lease do not authorize a new epoch"
    );
    Ok(())
}
