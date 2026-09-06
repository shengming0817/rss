use super::{fixture::*, scenarios::stage};
use rss_observation::{Body, Id, ObservationStore, ReadGrant};
use rss_projection::{BatchLimit, Source};
use sqlx::Row;
type Evidence = (
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    i64,
);
async fn evidence(f: &Fixture) -> anyhow::Result<Vec<Evidence>> {
    Ok(sqlx::query_as("SELECT tenant_id::text,scope,batch_id,raw,fingerprint,policy,decision,received_at FROM rss_observation.batches ORDER BY tenant_id,scope,sequence").fetch_all(&f.admin).await?)
}
pub async fn run() -> anyhow::Result<()> {
    let f = Fixture::new(true).await?;
    assert!(f.store().await.is_err());
    seed(&f).await?;
    let before = evidence(&f).await?;
    rollback_upgrade(&f).await?;
    let mut upgrade = f.owner.acquire().await?;
    sqlx::raw_sql(rss_observation_postgres::UPGRADE_SQL)
        .execute(&mut *upgrade)
        .await?;
    sqlx::raw_sql("GRANT SELECT ON rss_observation.journals TO handoff_runtime")
        .execute(&mut *upgrade)
        .await?;
    assert_eq!(before, evidence(&f).await?);
    verify_backfill(&f).await?;
    verify_rls(&f).await?;
    Ok(())
}
async fn seed(f: &Fixture) -> anyhow::Result<()> {
    // Deliberately seed tenant A's lexically later stream first, then B, then A's earlier stream.
    // Sequence order contradicts stream order, so both partition and ordering are observable.
    seed_stream(f, TENANT, "b-stream", 9).await?;
    seed_stream(f, OTHER, "b-stream", 1).await?;
    seed_stream(f, TENANT, "a-stream", 100).await?;
    Ok(())
}
async fn seed_stream(f: &Fixture, tenant: &str, object: &str, start: u64) -> anyhow::Result<()> {
    let stream = scope(tenant, object, "r", "source", "e")?;
    let mut tx = f.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT rss_observation.activate($1,NULL,$2,$3)")
        .bind(stream.encode()?)
        .bind(rss_observation::Policy::new(86400, 3600, 3600)?.encode()?)
        .bind(rss_observation::State::initial().encode()?)
        .execute(&mut *tx)
        .await?;
    seed_reports(&mut tx, &stream, start).await?;
    tx.commit().await?;
    Ok(())
}
async fn seed_reports(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    stream: &rss_observation::Scope,
    start: u64,
) -> anyhow::Result<()> {
    for (id, offset, body) in [
        ("first", 0, Body::Snapshot(vec![])),
        ("partial", 1, Body::Partial(vec![])),
        ("recovery", 2, Body::Snapshot(vec![])),
        (
            "next",
            3,
            Body::Delta {
                baseline: Id::new("recovery")?,
                previous: start + 2,
                changes: vec![],
            },
        ),
        (
            "failed",
            4,
            Body::Failed {
                code: Id::new("offline")?,
            },
        ),
    ] {
        stage(tx, &batch(stream, id, start + offset, "all", body)?).await?;
    }
    Ok(())
}
async fn rollback_upgrade(f: &Fixture) -> anyhow::Result<()> {
    // Transactional DDL failure restores FORCE RLS and removes all partial new state.
    let mut upgrade = f.owner.acquire().await?;
    let broken = rss_observation_postgres::UPGRADE_SQL.replace("COMMIT;", "SELECT 1/0; COMMIT;");
    sqlx::raw_sql(sqlx::AssertSqlSafe(broken))
        .execute(&mut *upgrade)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("upgrade fault did not fire"))?;
    sqlx::raw_sql("ROLLBACK").execute(&mut *upgrade).await?;
    let force: bool = sqlx::query_scalar(
        "SELECT relforcerowsecurity FROM pg_class WHERE oid='rss_observation.batches'::regclass",
    )
    .fetch_one(&f.admin)
    .await?;
    assert!(force);
    assert!(f.store().await.is_err());
    Ok(())
}
async fn verify_backfill(f: &Fixture) -> anyhow::Result<()> {
    let store = f.store().await?;
    verify_tenant(
        f,
        store.clone(),
        TENANT,
        &[
            ("a-stream", 100),
            ("a-stream", 102),
            ("a-stream", 103),
            ("b-stream", 9),
            ("b-stream", 11),
            ("b-stream", 12),
        ],
    )
    .await?;
    verify_tenant(
        f,
        store.clone(),
        OTHER,
        &[("b-stream", 1), ("b-stream", 3), ("b-stream", 4)],
    )
    .await?;
    let absent:(i64,i64)=sqlx::query_as("SELECT count(*) FILTER(WHERE NOT applicable),count(*) FILTER(WHERE NOT applicable AND log_position IS NULL) FROM rss_observation.batches").fetch_one(&f.admin).await?;
    assert_eq!(absent, (6, 6));
    continue_tenant(f, store.clone(), TENANT, "a-stream", 105, 7).await?;
    continue_tenant(f, store, OTHER, "b-stream", 6, 4).await?;
    Ok(())
}
async fn verify_tenant(
    f: &Fixture,
    store: std::sync::Arc<rss_observation_postgres::PgStore<Clock>>,
    tenant: &str,
    expected: &[(&str, u64)],
) -> anyhow::Result<()> {
    let source = f.source(store, tenant)?;
    let events = source
        .read(source.scope(), None, BatchLimit::new(20)?)
        .await?;
    assert_eq!(events.len(), expected.len());
    for (index, (event, (object, sequence))) in events.iter().zip(expected).enumerate() {
        assert_eq!(event.position().get(), index as u64 + 1);
        let record = source.resolve(event, deadline()).await?;
        assert_eq!(record.record().scope().object().as_str(), *object);
        assert_eq!(record.record().batch().sequence(), *sequence);
    }
    Ok(())
}
async fn continue_tenant(
    f: &Fixture,
    store: std::sync::Arc<rss_observation_postgres::PgStore<Clock>>,
    tenant: &str,
    object: &str,
    sequence: u64,
    position: u64,
) -> anyhow::Result<()> {
    let stream = scope(tenant, object, "r", "source", "e")?;
    assert!(
        store
            .lookup(
                &ReadGrant::verify(&Trusted, stream.clone())?,
                &Id::new("failed")?,
                deadline()
            )
            .await?
            .is_some()
    );
    store
        .receive(
            &batch(&stream, "live", sequence, "all", Body::Snapshot(vec![]))?,
            deadline(),
        )
        .await?;
    let source = f.source(store, tenant)?;
    assert_eq!(
        source.high_water(source.scope()).await?.map(|p| p.get()),
        Some(position)
    );
    Ok(())
}
async fn verify_rls(f: &Fixture) -> anyhow::Result<()> {
    let row=sqlx::query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='rss_observation.journals'::regclass").fetch_one(&f.admin).await?;
    assert!(
        row.try_get::<bool, _>("relrowsecurity")?
            && row.try_get::<bool, _>("relforcerowsecurity")?
    );
    Ok(())
}
