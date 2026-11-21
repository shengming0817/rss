//! Boundaries between claim ACK, stream polling, dual lease checks and terminal settlement.
use super::*;
use futures::StreamExt;
use rss_transactional_messaging::{
    error::MessagingErrorKind,
    inbox::{ConsumerIdentity, IdempotencyDisposition, InboxStore},
};

async fn project(p: &PgLocalProjection<Effect, Key>) -> anyhow::Result<PgProjectionOutcome> {
    Ok(only(
        collect_batch(p.project_batch(
            execution(tenant(), 1),
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        ))
        .await?,
    )?)
}

pub(super) async fn run(f: &Fixture) -> anyhow::Result<()> {
    let p = f
        .projection(Effect {
            gate: None,
            reject: false,
            fail: false,
        })
        .await?;
    stale_stream(f, &p).await?;
    inbox_contention(f, &p).await?;
    windows(f, &p).await
}

async fn stale_stream(f: &Fixture, p: &PgLocalProjection<Effect, Key>) -> anyhow::Result<()> {
    let binding = execution(tenant(), 1);
    for (id, change, restore) in [
        (
            "lease-epoch",
            "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=current_setting('rss.tenant_id')::uuid",
            "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1 WHERE tenant_id=current_setting('rss.tenant_id')::uuid",
        ),
        (
            "lease-lineage",
            "UPDATE rss_transactional_messaging.storage_lineage SET lineage=decode(repeat('03',16),'hex')",
            "UPDATE rss_transactional_messaging.storage_lineage SET lineage=decode(repeat('02',16),'hex')",
        ),
    ] {
        f.append(id, "orders").await?;
        let stream = p
            .project_batch(
                binding,
                &Validator,
                NonZeroUsize::MIN,
                deadline(),
                Duration::from_secs(5),
            )
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(change))
            .execute(&f.owner)
            .await?;
        assert!(
            matches!(only(stream.collect().await), Err(error) if error.kind()==MessagingErrorKind::OwnershipLost)
        );
        assert_eq!(f.state(id).await?, (0, 0, None, "publishing".into()));
        sqlx::raw_sql(sqlx::AssertSqlSafe(restore))
            .execute(&f.owner)
            .await?;
        sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp() WHERE message_id=$1").bind(id).execute(&f.owner).await?;
        committed_projection(project(p).await?)?;
    }
    f.append("lease-takeover", "orders").await?;
    let stale = p
        .project_batch(
            binding,
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        )
        .await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET lease_until=clock_timestamp() WHERE message_id='lease-takeover'").execute(&f.owner).await?;
    let fresh = p
        .project_batch(
            binding,
            &Validator,
            NonZeroUsize::MIN,
            deadline(),
            Duration::from_secs(5),
        )
        .await?;
    assert_eq!(
        attempt_status(only(stale.collect().await)?)?,
        Status::InfrastructureTransient
    );
    assert_eq!(
        f.state("lease-takeover").await?,
        (0, 0, None, "publishing".into())
    );
    committed_projection(only(fresh.collect().await)?)?;
    Ok(())
}

async fn inbox_contention(f: &Fixture, p: &PgLocalProjection<Effect, Key>) -> anyhow::Result<()> {
    let id = "lease-contended";
    f.append(id, "orders").await?;
    let message = message(id, "orders")?;
    let identity = ConsumerIdentity::new(
        tenant(),
        group()?,
        message.id().clone(),
        message.metadata().contract().clone(),
    );
    let other = PgInboxStore::new(
        f.worker.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    let IdempotencyDisposition::Acquired(held) = other
        .claim(execution(tenant(), 1), &identity, deadline())
        .await?
    else {
        anyhow::bail!("external consumer did not acquire Inbox")
    };
    assert!(matches!(project(p).await?, PgProjectionOutcome::InProgress));
    assert_eq!(f.state(id).await?, (0, 0, None, "pending".into()));
    other.release(held, deadline()).await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp() WHERE message_id=$1").bind(id).execute(&f.owner).await?;
    committed_projection(project(p).await?)?;
    Ok(())
}

async fn windows(f: &Fixture, p: &PgLocalProjection<Effect, Key>) -> anyhow::Result<()> {
    // The marker participates in the renewing transaction, so partial commits are visible.
    sqlx::raw_sql("CREATE TABLE public.lease_changes(id text, relation text);
        GRANT INSERT ON public.lease_changes TO projection_worker,rss_tmsg_relay;
        CREATE FUNCTION public.capture_lease() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN
        IF NEW.message_id='lease-short' AND TG_TABLE_NAME='inbox' THEN
          IF TG_OP='INSERT' THEN NEW.lease_until:=clock_timestamp()+interval '450 milliseconds';
          ELSIF OLD.lease_until IS DISTINCT FROM NEW.lease_until THEN RETURN NULL; END IF;
        END IF;
        IF TG_OP='UPDATE' AND OLD.lease_until IS NOT NULL AND NEW.lease_until IS NOT NULL AND OLD.lease_until<>NEW.lease_until THEN
          INSERT INTO public.lease_changes VALUES(NEW.message_id,TG_TABLE_NAME);
        END IF;
        RETURN NEW; END $f$;
        CREATE TRIGGER sample_inbox BEFORE INSERT OR UPDATE ON rss_transactional_messaging.inbox FOR EACH ROW EXECUTE FUNCTION public.capture_lease();
        CREATE TRIGGER sample_source BEFORE UPDATE ON rss_transactional_messaging.outbox FOR EACH ROW EXECUTE FUNCTION public.capture_lease();")
        .execute(&f.owner).await?;
    f.append("lease-full", "orders").await?;
    committed_projection(project(p).await?)?;
    f.append("lease-short", "orders").await?;
    assert_eq!(
        attempt_status(project(p).await?)?,
        Status::InfrastructureTransient
    );
    assert_eq!(
        f.state("lease-short").await?,
        (0, 0, None, "pending".into())
    );
    let writes: i64 = sqlx::query_scalar("SELECT count(*) FROM public.lease_changes")
        .fetch_one(&f.owner)
        .await?;
    assert_eq!(
        writes, 0,
        "full leases were rewritten or half of a failed renewal committed"
    );
    sqlx::raw_sql("DROP TRIGGER sample_inbox ON rss_transactional_messaging.inbox; DROP TRIGGER sample_source ON rss_transactional_messaging.outbox; UPDATE rss_transactional_messaging.outbox SET retry_after=clock_timestamp() WHERE message_id='lease-short'").execute(&f.owner).await?;
    committed_projection(project(p).await?)?;
    f.append("lease-delivery-expired", "orders").await?;
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET automatic_retry_deadline=clock_timestamp() WHERE message_id='lease-delivery-expired'").execute(&f.owner).await?;
    assert!(matches!(
        project(p).await?,
        PgProjectionOutcome::DeliveryExpired
    ));
    assert_eq!(
        f.state("lease-delivery-expired").await?,
        (0, 0, None, "dead_letter".into())
    );
    // The later dead-letter discovery scenario starts with a clean domain.
    sqlx::query("UPDATE rss_transactional_messaging.outbox SET status='resolved' WHERE message_id='lease-delivery-expired'").execute(&f.owner).await?;
    Ok(())
}
