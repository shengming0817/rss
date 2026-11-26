use super::*;

struct ObservePrefix(Writer);
impl PgEffect for ObservePrefix {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        event: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        if event.id() == "second" {
            let scope = scope.clone();
            let prefix: (i64,bool,bool,i64) = tx.with_connection(move |conn| Box::pin(async move {
                sqlx::query_as("SELECT c.position,
                    EXISTS(SELECT FROM rss_projection.receipts r WHERE (r.tenant_id,r.source_id,r.projection_id,r.generation)=(c.tenant_id,c.source_id,c.projection_id,c.generation) AND event_id='seed'),
                    EXISTS(SELECT FROM rss_projection.receipts r WHERE (r.tenant_id,r.source_id,r.projection_id,r.generation)=(c.tenant_id,c.source_id,c.projection_id,c.generation) AND event_id='first'),
                    (SELECT count(*) FROM public.batch_steps b WHERE (b.tenant_id,b.source_id,b.projection_id,b.generation)=(c.tenant_id,c.source_id,c.projection_id,c.generation))
                    FROM rss_projection.checkpoints c WHERE tenant_id=$1::uuid AND source_id=$2 AND projection_id=$3 AND generation=$4")
                  .bind(scope.source().tenant().to_string()).bind(scope.source().source())
                  .bind(scope.projection()).bind(scope.generation()).fetch_one(conn).await
            })).await?;
            println!(
                "projection_callback_prefix checkpoint={} seed={} first={} business_rows={}",
                prefix.0, prefix.1, prefix.2, prefix.3
            );
            assert_eq!(prefix, (0, true, false, 1));
        }
        self.0.apply(tx, scope, event).await
    }
}

pub(super) async fn verify(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("batch-prefix", TENANT)?;
    let seed = event(&s, 0, "seed", b"seed")?;
    store
        .initialize(
            &s,
            &DEFINITION,
            GenerationStart::after(seed.position(), vec![BaselineReceipt::from_event(&seed)])?,
            ReplayBound::Live,
            control,
        )
        .await?;
    for reject in [true, false] {
        let rec = Arc::new(Recorder::default());
        rec.reject.store(reject, Ordering::SeqCst);
        let exec = store.projection(
            store.takeover(&s, &DEFINITION, control).await?,
            ObservePrefix(Writer(rec.clone())),
        )?;
        let events = vec![
            event(&s, 1, "seed", b"seed")?,
            event(&s, 2, "first", b"first")?,
            event(&s, 3, "second", b"pause")?,
        ];
        let (result, new_claim) = tokio::join!(
            Box::pin(exec.execute_batch(Some(seed.position()), events, control)),
            Box::pin(wait_for_takeover(store, owner, control, &s, &rec))
        );
        let fresh = store.projection(new_claim?, Writer(rec.clone()))?;
        assert_eq!(rec.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            exec.checkpoint(control).await.map_err(|e| e.kind()),
            Err(ErrorKind::Fenced)
        );
        if reject {
            assert_eq!(result.map_err(|e| e.kind()), Err(ErrorKind::Rejected));
            assert_eq!(snapshot(owner, &s).await?, (Some(0), 1, vec![], 0));
        } else {
            assert_eq!(
                result?,
                [
                    ApplyOutcome::Duplicate,
                    ApplyOutcome::Applied,
                    ApplyOutcome::Applied
                ]
            );
            verify_suffix(&fresh, &s, &rec, owner, control).await?;
        }
    }
    Ok(())
}

async fn verify_suffix(
    fresh: &PgProjection<Writer>,
    s: &ProjectionScope,
    rec: &Recorder,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let next = Some(Position::new(3)?);
    let changed = vec![
        event(s, 4, "unseen", b"new")?,
        event(s, 5, "first", b"changed")?,
    ];
    assert_eq!(
        fresh
            .execute_batch(next, changed, control)
            .await
            .map_err(|e| e.kind()),
        Err(ErrorKind::Conflict)
    );
    assert_eq!(rec.calls.load(Ordering::SeqCst), 2);
    let suffix = vec![
        event(s, 4, "filtered", b"filter")?,
        event(s, 5, "first", b"first")?,
    ];
    assert_eq!(
        fresh.execute_batch(next, suffix, control).await?,
        [ApplyOutcome::Filtered, ApplyOutcome::Duplicate]
    );
    assert_eq!(snapshot(owner, s).await?, (Some(5), 4, vec![2, 3], 1));
    Ok(())
}

async fn wait_for_takeover(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
    s: &ProjectionScope,
    rec: &Recorder,
) -> anyhow::Result<PgClaim> {
    let _release_on_error = rec.resume.clone().drop_guard();
    tokio::time::timeout(Duration::from_secs(5), rec.paused.cancelled()).await?;
    assert_eq!(snapshot(owner, s).await?, (Some(0), 1, vec![], 0));
    let mut taking = Box::pin(store.takeover(s, &DEFINITION, control));
    tokio::select! {
        claim = &mut taking => { claim?; anyhow::bail!("takeover completed while the old effect was paused"); }
        waiting = tokio::time::timeout(Duration::from_secs(5), wait_for_lock(owner)) => { waiting??; }
    }
    rec.resume.cancel();
    Ok(tokio::time::timeout(Duration::from_secs(5), taking).await??)
}

async fn wait_for_lock(owner: &PgPool) -> anyhow::Result<()> {
    loop {
        let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename='projection_runtime' AND query LIKE '%rss_projection.takeover(%' AND cardinality(pg_blocking_pids(pid))>0)").fetch_one(owner).await?;
        if blocked {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
