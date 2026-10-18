use super::*;
#[tokio::test]
async fn history_latest_live_pages_and_budgets() -> anyhow::Result<()> {
    let f = Fixture::new("ts-queries").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let samples = vec![
        sample(&d, "z", 100, 7)?,
        sample(&d, "a", 100, 7)?,
        sample(&d, "late", 0, 1)?,
        sample(&d, "max", i64::MAX - 1, u64::MAX)?,
    ];
    confirmed(f.write(&batch("query", samples)?).await?)?;
    let q = Authorized::<Query>::verify(&authority(TENANT)?, query(&d, QueryMode::History, 1)?)?;
    let mut after = None;
    let mut ids = Vec::new();
    loop {
        let p = f.store.query(&q, after.as_ref(), deadline()?).await?;
        ids.extend(
            p.rows
                .iter()
                .map(|s| s.sample.input().id.as_str().to_owned()),
        );
        after = p.next;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(ids, ["late", "a", "z", "max"]);
    let qlatest =
        Authorized::<Query>::verify(&authority(TENANT)?, query(&d, QueryMode::Latest, 10)?)?;
    let p = f.store.query(&qlatest, None, deadline()?).await?;
    assert_eq!(p.rows.len(), 1);
    assert_eq!(p.rows[0].sample.input().id.as_str(), "max");
    let s = sample(&d, "max", i64::MAX - 1, u64::MAX)?;
    let exact = Query::new(
        Selection::Exact {
            stream: s.input().stream.clone(),
            series: s.input().series.clone(),
        },
        Interval::new(Timestamp::new(0)?, Timestamp::new(101)?)?,
        query(&d, QueryMode::Latest, 10)?.budget(),
        QueryMode::Latest,
    )?;
    let p = f
        .store
        .query(
            &Authorized::<Query>::verify(&authority(TENANT)?, exact)?,
            None,
            deadline()?,
        )
        .await?;
    assert_eq!(p.rows[0].sample.input().id.as_str(), "z");
    let first = f.store.query(&q, None, deadline()?).await?;
    let cursor = first.next.ok_or_else(|| anyhow::anyhow!("cursor"))?;
    let mut other = sample(&d, "other", 50, 1)?.input().clone();
    other.stream = Stream::new(d.spec().scope.clone(), id("zzz-source")?, id("generation")?);
    confirmed(f.write(&batch("other", vec![Sample::new(other)?])?).await?)?;
    let mut budget = query(&d, QueryMode::Latest, 10)?.budget();
    budget.max_series = NonZeroU32::MIN;
    let grouped = Query::new(
        query(&d, QueryMode::Latest, 10)?.selection().clone(),
        query(&d, QueryMode::Latest, 10)?.window(),
        budget,
        QueryMode::Latest,
    )?;
    let grouped = Authorized::<Query>::verify(&authority(TENANT)?, grouped)?;
    let first = f.store.query(&grouped, None, deadline()?).await?;
    assert_eq!(first.rows.len(), 1);
    // Update the already-returned group; its new latest must not reappear on page two.
    let mut update = sample(&d, "new-latest", i64::MAX - 1, u64::MAX)?
        .input()
        .clone();
    update.id = id("zz-new-latest")?;
    confirmed(
        f.write(&batch("update", vec![Sample::new(update)?])?)
            .await?,
    )?;
    let second = f
        .store
        .query(&grouped, first.next.as_ref(), deadline()?)
        .await?;
    assert_eq!(second.rows.len(), 1);
    assert_eq!(
        second.rows[0].sample.input().stream.source().as_str(),
        "zzz-source"
    );
    assert!(second.next.is_none());
    let fresh = PgStore::new(
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        f.pool.clone(),
        Timer,
        limits()?,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    assert_eq!(
        fresh.query(&q, Some(&cursor), deadline()?).await?.rows[0]
            .sample
            .input()
            .id
            .as_str(),
        "a"
    );
    assert_eq!(
        f.store
            .query(&qlatest, Some(&cursor), deadline()?)
            .await
            .err(),
        Some(Error::InvalidCursor)
    );
    let mut low = limits()?;
    low.max_bytes = NonZeroU32::MIN;
    let small = PgStore::new(
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        f.pool.clone(),
        Timer,
        low,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    assert_eq!(
        small.query(&q, None, deadline()?).await.err(),
        Some(Error::BudgetExceeded)
    );
    let too_many =
        Authorized::<Query>::verify(&authority(TENANT)?, query(&d, QueryMode::History, 101)?)?;
    assert_eq!(
        f.store.query(&too_many, None, deadline()?).await.err(),
        Some(Error::BudgetExceeded)
    );
    assert_eq!(
        f.store
            .query(&q, None, Deadline::from_timeout(&Timer, Duration::ZERO)?)
            .await
            .err(),
        Some(Error::Deadline)
    );
    Ok(())
}
#[tokio::test]
async fn original_receipt_survives_minimum_horizon() -> anyhow::Result<()> {
    let f = Fixture::new("ts-horizon").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let mut caps = limits()?;
    caps.replay_micros = NonZeroU64::MIN;
    let store = PgStore::new(
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        f.pool.clone(),
        Timer,
        caps,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    let b = batch("tiny-horizon", vec![sample(&d, "a", 1, 1)?])?;
    let auth = Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?;
    let first = confirmed(store.write(&auth, deadline()?).await?)?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.admin)
            .await?;
    assert!(now > first.replay_until().micros());
    let again = store.write(&auth, deadline()?).await?;
    assert!(matches!(again, Outcome::Replay(_)));
    assert_eq!(confirmed(again)?.replay_until(), first.replay_until());
    let missing = ReceiptQuery {
        batch_id: id("missing")?,
        ..receipt_query(&b)?
    };
    assert!(matches!(
        store
            .receipt(
                &Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, missing)?,
                deadline()?
            )
            .await?,
        Lookup::NotVisible
    ));
    let wrong = ReceiptQuery {
        digest: Digest::from_bytes([0; 32]),
        ..receipt_query(&b)?
    };
    assert_eq!(
        store
            .receipt(
                &Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, wrong)?,
                deadline()?
            )
            .await
            .err(),
        Some(Error::Conflict)
    );
    Ok(())
}

#[tokio::test]
async fn typed_values_keep_their_exact_persisted_identity() -> anyhow::Result<()> {
    let f = Fixture::new("ts-values").await?;
    let base = definition(TENANT)?;
    let cases = [
        (
            Metric::Gauge {
                number: NumberKind::I64,
            },
            Value::Number(Number::I64(i64::MIN)),
        ),
        (
            Metric::Gauge {
                number: NumberKind::F64,
            },
            Value::Number(Number::F64(FiniteF64::new(f64::from_bits(
                0x3fb999999999999b,
            ))?)),
        ),
        (Metric::Bool, Value::Bool(false)),
        (
            Metric::State {
                members: [id("ok")?, id("fault")?].into_iter().collect(),
            },
            Value::State(id("fault")?),
        ),
    ];
    for (index, (metric, value)) in cases.into_iter().enumerate() {
        let mut spec = base.spec().clone();
        spec.key = Id::new(format!("type-{index}"))?;
        spec.metric = metric;
        let d = Definition::new(spec)?;
        f.register(&d).await?;
        let mut input = sample(&base, &format!("value-{index}"), 50, 1)?
            .input()
            .clone();
        input.series = Series::new(
            d.clone(),
            id("device")?,
            id("resource")?,
            Default::default(),
        )?;
        input.reading = Reading::Valid(value);
        let sample = Sample::new(input)?;
        let b = batch(&format!("value-{index}"), vec![sample.clone()])?;
        let original = confirmed(f.write(&b).await?)?;
        confirmed(
            f.write(&batch(&format!("again-{index}"), vec![sample.clone()])?)
                .await?,
        )?;
        let q = Query::new(
            Selection::Exact {
                stream: sample.input().stream.clone(),
                series: sample.input().series.clone(),
            },
            query(&d, QueryMode::History, 1)?.window(),
            query(&d, QueryMode::History, 1)?.budget(),
            QueryMode::History,
        )?;
        let page = f
            .store
            .query(
                &Authorized::<Query>::verify(&authority(TENANT)?, q)?,
                None,
                deadline()?,
            )
            .await?;
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].sample, sample);
        assert_eq!(page.rows[0].received_at, original.received_at());
    }
    Ok(())
}
