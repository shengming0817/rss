use super::*;

const PAGE_SQL: &str = include_str!("../../../../crates/projection-postgres/src/journal_page.sql");

pub(crate) async fn verify(
    store: &PgStore,
    runtime: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    // Both joins must bind tenant and source even when other journals reuse position zero.
    let neighbor = scope("page-neighbor", TENANT)?;
    let other_tenant = scope("page-bytes", OTHER)?;
    append(store, &neighbor, "neighbor", b"other source", c).await?;
    append(store, &other_tenant, "other-tenant", b"other tenant", c).await?;
    let scope = scope("page-bytes", TENANT)?;
    let max = Event::MAX_PAYLOAD_BYTES;
    let mut events = Vec::new();
    for (i, size) in [max - 1, 0, 1, max, 1].into_iter().enumerate() {
        let id = format!("e{i}");
        let body = vec![i as u8; size as usize];
        let pos = append(store, &scope, &id, &body, c).await?;
        events.push(Event::new(scope.source().clone(), pos, id, body)?);
    }
    pages(store, runtime, scope.source(), &events, c).await?;
    for batched in [false, true] {
        settlement(store, owner, &scope, &events, c, batched).await?;
    }
    Ok(())
}

// The production statement returns these columns before adapter decoding.
type JournalRow = (i64, i32, Option<String>, Option<Vec<u8>>);

async fn raw_rows(
    runtime: &PgPool,
    scope: &SourceScope,
    after: Option<Position>,
    budget: PageBudget,
) -> anyhow::Result<Vec<JournalRow>> {
    let tenant = scope.tenant().to_string();
    let mut tx = runtime.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(&tenant)
        .execute(&mut *tx)
        .await?;
    let rows = sqlx::query_as(PAGE_SQL)
        .bind(&tenant)
        .bind(scope.source())
        .bind(after.map_or(-1, |p| p.get() as i64))
        .bind(i64::from(budget.rows()))
        .bind(i64::from(budget.payload_bytes()))
        .fetch_all(&mut *tx)
        .await?;
    tx.rollback().await?;
    Ok(rows)
}

fn expected_rows(page: &ReadPage<Event>) -> Vec<JournalRow> {
    match page {
        ReadPage::Events(events) => events
            .iter()
            .map(|e| {
                (
                    e.position().get() as i64,
                    e.payload().len() as i32,
                    Some(e.id().to_owned()),
                    Some(e.payload().to_vec()),
                )
            })
            .collect(),
        ReadPage::Blocked {
            position,
            required_bytes,
        } => vec![(position.get() as i64, *required_bytes as i32, None, None)],
    }
}

async fn pages(
    store: &PgStore,
    runtime: &PgPool,
    scope: &SourceScope,
    events: &[Event],
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let max = Event::MAX_PAYLOAD_BYTES;
    let prefix = |range: std::ops::Range<usize>| ReadPage::Events(events[range].to_vec());
    let blocked = |i: usize| ReadPage::Blocked {
        position: events[i].position(),
        required_bytes: events[i].payload().len() as u32,
    };
    for (after, rows, bytes, expected) in [
        (None, 5, max, prefix(0..3)),
        (None, 2, max, prefix(0..2)),
        (None, 5, max - 1, prefix(0..2)),
        (None, 5, max - 2, blocked(0)),
        (Some(2), 5, max - 1, blocked(3)),
        (Some(2), 5, max, prefix(3..4)),
        (Some(3), 5, max, prefix(4..5)),
        (Some(4), 5, max, prefix(5..5)),
    ] {
        let budget = PageBudget::new(rows, bytes)?;
        let cursor = after.map(Position::new).transpose()?;
        let records = raw_rows(runtime, scope, cursor, budget).await?;
        assert!(
            records == expected_rows(&expected),
            "SQL page at {cursor:?} with {budget:?}"
        );
        assert_eq!(store.read(scope, cursor, budget, c).await?, expected);
    }
    Ok(())
}

async fn settlement(
    store: &PgStore,
    owner: &PgPool,
    scope: &ProjectionScope,
    events: &[Event],
    c: &Control<'_, Clock>,
    batched: bool,
) -> anyhow::Result<()> {
    let generation = ProjectionScope::new(
        scope.source().clone(),
        "page",
        if batched { "batch" } else { "single" },
    )?;
    let exec = session(store, &generation, c).await?;
    let max = Event::MAX_PAYLOAD_BYTES;
    let blocked = Stop::PayloadBudget {
        position: events[3].position(),
        required_bytes: max,
    };
    for (bytes, settled, stop) in [(max - 1, 3, blocked), (max, events.len(), Stop::CaughtUp)] {
        let limit = RunLimit::new(PageBudget::new(5, bytes)?, 10)?;
        let report = if batched {
            run_batched(store, &exec, c, limit).await
        } else {
            run(store, &exec, c, limit).await
        };
        assert_eq!(report.stop, stop);
        assert_eq!(report.position, Some(events[settled - 1].position()));
        assert_eq!(exec.checkpoint(c).await?.position, report.position);
        assert_eq!(count(owner, &generation).await?, settled as i64);
        assert_receipts(store, &generation, events, settled, c).await?;
    }
    Ok(())
}

async fn assert_receipts(
    store: &PgStore,
    generation: &ProjectionScope,
    events: &[Event],
    settled: usize,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for (i, event) in events.iter().enumerate() {
        let query = ReceiptQuery::new(generation.clone(), DEFINITION, event.id())?;
        assert_eq!(
            store.receipt_status(&query, c).await?.is_settled(),
            i < settled
        );
    }
    Ok(())
}
