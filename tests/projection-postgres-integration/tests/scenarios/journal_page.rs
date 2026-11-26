use super::*;

const PAGE_SQL: &str = include_str!("../../../../crates/projection-postgres/src/journal_page.sql");

pub(crate) async fn verify(
    store: &PgStore, runtime: &PgPool, owner: &PgPool, c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = scope("page-bytes", TENANT)?;
    let max = Event::MAX_PAYLOAD_BYTES;
    let sizes = [max - 1, 0, 1, max, 1];
    for (i, size) in sizes.into_iter().enumerate() {
        append(store, &scope, &format!("e{i}"), &vec![i as u8; size as usize], c).await?;
    }
    for (after, rows, bytes, expected, blocked) in [
        (None, 5, max, vec![0, 1, 2], false),
        (None, 2, max, vec![0, 1], false),
        (None, 5, max - 1, vec![0, 1], false),
        (None, 5, max - 2, vec![0], true),
        (Some(2), 5, max - 1, vec![3], true),
        (Some(2), 5, max, vec![3], false),
        (Some(3), 5, max, vec![4], false),
        (Some(4), 5, max, vec![], false),
    ] {
        let budget = PageBudget::new(rows, bytes)?;
        // Measure the production statement's returned bytea column before adapter decoding.
        let mut tx = runtime.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(TENANT).execute(&mut *tx).await?;
        let records: Vec<(i64, i32, Option<String>, Option<Vec<u8>>)> = sqlx::query_as(PAGE_SQL)
            .bind(TENANT).bind(scope.source().source()).bind(after.unwrap_or(-1_i64))
            .bind(i64::from(rows)).bind(i64::from(bytes)).fetch_all(&mut *tx).await?;
        tx.rollback().await?;
        assert_eq!(records.len(), expected.len());
        let mut returned = 0;
        let mut events = Vec::new();
        for ((position, size, id, body), i) in records.into_iter().zip(expected) {
            assert_eq!((position, size), (i as i64, sizes[i] as i32));
            if blocked {
                assert_eq!((id, body), (None, None));
            } else {
                let id = id.ok_or_else(|| anyhow::anyhow!("missing event id"))?;
                let body = body.ok_or_else(|| anyhow::anyhow!("missing payload"))?;
                assert_eq!(id, format!("e{i}"));
                assert_eq!(body.len(), sizes[i] as usize);
                assert!(body.iter().all(|&b| b == i as u8));
                returned += body.len();
                events.push(event(&scope, position as u64, &id, &body)?);
            }
        }
        assert!(returned <= bytes as usize);
        let expected = if blocked {
            let i = after.map_or(0, |p| p as usize + 1);
            ReadPage::Blocked {position: Position::new(i as u64)?, required_bytes: sizes[i]}
        } else { ReadPage::Events(events) };
        assert_eq!(store.read(scope.source(), after.map(|p| Position::new(p as u64)).transpose()?, budget, c).await?, expected);
    }
    for batched in [false, true] {
        let gen = ProjectionScope::new(scope.source().clone(), "page", if batched { "batch" } else { "single" })?;
        let exec = session(store, &gen, c).await?;
        for bytes in [max - 1, max] {
            let limit = RunLimit::new(PageBudget::new(5, bytes)?, 10)?;
            let report = if batched { run_batched(store, &exec, c, limit).await } else { run(store, &exec, c, limit).await };
            let (settled, stop) = if bytes < max {
                (3, Stop::PayloadBudget {position: Position::new(3)?, required_bytes: max})
            } else { (5, Stop::CaughtUp) };
            assert_eq!(report.stop, stop);
            assert_eq!(report.position, Some(Position::new(settled - 1)?));
            assert_eq!(exec.checkpoint(c).await?.position, report.position);
            assert_eq!(count(owner, &gen).await?, settled as i64);
            for i in 0..sizes.len() {
                let query = ReceiptQuery::new(gen.clone(), DEFINITION, format!("e{i}"))?;
                assert_eq!(store.receipt_status(&query,c).await?.is_settled(), (i as u64) < settled);
            }
        }
    }
    Ok(())
}
