//! Multi-chunk order, lock handoff and exhaustion on the original transaction.
use super::*;
use sqlx::{Postgres, Transaction};

pub(super) async fn run<T: Timer>(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    ordered_errors(pool, owner, control).await?;
    unpersisted_prefix(pool, owner, control).await?;
    exhaustion(pool, owner, control).await?;
    competing(pool, owner, control).await
}
async fn scoped(pool: &PgPool) -> anyhow::Result<Transaction<'static, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn ordered_errors<T: Timer>(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    let auth = auth()?;
    let make = |id, v| request("order-errors", id, &[v]);
    let mut tx = scoped(pool).await?;
    append_batch_in_transaction(
        &mut tx,
        &auth,
        &[make("a", 1)?, make("b", 2)?, make("tail", 3)?],
        control,
    )
    .await?;
    tx.commit().await?;
    sqlx::query("UPDATE rss_ledger.entries SET payload='corrupt'::bytea WHERE chain_id='order-errors' AND record_id='b'").execute(owner).await?;
    for (first, second, conflict) in [
        (make("a", 9)?, make("b", 2)?, true),
        (make("b", 2)?, make("a", 9)?, false),
    ] {
        let mut tx = scoped(pool).await?;
        let error = append_batch_in_transaction(&mut tx, &auth, &[first, second], control).await;
        let expected = if conflict {
            matches!(error, Err(Error::Conflict))
        } else {
            matches!(
                error,
                Err(Error::Protocol(rss_ledger::Error::Authentication))
            )
        };
        assert!(expected);
        tx.rollback().await?;
    }
    Ok(())
}

async fn exhaustion<T: Timer>(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    let auth = auth()?;
    let before = i64::MAX - 32;
    // Independent HMAC-SHA256 over the V1 fixture's empty "last" entry at MAX-32.
    let tag = "22011f536215b6014769d2c56dd45cf4c28adbda2f0c87f6b6bd9bdab0d36462";
    sqlx::query("INSERT INTO rss_ledger.heads VALUES($1::uuid,'near-limit','fixture-key',1,$2,decode($3,'hex'))").bind(TENANT).bind(before).bind(tag).execute(owner).await?;
    sqlx::query("INSERT INTO rss_ledger.entries VALUES($1::uuid,'near-limit','last',$2,decode(repeat('00',32),'hex'),decode($3,'hex'),''::bytea,1,'fixture-key')").bind(TENANT).bind(before).bind(tag).execute(owner).await?;
    let rows = (0..33)
        .map(|i| request("near-limit", &format!("r{i}"), &[i]))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut tx = scoped(pool).await?;
    let failed = append_batch_in_transaction(&mut tx, &auth, &rows, control).await;
    assert!(matches!(
        failed,
        Err(Error::Protocol(rss_ledger::Error::SequenceExhausted))
    ));
    let head = "SELECT seq FROM rss_ledger.heads WHERE chain_id='near-limit'";
    assert_eq!(
        sqlx::query_scalar::<_, i64>(head)
            .fetch_one(&mut *tx)
            .await?,
        i64::MAX
    );
    tx.rollback().await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(head).fetch_one(owner).await?,
        before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM rss_ledger.entries WHERE chain_id='near-limit'"
        )
        .fetch_one(owner)
        .await?,
        1
    );
    use_final_sequence(pool, control, &rows).await
}
async fn use_final_sequence<T: Timer>(
    pool: &PgPool,
    control: &Control<'_, T>,
    rows: &[AppendRequest],
) -> anyhow::Result<()> {
    let auth = auth()?;
    let mut tx = scoped(pool).await?;
    let last = append_batch_in_transaction(&mut tx, &auth, &rows[..32], control).await?;
    assert_eq!(last[31], (Sequence::new(i64::MAX as u64), true));
    tx.commit().await?;
    let mut tx = scoped(pool).await?;
    assert_eq!(
        append_batch_in_transaction(&mut tx, &auth, &rows[31..32], control).await?,
        [(Sequence::new(i64::MAX as u64), false)]
    );
    tx.commit().await?;
    Ok(())
}

async fn competing<T: Timer>(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    let auth = auth()?;
    let mut first = scoped(pool).await?;
    let mut second = scoped(pool).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *first)
        .await?;
    let rows = (0..33)
        .map(|i| request("locked-batch", &format!("r{i}"), &[i]))
        .collect::<anyhow::Result<Vec<_>>>()?;
    append_batch_in_transaction(&mut first, &auth, &rows, control).await?;
    let inputs = [
        rows[32].clone(),
        request("locked-batch", "next", b"new")?,
        rows[0].clone(),
    ];
    let release = async {
        tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(owner).await?;
                if blocked {return Ok::<(),sqlx::Error>(());}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        first.commit().await?;
        Ok::<(), anyhow::Error>(())
    };
    let (added, released) = tokio::join!(
        append_batch_in_transaction(&mut second, &auth, &inputs, control),
        release
    );
    released?;
    assert_eq!(
        added?,
        [
            (Sequence::new(32), false),
            (Sequence::new(33), true),
            (Sequence::new(0), false)
        ]
    );
    let window = read_window_in_transaction(
        &mut second,
        &auth,
        rows[0].ledger(),
        Sequence::new(0),
        ReadLimit::new(34, 65536)?,
        control,
    )
    .await?;
    assert_eq!(window.verified().entries().len(), 34);
    second.commit().await?;
    Ok(())
}

async fn unpersisted_prefix<T: Timer>(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    let auth = auth()?;
    let chain = "unpersisted-prefix";
    let orphan = request(chain, "orphan", b"real")?;
    let mut tx = scoped(pool).await?;
    append_batch_in_transaction(
        &mut tx,
        &auth,
        &[request(chain, "anchor", b"anchor")?, orphan.clone()],
        control,
    )
    .await?;
    tx.commit().await?;
    sqlx::query("UPDATE rss_ledger.heads h SET seq=e.seq,tag=e.tag FROM rss_ledger.entries e WHERE h.tenant_id=e.tenant_id AND h.chain_id=e.chain_id AND h.chain_id=$1 AND e.seq=0")
        .bind(chain).execute(owner).await?;
    for include_orphan in [true, false] {
        let mut rows = (0..32)
            .map(|i| request(chain, &format!("new{i}"), &[i]))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if include_orphan {
            rows.push(orphan.clone());
        }
        rows.push(request(chain, "new0", b"changed")?);
        let mut tx = scoped(pool).await?;
        let failure = append_batch_in_transaction(&mut tx, &auth, &rows, control).await;
        assert!(matches!(failure, Err(Error::StorageContract)));
        let coords:(i64,i64)=sqlx::query_as("SELECT h.seq,(SELECT count(*) FROM rss_ledger.entries e WHERE e.tenant_id=h.tenant_id AND e.chain_id=h.chain_id) FROM rss_ledger.heads h WHERE h.chain_id=$1")
            .bind(chain).fetch_one(&mut *tx).await?;
        assert_eq!(coords, (0, 2));
        tx.rollback().await?;
    }
    Ok(())
}
