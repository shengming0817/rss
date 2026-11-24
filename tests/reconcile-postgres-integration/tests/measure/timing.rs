//! Sample the DB clock on either side of the actual scan lock. The production
//! function and throughput lanes stay probe-free. Only the timing lanes call this copy.
use super::*;
use sqlx::{Acquire, PgConnection};

const MICROS: &str = "(extract(epoch FROM clock_timestamp())*1000000)::bigint";

pub(super) async fn install(owner: &PgPool) -> anyhow::Result<()> {
    let (_, definition) = MIGRATION_SQL
        .split_once("CREATE FUNCTION rss_reconcile.claim_due(")
        .ok_or_else(|| anyhow::anyhow!("missing claim function"))?;
    let (definition, _) = definition
        .split_once("END $$;")
        .ok_or_else(|| anyhow::anyhow!("missing claim body"))?;
    let mut probe = format!("CREATE FUNCTION claim_measure.claim_due({definition}END $$;");
    for (anchor, replacement) in [
        ("claims rss_reconcile.targets[],more boolean)", "claims rss_reconcile.targets[],more boolean,before_us bigint,locked_us bigint,leaving_us bigint)".into()),
        (" SELECT * INTO scan FROM", format!(" before_us:={MICROS};\n SELECT * INTO scan FROM")),
        (" IF NOT FOUND THEN RETURN NEXT; RETURN; END IF;", format!(" IF NOT FOUND THEN RETURN NEXT; RETURN; END IF;\n locked_us:={MICROS};")),
        (" RETURN NEXT;\nEND $$;", format!(" leaving_us:={MICROS};\n RETURN NEXT;\nEND $$;")),
    ] {
        anyhow::ensure!(probe.matches(anchor).count()==1, "ambiguous timing point: {anchor}");
        probe = probe.replace(anchor, &replacement);
    }
    let mut tx = owner.begin().await?;
    sqlx::raw_sql(
        "CREATE SCHEMA claim_measure AUTHORIZATION reconcile_owner; SET LOCAL ROLE reconcile_owner",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(probe))
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA claim_measure FROM PUBLIC; GRANT USAGE ON SCHEMA claim_measure TO reconcile_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA claim_measure TO reconcile_runtime")
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

type ClaimRow = (
    i64,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<i64>,
);
async fn sample_once(conn: &mut PgConnection, scope: &Scope) -> anyhow::Result<Option<(i64, i64)>> {
    let mut tx = conn.begin().await?;
    let tenant = "SELECT set_config('rss.tenant_id',$1,true)";
    sqlx::query(tenant).bind(TENANT).execute(&mut *tx).await?;
    let rows: Vec<ClaimRow> = sqlx::query_as("SELECT b.before_us,b.locked_us,b.leaving_us,c.entity,c.token::text,c.epoch FROM claim_measure.claim_due($1::uuid,$2,$3,$4,$5) b LEFT JOIN LATERAL unnest(b.claims) c ON true")
        .bind(TENANT).bind(scope.reconciler()).bind(BATCH as i32).bind(BUDGET as i32).bind(LEASE.as_millis() as i64).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    // The COMMIT ACK precedes this read on the same connection.
    let after: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&mut *conn)
            .await?;
    let (before, locked, leaving, ..) = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing scan row"))?;
    let bounds = match (locked, leaving) {
        (Some(start), Some(end)) => {
            anyhow::ensure!(
                before <= start && start <= end && *end <= after,
                "invalid scan clock bounds"
            );
            Some((end - start, after - before))
        }
        (None, None) => None, // SKIP LOCKED did not acquire the scan.
        _ => anyhow::bail!("incomplete lock sample"),
    };
    for (_, _, _, entity, token, epoch) in rows {
        if let Some(entity) = entity {
            let mut release = conn.begin().await?;
            sqlx::query(tenant)
                .bind(TENANT)
                .execute(&mut *release)
                .await?;
            sqlx::query("SELECT rss_reconcile.release($1::uuid,$2,$3,$4::uuid,$5)")
                .bind(TENANT)
                .bind(scope.reconciler())
                .bind(entity)
                .bind(token)
                .bind(epoch)
                .execute(&mut *release)
                .await?;
            release.commit().await?;
        }
    }
    Ok(bounds)
}

pub(super) async fn sample(pool: &PgPool, scope: &Scope, clock: &Clock) -> anyhow::Result<String> {
    let start = clock.now();
    let lanes = try_join_all((0..WORKERS).map(|_| async {
        let mut conn = pool.acquire().await?;
        let mut samples = Vec::new();
        while clock.now() - start < WINDOW {
            if let Some(bounds) = sample_once(&mut conn, scope).await? {
                samples.push(bounds);
            }
        }
        Ok::<_, anyhow::Error>(samples)
    }))
    .await?;
    let (mut lower, mut upper): (Vec<_>, Vec<_>) = lanes.into_iter().flatten().unzip();
    let n = lower.len();
    anyhow::ensure!(n > 0, "no acquired scan rows");
    lower.sort_unstable();
    upper.sort_unstable();
    let p50 = (n * 50).div_ceil(100) - 1;
    let p95 = (n * 95).div_ceil(100) - 1;
    Ok(format!(
        "lock_samples={n} p50_us={}..{} p95_us={}..{}",
        lower[p50], upper[p50], lower[p95], upper[p95]
    ))
}
