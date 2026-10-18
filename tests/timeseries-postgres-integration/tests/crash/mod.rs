use super::*;
#[tokio::test]
async fn restart_after_real_process_interruption() -> anyhow::Result<()> {
    let f = Fixture::new("ts-crash").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let root = std::env::temp_dir().join(format!("rss-ts-crash-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let ca = root.join("ca.pem");
    std::fs::write(&ca, f.pg.ca_pem())?;
    for committed in [false, true] {
        let name = if committed { "after" } else { "before" };
        let marker = root.join(name);
        let p = f.pg.params();
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "crash::child", "--ignored", "--nocapture"])
            .env("TS_HOST", &p.host)
            .env("TS_PORT", p.port.to_string())
            .env("TS_DB", &p.database)
            .env("TS_CA", &ca)
            .env("TS_MARKER", &marker)
            .env("TS_PHASE", name)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let ready=tokio::time::timeout(Duration::from_secs(20),async {
            loop {
                if child.try_wait()?.is_some() {anyhow::bail!("child exited before boundary");}
                let staged:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE application_name='timeseries-crash' AND state='idle in transaction' AND query LIKE '%put_batch%')").fetch_one(&f.admin).await?;
                if (committed && marker.exists()) || (!committed && staged) {break;}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_,anyhow::Error>(())
        }).await;
        child.kill().await?;
        child.wait().await?;
        ready??;
        let b = batch(name, vec![sample(&d, name, 20, 1)?])?;
        let reopened = PgStore::new(
            f.pool.clone(),
            Timer,
            limits()?,
            CursorKey::new([17; 32]),
            deadline()?,
        )
        .await?;
        let state = reopened
            .receipt(
                &Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&b)?)?,
                deadline()?,
            )
            .await?;
        assert_eq!(matches!(state, Lookup::Found(_)), committed);
        let outcome = f.write(&b).await?;
        assert_eq!(matches!(outcome, Outcome::Replay(_)), committed);
        confirmed(outcome)?;
    }
    assert_eq!(f.count().await?, 2);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
#[ignore = "subprocess stopped at a real PostgreSQL commit boundary"]
async fn child() -> anyhow::Result<()> {
    let phase = std::env::var("TS_PHASE")?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .host(&std::env::var("TS_HOST")?)
                .port(std::env::var("TS_PORT")?.parse()?)
                .database(&std::env::var("TS_DB")?)
                .username("ts_runtime")
                .password("fixture-only")
                .application_name("timeseries-crash")
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(std::fs::read(std::env::var("TS_CA")?)?),
        )
        .await?;
    let store = PgStore::new(
        pool,
        Timer,
        limits()?,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    let b = batch(&phase, vec![sample(&definition(TENANT)?, &phase, 20, 1)?])?;
    store.inject_next_fault(if phase == "before" {
        Fault::CommitPending
    } else {
        Fault::CommitAckLost
    });
    let result = store
        .write(
            &Authorized::<Batch>::verify(&authority(TENANT)?, b)?,
            Deadline::from_timeout(&Timer, Duration::from_secs(60))?,
        )
        .await?;
    anyhow::ensure!(
        matches!(result, Outcome::Unknown),
        "expected hidden acknowledgment"
    );
    std::fs::write(std::env::var("TS_MARKER")?, b"committed")?;
    std::future::pending::<()>().await;
    Ok(())
}
