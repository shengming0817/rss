//! Real PostgreSQL frame loss. SQLx receives EOF, never a fabricated provider error.
//! ref: sqlx-postgres/src/transaction.rs@0.9.0; tokio-rustls/src/client.rs@0.26.4
use super::*;
#[path = "completion_transport.rs"]
mod completion_transport;
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
use std::sync::atomic::{AtomicU8, AtomicUsize};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

struct Proxy {
    port: u16,
    arm: Arc<AtomicU8>,
    lost: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Proxy {
    async fn new(fixture: &testkit::PgTlsFixture) -> anyhow::Result<Self> {
        // Only the private loopback test leg is plaintext; PostgreSQL still requires verified TLS.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let params = fixture.params().clone();
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(fixture.ca_pem().as_bytes()) {
            roots.add(cert?)?;
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let arm = Arc::new(AtomicU8::new(0));
        let lost = Arc::new(AtomicUsize::new(0));
        let next = arm.clone();
        let losses = lost.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming=listener.accept()=> {
                        let Ok((client,_))=incoming else { break };
                        let params=params.clone(); let connector=connector.clone();
                        let next=next.clone(); let losses=losses.clone();
                        connections.spawn(async move { relay(client,params,connector,next,losses).await });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty()=> {}
                }
            }
        });
        Ok(Self {
            port,
            arm,
            lost,
            task,
        })
    }
}
async fn frame<R: AsyncRead + Unpin>(input: &mut R) -> anyhow::Result<Vec<u8>> {
    let kind = input.read_u8().await?;
    let length = input.read_u32().await?;
    anyhow::ensure!(
        (4..=16 * 1024 * 1024).contains(&length),
        "invalid frame length"
    );
    let mut bytes = vec![0; length as usize + 1];
    bytes[0] = kind;
    bytes[1..5].copy_from_slice(&length.to_be_bytes());
    input.read_exact(&mut bytes[5..]).await?;
    Ok(bytes)
}
async fn relay(
    mut client: TcpStream,
    params: testkit::PgConnParams,
    connector: tokio_rustls::TlsConnector,
    arm: Arc<AtomicU8>,
    lost: Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    let mut tcp = TcpStream::connect((params.host.as_str(), params.port)).await?;
    tcp.write_all(&[0, 0, 0, 8, 4, 210, 22, 47]).await?;
    anyhow::ensure!(tcp.read_u8().await? == b'S', "upstream TLS required");
    let name = ServerName::try_from(params.host)?;
    let mut server = connector.connect(name, tcp).await?;
    let length = client.read_u32().await?;
    anyhow::ensure!(
        (8..=1024 * 1024).contains(&length),
        "invalid startup length"
    );
    let mut startup = vec![0; length as usize];
    startup[..4].copy_from_slice(&length.to_be_bytes());
    client.read_exact(&mut startup[4..]).await?;
    server.write_all(&startup).await?;
    server.flush().await?;
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = tokio::io::split(server);
    let active = AtomicU8::new(0);
    let forward = async {
        loop {
            let bytes = match frame(&mut cr).await {
                Ok(bytes) => bytes,
                Err(_) => return Ok::<(), anyhow::Error>(()),
            };
            let command = if bytes[0] == b'Q' {
                std::str::from_utf8(&bytes[5..])
                    .unwrap_or("")
                    .trim_end_matches('\0')
            } else {
                ""
            };
            let mode = arm.load(Ordering::SeqCst);
            if ((mode == 1 && command == "COMMIT") || (mode == 2 && command == "ROLLBACK"))
                && arm
                    .compare_exchange(mode, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                active.store(mode, Ordering::SeqCst);
            }
            sw.write_all(&bytes).await?;
            sw.flush().await?;
        }
    };
    let backward = async {
        loop {
            let bytes = frame(&mut sr).await?;
            if active.load(Ordering::SeqCst) != 0 {
                // Consume the real settlement response but never deliver CommandComplete/ReadyForQuery.
                if bytes[0] == b'Z' {
                    lost.fetch_add(1, Ordering::SeqCst);
                    return Ok::<(), anyhow::Error>(());
                }
            } else {
                cw.write_all(&bytes).await?;
                cw.flush().await?;
            }
        }
    };
    tokio::pin!(forward, backward);
    tokio::select! {
        result=&mut backward=>result,
        result=&mut forward=> {
            result?;
            // A client timeout must not silently settle the server transaction. Keep the upstream
            // open until its real ReadyForQuery so recovery has to wait for the outstanding lock.
            if active.load(Ordering::SeqCst)!=0 { backward.await } else { Ok(()) }
        }
    }
}
async fn backend(pool: &PgPool) -> anyhow::Result<i32> {
    Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(pool)
        .await?)
}
pub async fn verify(
    fixture: &testkit::PgTlsFixture,
    direct: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let proxy = Proxy::new(fixture).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(proxy.port)
                .database(&fixture.params().database)
                .username("saga_runtime")
                .password("fixture-only")
                .ssl_mode(PgSslMode::Disable),
        )
        .await?;
    let store = PgStore::new(pool.clone(), control).await?;
    registration_ack(&proxy, &store, &pool, direct, d, control).await?;
    completion(&proxy, &store, direct, owner, d, control).await?;
    pending(&proxy, &store, direct, owner, d, control).await?;
    aborted_commit(&proxy, &store, direct, owner, d, control).await?;
    assert_eq!(store.close(control).await, CloseOutcome::Drained);
    Ok(())
}
async fn pending(
    proxy: &Proxy,
    store: &PgStore,
    direct: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    // Test-only deferred trigger runs inside COMMIT, after SQLx has sent COMMIT to PostgreSQL.
    let mut blocker = owner.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(2293931)")
        .execute(&mut *blocker)
        .await?;
    sqlx::raw_sql("CREATE FUNCTION rss_saga.test_hold_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2293931); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER test_hold_commit AFTER INSERT ON rss_saga.instances DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rss_saga.test_hold_commit();").execute(owner).await?;
    let s = scope(TENANT)?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let short = Control::new(&clock, Duration::from_secs(10), &cancel);
    proxy.arm.store(1, Ordering::SeqCst);
    assert_kind(
        cancel_during_commit(proxy, store, s, d, &short, &cancel).await,
        ErrorKind::CommitUnknown,
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_saga.instances WHERE saga_id=$1")
        .bind(s.id())
        .fetch_one(owner)
        .await?;
    assert_eq!(
        count, 0,
        "ordinary MVCC read does not prove absence after settlement"
    );
    assert_eq!(
        proxy.lost.load(Ordering::SeqCst),
        3,
        "server has not settled yet"
    );
    let recovery = direct.register(s, d, control);
    tokio::pin!(recovery);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut recovery)
            .await
            .is_err(),
        "recovery must wait for outstanding transaction, even though an ordinary read sees no row"
    );
    blocker.commit().await?;
    recovery.await?;
    sqlx::raw_sql("DROP TRIGGER test_hold_commit ON rss_saga.instances; DROP FUNCTION rss_saga.test_hold_commit();").execute(owner).await?;
    verify_snapshot(direct, s, d, control).await?;
    Ok(())
}

async fn completion(
    proxy: &Proxy,
    store: &PgStore,
    direct: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let effects = Arc::new(Effects::default());
    let faulty = completion_transport::CompletionFault {
        store: store.clone(),
        armed: std::sync::atomic::AtomicBool::new(true),
        arm: proxy.arm.clone(),
        when: EventKind::ForwardApplied,
    };
    let executor = Executor::new(
        faulty,
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
    )
    .with_lease_policy(LeasePolicy::new(Duration::from_millis(300))?);
    executor.register(s, d, control).await?;
    assert_kind(executor.run(s, 30, control).await, ErrorKind::CommitUnknown);
    assert_eq!(proxy.lost.load(Ordering::SeqCst), 3);
    assert_kind(
        direct.claim(s, Duration::from_secs(5), control).await,
        ErrorKind::Fenced,
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    let recovered = Executor::new(
        direct.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
    );
    assert_eq!(
        recovered.run(s, 30, control).await?.status,
        Status::Succeeded
    );
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_saga.step_receipts WHERE saga_id=$1")
            .bind(s.id())
            .fetch_one(owner)
            .await?;
    assert_eq!(receipts, 3);
    assert_eq!(
        *effects
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned"))?,
        vec!["execute:one", "execute:two", "execute:three"]
    );
    Ok(())
}

fn assert_kind<T>(result: Result<T, Error>, kind: ErrorKind) {
    assert_eq!(result.err().map(|e| e.kind()), Some(kind));
}

async fn registration_ack(
    proxy: &Proxy,
    store: &PgStore,
    pool: &PgPool,
    direct: &PgStore,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let before = backend(pool).await?;
    proxy.arm.store(1, Ordering::SeqCst);
    assert_kind(
        store.register(s, d, control).await,
        ErrorKind::CommitUnknown,
    );
    assert_eq!(proxy.lost.load(Ordering::SeqCst), 1);
    assert_ne!(
        before,
        backend(pool).await?,
        "uncertain connection must not reenter pool"
    );
    // New transaction and instance lock prove the complete committed registration is present.
    direct.register(s, d, control).await?;
    verify_snapshot(direct, s, d, control).await?;
    rollback_ack(proxy, store, pool, s, d, control).await?;
    direct.register(s, d, control).await?;
    Ok(())
}
async fn rollback_ack(
    proxy: &Proxy,
    store: &PgStore,
    pool: &PgPool,
    s: Scope,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let different = Definition::new("different-owner", d.identity().clone(), d.steps().to_vec())?;
    let before = backend(pool).await?;
    proxy.arm.store(2, Ordering::SeqCst);
    assert_kind(
        store.register(s, &different, control).await,
        ErrorKind::RollbackUnknown,
    );
    assert_eq!(proxy.lost.load(Ordering::SeqCst), 2);
    assert_ne!(before, backend(pool).await?);
    Ok(())
}

async fn cancel_during_commit(
    proxy: &Proxy,
    store: &PgStore,
    s: Scope,
    d: &Definition,
    control: &Control<'_, Clock>,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let (result, ()) = tokio::join!(store.register(s, d, control), async {
        while proxy.arm.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
    });
    result
}

async fn verify_snapshot(
    direct: &PgStore,
    s: Scope,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let lease = direct.claim(s, Duration::from_secs(5), control).await?;
    assert_eq!(direct.snapshot(&lease, control).await?.definition(), d);
    direct.release(&lease, control).await?;
    Ok(())
}

async fn aborted_commit(
    proxy: &Proxy,
    store: &PgStore,
    direct: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE FUNCTION rss_saga.test_abort_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejection'; END $$; CREATE CONSTRAINT TRIGGER test_abort_commit AFTER INSERT ON rss_saga.instances DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rss_saga.test_abort_commit();").execute(owner).await?;
    let s = scope(TENANT)?;
    proxy.arm.store(1, Ordering::SeqCst);
    assert_kind(
        store.register(s, d, control).await,
        ErrorKind::CommitUnknown,
    );
    sqlx::raw_sql("DROP TRIGGER test_abort_commit ON rss_saga.instances; DROP FUNCTION rss_saga.test_abort_commit();").execute(owner).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_saga.instances WHERE saga_id=$1")
        .bind(s.id())
        .fetch_one(owner)
        .await?;
    assert_eq!(count, 0);
    // The fresh registration transaction serializes on unique identity and establishes absence.
    direct.register(s, d, control).await?;
    verify_snapshot(direct, s, d, control).await?;
    Ok(())
}
