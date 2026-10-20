//! Capture/replay real production INSERT requests; discard real server responses.
//! Both proxy legs verify TLS. No synthetic database success/error is injected.
use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, body::Incoming};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use tokio::{net::TcpListener, sync::Mutex};
type Http = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;
#[derive(Clone)]
struct Captured {
    uri: hyper::Uri,
    headers: hyper::HeaderMap,
    body: Bytes,
}
struct State {
    mode: AtomicU8,
    dropped: AtomicUsize,
    saved: Mutex<Option<Captured>>,
    upstream: String,
    http: Http,
}
pub(super) struct Proxy {
    pub endpoint: String,
    pub ca: String,
    state: Arc<State>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Proxy {
    pub async fn new(ch: &testkit::ClickHouseFixture) -> anyhow::Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let ca = cert.cert.pem();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            )?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ch.ca_pem().as_bytes()) {
            roots.add(cert?)?;
        }
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .build();
        let http =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);
        let state = Arc::new(State {
            mode: AtomicU8::new(0),
            dropped: AtomicUsize::new(0),
            saved: Mutex::new(None),
            upstream: ch.endpoint().into(),
            http,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("https://localhost:{}", listener.local_addr()?.port());
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>{let Ok((tcp,_))=accepted else {break;};let acceptor=acceptor.clone();let state=shared.clone();connections.spawn(async move {
                        let tls=acceptor.accept(tcp).await?;
                        hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls),hyper::service::service_fn(move |request|serve(state.clone(),request))).await?;
                        Ok::<_,anyhow::Error>(())
                    });}
                    Some(_)=connections.join_next(),if !connections.is_empty()=>{}
                }
            }
        });
        Ok(Self {
            endpoint,
            ca,
            state,
            task,
        })
    }
    pub fn arm(&self, mode: u8) {
        self.state.mode.store(mode, Ordering::SeqCst);
    }
    pub fn dropped(&self) -> usize {
        self.state.dropped.load(Ordering::SeqCst)
    }
    pub async fn replay(&self) -> anyhow::Result<()> {
        let saved = self
            .state
            .saved
            .lock()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("real request not captured"))?;
        let response = forward(&self.state, saved).await?;
        anyhow::ensure!(
            response.status().is_success(),
            "late request transport did not complete"
        );
        Ok(())
    }
    pub async fn store(&self, pool: PgPool) -> anyhow::Result<ChStore<Timer>> {
        let c = |user: &str| Credentials::new(user.into(), "fixture-only".into());
        Ok(ChStore::new(
            TenantId::parse(TENANT)?,
            pool,
            Connections::new(
                &self.endpoint,
                self.ca.as_bytes(),
                c("ch_reader")?,
                c("ch_writer")?,
                c("ch_maint")?,
            )?,
            Timer,
            limits()?,
            CursorKey::new([42; 32]),
            deadline()?,
        )
        .await?)
    }
}
async fn forward(state: &State, request: Captured) -> anyhow::Result<Response<Full<Bytes>>> {
    let target = format!(
        "{}{}",
        state.upstream,
        request.uri.path_and_query().map_or("/", |p| p.as_str())
    );
    let mut outgoing = Request::post(target).body(Full::new(request.body))?;
    *outgoing.headers_mut() = request.headers;
    outgoing.headers_mut().remove(hyper::header::HOST);
    outgoing.headers_mut().remove(hyper::header::CONTENT_LENGTH);
    outgoing
        .headers_mut()
        .remove(hyper::header::TRANSFER_ENCODING);
    let response = state.http.request(outgoing).await?;
    let (parts, body) = response.into_parts();
    let data = Limited::new(body, 8 * 1024 * 1024)
        .collect()
        .await
        .map_err(|_| anyhow::anyhow!("bounded upstream response"))?
        .to_bytes();
    let mut response = Response::from_parts(parts, Full::new(data));
    response
        .headers_mut()
        .remove(hyper::header::TRANSFER_ENCODING);
    response.headers_mut().remove(hyper::header::CONTENT_LENGTH);
    Ok(response)
}
async fn serve(
    state: Arc<State>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let (parts, body) = request.into_parts();
    let data = Limited::new(body, 8 * 1024 * 1024)
        .collect()
        .await
        .map_err(|_| std::io::Error::other("bounded request"))?
        .to_bytes();
    let sql = url::form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes())
        .find(|(key, _)| key == "query")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    let is_insert = ["raw", "summaries"].iter().any(|table| {
        let prefix = format!("INSERT INTO rss_ts_ch.{table}");
        sql.starts_with(&prefix) || data.starts_with(prefix.as_bytes())
    });
    let mode = if is_insert {
        state.mode.swap(0, Ordering::SeqCst)
    } else {
        0
    };
    let captured = Captured {
        uri: parts.uri,
        headers: parts.headers,
        body: data,
    };
    if mode != 0 {
        *state.saved.lock().await = Some(captured.clone());
    }
    if mode == 2 {
        state.dropped.fetch_add(1, Ordering::SeqCst);
        return Err(std::io::Error::other("withheld before registration"));
    }
    let response = forward(&state, captured)
        .await
        .map_err(|_| std::io::Error::other("upstream transport"))?;
    if mode == 1 && response.status().is_success() {
        state.dropped.fetch_add(1, Ordering::SeqCst);
        return Err(std::io::Error::other("discarded real response"));
    }
    Ok(response)
}
#[tokio::test]
async fn lost_real_response_and_pre_registration_late_request() -> anyhow::Result<()> {
    let f = Fixture::new("ch-wire").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let proxy = Proxy::new(&f.ch).await?;
    let store = proxy.store(f.pool.clone()).await?;
    for mode in [1, 2] {
        let b = batch(
            &format!("wire.{mode}"),
            vec![sample(
                &d,
                &format!("wire.{mode}"),
                i64::from(mode) * 10,
                7,
            )?],
        )?;
        proxy.arm(mode);
        assert!(matches!(
            store
                .write(
                    &Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?,
                    deadline()?
                )
                .await?,
            Outcome::Unknown
        ));
        assert_eq!(proxy.dropped(), usize::from(mode));
        confirmed(f.write(&b).await?)?;
    }
    let selection = query(&d, QueryMode::History, 10)?.selection().clone();
    f.maintain(
        "cutoff",
        MaintenanceAction::AdvanceCutoff {
            selection: selection.clone(),
            before: Timestamp::new(100)?,
        },
    )
    .await?;
    f.maintain(
        "prune",
        MaintenanceAction::Prune {
            selection,
            raw_before: Timestamp::new(100)?,
            summaries_before: Timestamp::new(0)?,
        },
    )
    .await?;
    assert_eq!(
        f.ch.sql("SELECT count() FROM rss_ts_ch.raw").await?.trim(),
        "0"
    );
    proxy.replay().await?;
    assert_eq!(
        f.ch.sql("SELECT count() FROM rss_ts_ch.raw").await?.trim(),
        "0"
    );
    Ok(())
}

#[tokio::test]
async fn revoke_drains_a_real_query_with_an_old_guard_snapshot() -> anyhow::Result<()> {
    let f = Fixture::new("ch-drain").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let replacement = replacement_writer(&f).await?;
    // Fixture-only deterministic pause inside the real PostgreSQLSource statement.
    // Its MVCC snapshot predates revocation, so guard rereading alone cannot save it.
    sqlx::raw_sql("CREATE FUNCTION rss_ts_ch.test_guard_wait() RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$ BEGIN PERFORM pg_advisory_xact_lock(2813); RETURN true; END $$; CREATE OR REPLACE VIEW rss_ts_ch.active_attempts WITH (security_barrier=true) AS SELECT a.tenant_id::text AS tenant,a.namespace,a.id::text AS attempt,a.query_id::text AS query_id,a.target,a.digest,a.revision,i.id::text AS installation FROM rss_ts_ch.attempts a CROSS JOIN rss_ts_ch.installation i WHERE a.allowed AND NOT pg_is_in_recovery() AND (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AND rss_ts_ch.test_guard_wait(); ALTER VIEW rss_ts_ch.active_attempts OWNER TO ch_owner;").execute(&f.admin).await?;
    let mut blocker = f.admin.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock(2813)")
        .execute(&mut *blocker)
        .await?;
    let b = batch("blocked", vec![sample(&d, "blocked", 10, 3)?])?;
    let writer = f.write(&b);
    let recover = async {
        tokio::time::timeout(Duration::from_secs(10),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND objid=2813 AND NOT granted)").fetch_one(&f.admin).await?;
                if waiting {break;}tokio::time::sleep(Duration::from_millis(20)).await;
            }Ok::<_,anyhow::Error>(())
        }).await??;
        assert_ne!(
            f.ch.sql(
                "SELECT count() FROM system.processes WHERE query LIKE 'INSERT INTO rss_ts_ch.raw%'"
            )
            .await?
            .trim(),
            "0"
        );
        let auth = authority(TENANT)?;
        let recovery = replacement.recover(
            &d.spec().scope,
            &auth,
            Deadline::from_timeout(&Timer, Duration::from_secs(30))?,
        );
        let release = async {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if f.ch
                        .sql("SELECT count() FROM system.processes WHERE query LIKE 'KILL QUERY%'")
                        .await?
                        .trim()
                        != "0"
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await??;
            sqlx::query("SELECT pg_advisory_unlock(2813)")
                .execute(&mut *blocker)
                .await?;
            Ok::<_, anyhow::Error>(())
        };
        let (recovered, released) = tokio::join!(recovery, release);
        released?;
        anyhow::ensure!(
            confirmed(recovered?)?.is_some(),
            "production recovery after drain"
        );
        Ok::<_, anyhow::Error>(())
    };
    let (written, recovered) = tokio::join!(writer, recover);
    recovered?;
    assert!(matches!(written?, Outcome::Unknown));
    assert_eq!(f.read(&d).await?.rows.len(), 1);
    assert_eq!(
        f.ch.sql(
            "SELECT count() FROM system.processes WHERE query LIKE 'INSERT INTO rss_ts_ch.raw%'"
        )
        .await?
        .trim(),
        "0"
    );
    Ok(())
}

async fn replacement_writer(f: &Fixture) -> anyhow::Result<ChStore<Timer>> {
    f.ch.sql("CREATE USER ch_writer_next IDENTIFIED WITH sha256_password BY 'fixture-only'; GRANT SELECT ON rss_ts_ch.installation TO ch_writer_next; GRANT SELECT ON rss_ts_ch.active_attempts TO ch_writer_next; GRANT SELECT ON rss_ts_ch.guard_identity TO ch_writer_next; GRANT INSERT ON rss_ts_ch.raw TO ch_writer_next; GRANT INSERT ON rss_ts_ch.summaries TO ch_writer_next; GRANT CREATE TEMPORARY TABLE ON *.* TO ch_writer_next;").await?;
    Fixture::connect_options(
        &f.ch,
        f.pool.clone(),
        TENANT,
        "ch_reader",
        "ch_writer_next",
        limits()?,
    )
    .await
}
async fn wait_sink(f: &Fixture) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND objid=2814 AND NOT granted)").fetch_one(&f.admin).await?;
            if waiting { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await?
}

#[tokio::test]
async fn revoked_inserts_in_dependent_sink_do_not_resurrect_after_cleanup() -> anyhow::Result<()> {
    for target in ["raw", "summaries"] {
        let mut f = Fixture::new(&format!("ch-sink-{target}")).await?;
        let d = definition(TENANT)?;
        f.register(&d).await?;
        let proxy = Proxy::new(&f.ch).await?;
        let writer = proxy.store(f.pool.clone()).await?;
        f.store = replacement_writer(&f).await?;
        let b = batch("sink", vec![sample(&d, "sink", 10, 3)?])?;
        if target == "summaries" {
            confirmed(f.write(&b).await?)?;
        }
        // A dependent materialized-view sink receives a real INSERT block, after
        // the production guard join yielded rows. Its PostgreSQL source is the
        // deterministic gate, not a timing guess based on system.processes.
        // ref: ClickHouse InsertDependenciesBuilder.cpp@v25.8.12.129-lts
        sqlx::raw_sql("CREATE FUNCTION rss_ts_ch.test_sink_wait() RETURNS integer LANGUAGE plpgsql VOLATILE AS $$ BEGIN PERFORM pg_advisory_xact_lock(2814); RETURN 1; END $$; CREATE VIEW rss_ts_ch.test_sink_gate AS SELECT rss_ts_ch.test_sink_wait() AS ready; GRANT SELECT ON rss_ts_ch.test_sink_gate TO ch_guard;").execute(&f.admin).await?;
        f.ch.sql("CREATE TABLE default.test_sink_gate (ready Int32) ENGINE=PostgreSQL(rss_ts_ch_guard, table='test_sink_gate',schema='rss_ts_ch')").await?;
        f.ch.sql(&format!("CREATE MATERIALIZED VIEW default.test_sink DEFINER=default SQL SECURITY DEFINER ENGINE=Null AS SELECT r.revision FROM rss_ts_ch.{target} AS r CROSS JOIN default.test_sink_gate AS g WHERE g.ready=1")).await?;
        let mut blocker = f.admin.acquire().await?;
        sqlx::query("SELECT pg_advisory_lock(2814)")
            .execute(&mut *blocker)
            .await?;
        let spec = SummarySpec::new(
            b.stream().clone(),
            b.samples()[0].input().series.clone(),
            NonZeroU64::new(100).ok_or(Error::InvalidInput)?,
            CoveragePolicy::ObservedOnly,
            None,
        )?;
        let request = Authorized::<MaintenanceRequest>::verify(
            &authority(TENANT)?,
            MaintenanceRequest::new(
                id("sink-sum")?,
                MaintenanceAction::Recompute {
                    spec,
                    window: Interval::new(Timestamp::new(0)?, Timestamp::new(100)?)?,
                },
                MaintenanceBudget {
                    rows: NonZeroU32::new(2).ok_or(Error::InvalidInput)?,
                    buckets: NonZeroU32::new(1).ok_or(Error::InvalidInput)?,
                },
            )?,
        )?;
        let write = Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?;
        proxy.arm(3);
        {
            let insert = async {
                if target == "raw" {
                    writer.write(&write, deadline()?).await?;
                } else {
                    let mut next = None;
                    for _ in 0..10 {
                        match confirmed(writer.step(&request, next.as_ref(), deadline()?).await?)? {
                            MaintenanceProgress::More { next: n, .. } => next = Some(n),
                            _ => break,
                        }
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            tokio::select! {
                result = insert => { result?; anyhow::bail!("insert completed before dependent sink gate"); }
                result = wait_sink(&f) => result?,
            }
            // Dropping the client operation releases PG locks. The proxy still
            // awaits the real server response; the old writer remains in the sink.
        }
        let release = async {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if f.ch
                        .sql("SELECT count() FROM system.processes WHERE query LIKE 'KILL QUERY%'")
                        .await?
                        .trim()
                        != "0"
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await??;
            sqlx::query("SELECT pg_advisory_unlock(2814)")
                .execute(&mut *blocker)
                .await?;
            Ok::<_, anyhow::Error>(())
        };
        let cleanup = async {
            if target == "raw" {
                confirmed(
                    f.store
                        .recover(&d.spec().scope, &authority(TENANT)?, deadline()?)
                        .await?,
                )?;
                f.maintain(
                    "sink-cut",
                    MaintenanceAction::AdvanceCutoff {
                        selection: query(&d, QueryMode::History, 10)?.selection().clone(),
                        before: Timestamp::new(100)?,
                    },
                )
                .await?;
            }
            let progress = f
                .maintain(
                    "sink-prune",
                    MaintenanceAction::Prune {
                        selection: query(&d, QueryMode::History, 10)?.selection().clone(),
                        raw_before: Timestamp::new(if target == "raw" { 100 } else { 0 })?,
                        summaries_before: Timestamp::new(100)?,
                    },
                )
                .await?;
            assert!(matches!(progress, MaintenanceProgress::Complete { .. }));
            Ok::<_, anyhow::Error>(())
        };
        let (cleaned, released) = tokio::join!(cleanup, release);
        released?;
        cleaned?;
        assert_eq!(
            f.ch.sql(
                "SELECT count() FROM system.processes WHERE query LIKE 'INSERT INTO rss_ts_ch.%'"
            )
            .await?
            .trim(),
            "0"
        );
        assert_eq!(
            f.ch.sql(&format!("SELECT count() FROM rss_ts_ch.{target}"))
                .await?
                .trim(),
            "0"
        );
        proxy.replay().await?;
        assert_eq!(
            f.ch.sql(&format!("SELECT count() FROM rss_ts_ch.{target}"))
                .await?
                .trim(),
            "0"
        );
    }
    Ok(())
}
