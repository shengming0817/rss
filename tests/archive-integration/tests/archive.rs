mod dr;
#[path = "../../fixtures/message_fence.rs"]
mod fence_fixture;
#[path = "../../postgres-integration/tests/recovery/support.rs"]
mod support;
use anyhow::Context;
use aws_sdk_s3::{
    Client,
    config::{Credentials, Region},
};
use aws_smithy_http_client::tls::{self, TrustStore};
use rss_transactional_messaging::{
    inbox::{ConsumerGroup, ConsumerIdentity},
    message::MessageFingerprint,
    policy::*,
};
use rss_transactional_messaging_postgres::*;
use rss_transactional_messaging_recovery::{
    DeadLetterId, OperationId, Version,
    archive::*,
    protection::{CaptureContext, seal},
};
use rss_transactional_messaging_recovery_s3::{Clock, Unverified};
use sha2::{Digest, Sha256};
use sqlx::{
    Row,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use support::*;
struct Wall;
impl Clock for Wall {
    #[allow(clippy::disallowed_methods)] // reason: real-provider wall-clock fixture.
    fn unix_seconds(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    }
}
struct Allow;
impl Authorizer for Allow {
    async fn authorize(
        &self,
        c: Challenge<'_>,
        _: OperationDeadline,
    ) -> Result<Authorization, Error> {
        Ok(c.authorized())
    }
}
struct Observe;
impl Observer for Observe {
    fn observe(&self, _: Event) {}
}
fn deadline() -> OperationDeadline {
    let t = Timer::new();
    t.cutoff().operation(&t)
}
fn settled<T, E: std::fmt::Display>(
    v: rss_transactional_messaging::transaction::LocalTxAttempt<T, E>,
) -> anyhow::Result<T> {
    v.fold(
        Ok,
        |e| Err(anyhow::anyhow!("not started: {e}")),
        |e| Err(anyhow::anyhow!("rolled back: {e}")),
        |e| Err(anyhow::anyhow!("rollback failed: {e}")),
        |e| Err(anyhow::anyhow!("commit unknown: {e}")),
        |e| Err(anyhow::anyhow!("fenced: {e}")),
    )
}
fn client(f: &testkit::MinioTlsFixture) -> anyhow::Result<Client> {
    let c = f.workload();
    let tls = tls::TlsContext::builder()
        .with_trust_store(TrustStore::empty().with_pem_certificate(f.ca_pem().as_bytes().to_vec()))
        .build()?;
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(
            tls::rustls_provider::CryptoMode::Ring,
        ))
        .tls_context(tls)
        .build_https();
    Ok(Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .endpoint_url(c.endpoint_url())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                c.access_key_id(),
                c.secret_access_key(),
                None,
                None,
                "fixture",
            ))
            .force_path_style(true)
            .http_client(http)
            .build(),
    ))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_archive_closed_loop() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), run()).await??;
    Ok(())
}
#[allow(clippy::cognitive_complexity)] // reason: ordered real-provider fixture lifecycle and adjacent assertions.
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("archive").await?;
    let minio = testkit::minio_tls_archive(testkit::NetworkAttachment {
        network: network.name(),
        dns_name: "archive-s3",
    })
    .await?;
    let sdk = client(&minio)?;
    let store = Unverified::new(sdk.clone(), minio.archive_bucket().into())?
        .verify(&Wall, deadline())
        .await
        .context("verify real bucket")?;
    Box::pin(adapter_errors(&sdk, &minio)).await?;
    let bytes = b"exact version fixture".to_vec();
    let p = Prepared {
        object: Object {
            key: "short-retention".into(),
            checksum: Sha256::digest(&bytes).into(),
            length: bytes.len() as u64,
            version: None,
            retain_until: Wall.unix_seconds() + 3,
        },
        bytes,
    };
    let object = store
        .put(&p, deadline())
        .await
        .context("short object PUT")?;
    assert_eq!(store.put(&p, deadline()).await?, object);
    minio
        .assert_admin_cannot_delete_retained_version(
            &object.key,
            object
                .version
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("version"))?,
        )
        .await?;
    tokio::time::sleep(Duration::from_secs(4)).await;
    minio
        .delete_expired_version(
            &object.key,
            object
                .version
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("version"))?,
        )
        .await?;
    assert!(
        store
            .inspect(&object, true, deadline())
            .await
            .context("expired HEAD")?
            .is_none()
    );
    let pg = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "archive-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let params = pg.params();
    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .options([
            ("rss.tenant_id", "11111111-1111-1111-1111-111111111111"),
            ("rss.storage_target", "01010101010101010101010101010101"),
            ("rss.storage_lineage", "02020202020202020202020202020202"),
            ("rss.execution_epoch", "1"),
        ])
        .password(&params.password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(pg.ca_pem().as_bytes().to_vec());
    let owner = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options.clone())
        .await?;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS")
        .execute(&owner)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL).execute(&owner).await?;
    sqlx::raw_sql("CREATE ROLE archive_worker LOGIN PASSWORD 'fixture-only' NOBYPASSRLS; GRANT USAGE ON SCHEMA rss_transactional_messaging TO archive_worker; GRANT SELECT ON rss_transactional_messaging.consumer_dead_letter,rss_transactional_messaging.archive_jobs,rss_transactional_messaging.archive_objects TO archive_worker; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.archive_claim(uuid,uuid,bigint,bytea,bigint,bigint,boolean,bigint),rss_transactional_messaging.archive_prepare(uuid,uuid,bytea,jsonb,bytea),rss_transactional_messaging.archive_record(uuid,uuid,bytea,uuid,jsonb),rss_transactional_messaging.archive_purge(uuid,uuid,bytea,jsonb),rss_transactional_messaging.archive_missing(uuid,uuid,bytea,uuid,jsonb),rss_transactional_messaging.archive_fault(uuid,uuid,bytea,text) TO archive_worker;").execute(&owner).await?;
    let config = PgConfig::new(
        &params.host,
        params.port,
        &params.database,
        "archive_worker",
        PgPassword::new("fixture-only"),
        PgPrivateCa::from_pem(pg.ca_pem().as_bytes().to_vec())?,
    );
    fence_fixture::provision(&owner).await?;
    let repository =
        PgArchiveRepository::connect(config.clone(), Timer::new(), fence_fixture::binding())
            .await?;
    let raw = PgPoolOptions::new()
        .connect_with(
            options
                .clone()
                .username("archive_worker")
                .password("fixture-only"),
        )
        .await?;
    assert!(
        sqlx::query("UPDATE rss_transactional_messaging.consumer_dead_letter SET capsule=NULL")
            .execute(&raw)
            .await
            .is_err()
    );
    temporary_table_shadow(&raw).await?;
    let msg = message("archive-source");
    let id = DeadLetterId::new();
    let fingerprint = MessageFingerprint::of(&msg);
    let context = CaptureContext::from_provider(
        id,
        ConsumerIdentity::new(
            tenant(),
            ConsumerGroup::parse("archive")?,
            msg.id().clone(),
            msg.metadata().contract().clone(),
        ),
        fingerprint,
    );
    let capsule = seal(&Key(1), &context, &msg)?;
    let contract = msg.metadata().contract();
    sqlx::query("INSERT INTO rss_transactional_messaging.consumer_dead_letter(tenant_id,id,message_id,consumer_group,contract,contract_version,schema_digest,fingerprint,capsule,reason,created_at) VALUES($1::uuid,$2::uuid,$3,'archive',$4,$5,$6,$7,$8,'rejected_permanent',clock_timestamp()-interval '3 days')")
        .bind(tenant().to_string()).bind(id.to_string()).bind(msg.id().as_str()).bind(contract.id().as_str()).bind(contract.version().to_string()).bind(contract.schema_digest().as_str()).bind(fingerprint.as_bytes().as_slice()).bind(capsule.bytes()).execute(&owner).await?;
    let request = authorize(
        &Allow,
        Request::new(
            tenant(),
            id,
            OperationId::new(),
            Version::new(1)?,
            Retention::new(172800, 604800)?,
            Hold::Release,
        ),
        deadline(),
    )
    .await?;
    let clock = Timer::new();
    let deadlines = ExecutionDeadlines::from_budget(
        &clock,
        ExecutionBudget::new(Duration::from_secs(20), Duration::from_secs(5))?,
    )?;
    let result = execute(
        &repository,
        &store,
        &HotKey(Key(1)),
        &ArchiveKey(ArchiveFixtureKey),
        &request,
        &clock,
        deadlines,
        &Observe,
    )
    .await;
    assert_eq!(settled(result)?, Outcome::Purged);
    let exhausted_clock = Timer::new();
    let exhausted = ExecutionDeadlines::from_budget(
        &exhausted_clock,
        ExecutionBudget::new(Duration::from_millis(100), Duration::from_millis(50))?,
    )?;
    tokio::time::sleep(Duration::from_millis(55)).await;
    let expired = execute(
        &repository,
        &store,
        &HotKey(Key(1)),
        &ArchiveKey(ArchiveFixtureKey),
        &request,
        &exhausted_clock,
        exhausted,
        &Observe,
    )
    .await;
    assert_eq!(
        expired.fold(|_| None, Some, |_| None, |_| None, |_| None, |_| None),
        Some(Error::Deadline)
    );
    let row=sqlx::query("SELECT capsule,recovery_version FROM rss_transactional_messaging.consumer_dead_letter WHERE id=$1::uuid").bind(id.to_string()).fetch_one(&owner).await?;
    assert!(row.try_get::<Option<Vec<u8>>, _>("capsule")?.is_none());
    assert_eq!(row.try_get::<i64, _>("recovery_version")?, 2);
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM rss_transactional_messaging.archive_objects WHERE verified AND prepared IS NULL").fetch_one(&owner).await?,1);
    Box::pin(lease_budget(&repository, &owner)).await?;
    Box::pin(fault_matrix(&repository, &store, &owner)).await?;
    unreadable_archive(&repository, &store, &owner).await?;
    expiry_reconciliation(&repository, &store, &owner, &minio).await?;
    fair_scan(&repository, &owner).await?;
    Box::pin(fault_receipt(&repository, &store, &owner)).await?;
    Box::pin(interrupted_fault_receipt(&repository, &store, &owner)).await?;
    adversarial_schema(&config, &owner).await?;
    let upgrade_config = PgConfig::new(
        &params.host,
        params.port,
        "archive_upgrade",
        "archive_worker",
        PgPassword::new("fixture-only"),
        PgPrivateCa::from_pem(pg.ca_pem().as_bytes().to_vec())?,
    );
    Box::pin(dr::upgrade::run(
        &repository,
        &store,
        &owner,
        options,
        upgrade_config,
    ))
    .await?;
    dr::run(&repository, &store, &owner, &config).await?;
    repository.close().await;
    Ok(())
}
struct ArchiveFixtureKey;
impl rss_data_protection::Aead for ArchiveFixtureKey {
    fn seal(
        &self,
        p: &[u8],
        a: &rss_data_protection::DerivedAad,
    ) -> Result<rss_data_protection::CiphertextEnvelope, rss_data_protection::AeadError> {
        let c = rss_data_protection::Aead::seal(&Key(2), p, a)?;
        rss_data_protection::CiphertextEnvelope::new(
            c.alg(),
            c.mode(),
            "archive-key",
            c.key_version(),
            c.nonce().to_vec(),
            c.ciphertext().to_vec(),
            c.tag().to_vec(),
            a.coordinates().clone(),
        )
        .map_err(|_| rss_data_protection::AeadError::Seal)
    }
    fn open(
        &self,
        c: &rss_data_protection::CiphertextEnvelope,
        a: &rss_data_protection::DerivedAad,
    ) -> Result<rss_data_protection::Plaintext, rss_data_protection::AeadError> {
        rss_data_protection::Aead::open(&Key(2), c, a)
    }
}

async fn seed(owner: &sqlx::PgPool, name: &str) -> anyhow::Result<DeadLetterId> {
    let msg = message(name);
    let id = DeadLetterId::new();
    let fp = MessageFingerprint::of(&msg);
    let context = CaptureContext::from_provider(
        id,
        ConsumerIdentity::new(
            tenant(),
            ConsumerGroup::parse("archive")?,
            msg.id().clone(),
            msg.metadata().contract().clone(),
        ),
        fp,
    );
    let capsule = seal(&Key(1), &context, &msg)?;
    let contract = msg.metadata().contract();
    sqlx::query("INSERT INTO rss_transactional_messaging.consumer_dead_letter(tenant_id,id,message_id,consumer_group,contract,contract_version,schema_digest,fingerprint,capsule,reason,created_at) VALUES($1::uuid,$2::uuid,$3,'archive',$4,$5,$6,$7,$8,'rejected_permanent',clock_timestamp()-interval '3 days')")
    .bind(tenant().to_string()).bind(id.to_string()).bind(name).bind(contract.id().as_str()).bind(contract.version().to_string()).bind(contract.schema_digest().as_str()).bind(fp.as_bytes().as_slice()).bind(capsule.bytes()).execute(owner).await?;
    Ok(id)
}
async fn request(id: DeadLetterId, version: i64, hold: Hold) -> anyhow::Result<AuthorizedRequest> {
    Ok(authorize(
        &Allow,
        Request::new(
            tenant(),
            id,
            OperationId::new(),
            Version::new(version)?,
            Retention::new(172800, 604800)?,
            hold,
        ),
        deadline(),
    )
    .await?)
}
async fn expire(owner: &sqlx::PgPool, r: &AuthorizedRequest) -> anyhow::Result<()> {
    sqlx::query("UPDATE rss_transactional_messaging.archive_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE operation_id=$1::uuid").bind(r.request().operation().to_string()).execute(owner).await?;
    Ok(())
}
async fn is_hot(owner: &sqlx::PgPool, id: DeadLetterId) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar("SELECT capsule IS NOT NULL FROM rss_transactional_messaging.consumer_dead_letter WHERE id=$1::uuid").bind(id.to_string()).fetch_one(owner).await?)
}
async fn invoke<S: ArchiveObjectStore>(
    r: &PgArchiveRepository,
    s: &S,
    q: &AuthorizedRequest,
) -> rss_transactional_messaging::transaction::LocalTxAttempt<Outcome, Error> {
    let c = Timer::new();
    let budget = ExecutionBudget::new(Duration::from_secs(15), Duration::from_secs(3));
    let d = match budget.and_then(|b| ExecutionDeadlines::from_budget(&c, b)) {
        Ok(v) => v,
        Err(_) => {
            return rss_transactional_messaging::transaction::LocalTxAttempt::not_started(
                Error::Invalid,
            );
        }
    };
    execute(
        r,
        s,
        &HotKey(Key(1)),
        &ArchiveKey(ArchiveFixtureKey),
        q,
        &c,
        d,
        &Observe,
    )
    .await
}
#[derive(Clone, Copy)]
enum Fault {
    LostPut,
    CommitUnknown,
    Checksum,
    Body,
    MissingCommitUnknown,
    MissingCommitPending,
    Version,
    Retention,
    Missing,
    Unavailable,
}
struct FaultStore<'a> {
    real: &'a rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    repository: &'a PgArchiveRepository,
    fault: Fault,
}
impl ArchiveObjectStore for FaultStore<'_> {
    async fn put(&self, p: &Prepared, d: OperationDeadline) -> Result<Object, Error> {
        let result = self.real.put(p, d).await?;
        match self.fault {
            Fault::LostPut => Err(Error::Unavailable),
            Fault::CommitUnknown => {
                self.repository
                    .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
                Ok(result)
            }
            _ => Ok(result),
        }
    }
    async fn inspect(
        &self,
        o: &Object,
        b: bool,
        d: OperationDeadline,
    ) -> Result<Option<Observation>, Error> {
        let result = self.real.inspect(o, b, d).await?;
        if matches!(self.fault, Fault::MissingCommitPending) {
            self.repository
                .inject_next_transaction_fault(PgTransactionFault::CommitPending);
            return Ok(None);
        }
        if matches!(self.fault, Fault::MissingCommitUnknown) {
            self.repository
                .inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
            return Ok(None);
        }
        if matches!(self.fault, Fault::Missing) {
            return Ok(None);
        }
        if matches!(self.fault, Fault::Unavailable) {
            return Err(Error::Unavailable);
        }
        Ok(result.map(|mut v| {
            match self.fault {
                Fault::Checksum => v.object.checksum[0] ^= 1,
                Fault::Body => {
                    if let Some(bytes) = v.bytes.as_mut() {
                        bytes[0] ^= 1
                    }
                }

                Fault::Version => v.object.version = Some("wrong-version".into()),
                Fault::Retention => v.object.retain_until = 1,
                _ => {}
            }
            v
        }))
    }
}
#[allow(clippy::cognitive_complexity)] // reason: independent real-provider failure scenarios share one bounded fixture.
async fn fault_matrix(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    for (name, fault) in [
        ("lost-put", Fault::LostPut),
        ("commit-unknown", Fault::CommitUnknown),
        ("wrong-checksum", Fault::Checksum),
        ("wrong-body", Fault::Body),
        ("wrong-version", Fault::Version),
        ("short-retention", Fault::Retention),
        ("missing", Fault::Missing),
        ("unavailable", Fault::Unavailable),
    ] {
        let id = seed(owner, name).await?;
        let r = request(id, 1, Hold::Release).await?;
        let result = invoke(
            repository,
            &FaultStore {
                real: store,
                repository,
                fault,
            },
            &r,
        )
        .await;
        if matches!(fault, Fault::LostPut) {
            assert_eq!(
                result.fold(|_| None, |_| None, |_| None, |_| None, Some, |_| None),
                Some(Error::Unavailable)
            );
        } else if matches!(fault, Fault::CommitUnknown) {
            assert_eq!(settled(result)?, Outcome::Archived)
        } else {
            assert!(settled(result).is_err(), "{name}")
        }
        assert!(is_hot(owner, id).await?, "{name} retained HOT");
        if matches!(
            fault,
            Fault::Checksum | Fault::Body | Fault::Version | Fault::Retention | Fault::Missing
        ) {
            let expected = if matches!(fault, Fault::Missing) {
                Error::Missing
            } else {
                Error::Evidence
            };
            assert_eq!(repository.receipt(&r, deadline()).await, Err(expected));
            expire(owner, &r).await?;
            assert_eq!(
                invoke(repository, store, &r)
                    .await
                    .fold(|_| None, Some, Some, Some, Some, Some),
                Some(expected)
            );
            assert!(is_hot(owner, id).await?);
            let next = request(id, 2, Hold::Release).await?;
            assert_eq!(
                settled(invoke(repository, store, &next).await)?,
                Outcome::Purged
            );
            assert_eq!(repository.receipt(&r, deadline()).await, Err(expected));
        }
        if matches!(fault, Fault::LostPut | Fault::CommitUnknown) {
            let before:serde_json::Value=sqlx::query_scalar("SELECT object FROM rss_transactional_messaging.archive_objects WHERE operation_id=$1::uuid").bind(r.request().operation().to_string()).fetch_one(owner).await?;
            expire(owner, &r).await?;
            assert_eq!(
                settled(invoke(repository, store, &r).await)?,
                Outcome::Purged
            );
            let after:serde_json::Value=sqlx::query_scalar("SELECT object FROM rss_transactional_messaging.archive_objects WHERE operation_id=$1::uuid").bind(r.request().operation().to_string()).fetch_one(owner).await?;
            assert_eq!(before["checksum"], after["checksum"]);
            assert_eq!(before["key"], after["key"]);
            assert_eq!(
                repository.receipt(&r, deadline()).await?,
                Some(Outcome::Purged)
            );
            expire(owner, &r).await?;
            assert_eq!(
                settled(invoke(repository, store, &r).await)?,
                Outcome::Purged
            );
        }
    }
    let id = seed(owner, "held").await?;
    let held = request(id, 1, Hold::Retain).await?;
    assert_eq!(
        settled(invoke(repository, store, &held).await)?,
        Outcome::Held
    );
    assert!(is_hot(owner, id).await?);
    let release = request(id, 2, Hold::Release).await?;
    assert_eq!(
        settled(invoke(repository, store, &release).await)?,
        Outcome::Purged
    );
    assert!(
        settled(invoke(repository, store, &held).await).is_err(),
        "old policy fenced"
    );
    let id = seed(owner, "concurrent").await?;
    let r = request(id, 1, Hold::Release).await?;
    let (a, b) = tokio::join!(
        repository.claim(&r, deadline()),
        repository.claim(&r, deadline())
    );
    let a = a.fold(Ok, Err, Err, Err, Err, Err);
    let b = b.fold(Ok, Err, Err, Err, Err, Err);
    assert_eq!(a.as_ref().err().or(b.as_ref().err()), Some(&Error::Busy));
    assert_ne!(a.is_ok(), b.is_ok());
    let old = a.or(b)?;
    expire(owner, &r).await?;
    let new = settled(repository.claim(&r, deadline()).await)?;
    assert_ne!(old.token, new.token);
    let p = Prepared {
        object: Object {
            key: "invalid".into(),
            checksum: [0; 32],
            length: 1,
            version: None,
            retain_until: 1,
        },
        bytes: vec![0],
    };
    assert_eq!(
        repository.prepare(&r, &old, &p, deadline()).await.fold(
            |_| None,
            |_| None,
            |_| None,
            |_| None,
            |_| None,
            Some
        ),
        Some(Error::Conflict)
    );
    assert_eq!(
        repository.prepare(&r, &new, &p, deadline()).await.fold(
            |_| None,
            Some,
            Some,
            Some,
            Some,
            Some
        ),
        Some(Error::Evidence)
    );
    let conflict = request(id, 1, Hold::Release).await?;
    assert_eq!(
        repository
            .claim(&conflict, deadline())
            .await
            .fold(|_| None, Some, Some, Some, Some, Some),
        Some(Error::Conflict)
    );
    let short = authorize(
        &Allow,
        Request::new(
            tenant(),
            id,
            OperationId::new(),
            Version::new(2)?,
            Retention::new(1, 1)?,
            Hold::Release,
        ),
        deadline(),
    )
    .await?;
    assert_eq!(
        repository
            .claim(&short, deadline())
            .await
            .fold(|_| None, Some, Some, Some, Some, Some),
        Some(Error::Retention)
    );
    let wrong_tenant =
        rss_request_context::TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?;
    let q = authorize(
        &Allow,
        Request::new(
            wrong_tenant,
            id,
            OperationId::new(),
            Version::new(2)?,
            Retention::new(172800, 604800)?,
            Hold::Release,
        ),
        deadline(),
    )
    .await?;
    assert!(matches!(
        repository
            .claim(&q, deadline())
            .await
            .fold(|_| None, Some, Some, Some, Some, Some),
        Some(Error::NotFound)
    ));
    let id = seed(owner, "key-mix").await?;
    let r = request(id, 1, Hold::Release).await?;
    let clock = Timer::new();
    let deadlines = ExecutionDeadlines::from_budget(
        &clock,
        ExecutionBudget::new(Duration::from_secs(10), Duration::from_secs(2))?,
    )?;
    let result = execute(
        repository,
        store,
        &HotKey(Key(1)),
        &ArchiveKey(Key(1)),
        &r,
        &clock,
        deadlines,
        &Observe,
    )
    .await;
    assert!(settled(result).is_err());
    assert!(is_hot(owner, id).await?);
    let id = seed(owner, "renew-generation").await?;
    let r = request(id, 1, Hold::Release).await?;
    assert!(
        settled(
            invoke(
                repository,
                &FaultStore {
                    real: store,
                    repository,
                    fault: Fault::LostPut
                },
                &r
            )
            .await
        )
        .is_err()
    );
    sqlx::query("UPDATE rss_transactional_messaging.archive_objects SET object=jsonb_set(object,'{retainUntil}',to_jsonb(1::bigint)) WHERE operation_id=$1::uuid").bind(r.request().operation().to_string()).execute(owner).await?;
    expire(owner, &r).await?;
    assert_eq!(
        settled(invoke(repository, store, &r).await)?,
        Outcome::Purged
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM rss_transactional_messaging.archive_objects WHERE operation_id=$1::uuid AND prepared IS NULL AND verified").bind(r.request().operation().to_string()).fetch_one(owner).await?,2);
    Ok(())
}

#[allow(clippy::cognitive_complexity)] // reason: elapsed-horizon snapshot and real exact-version deletion assertions.
async fn expiry_reconciliation(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
    minio: &testkit::MinioTlsFixture,
) -> anyhow::Result<()> {
    let id = seed(owner, "elapsed-horizon").await?;
    let r = request(id, 1, Hold::Release).await?;
    let c = settled(repository.claim(&r, deadline()).await)?;
    let bytes = b"expired fixture snapshot".to_vec();
    let p = Prepared {
        object: Object {
            key: format!("consumer/{}/{}/{}.v1.enc", tenant(), id, c.generation),
            checksum: Sha256::digest(&bytes).into(),
            length: bytes.len() as u64,
            version: None,
            retain_until: Wall.unix_seconds() + 3,
        },
        bytes,
    };
    let object = store.put(&p, deadline()).await?;
    // Seed the state after a formerly sufficient horizon has elapsed. This short lock never authorizes production purge.
    sqlx::query("INSERT INTO rss_transactional_messaging.archive_objects(tenant_id,operation_id,generation,object,verified,verified_epoch,verified_lineage) VALUES($1::uuid,$2::uuid,$3::uuid,$4,true,current_setting('rss.execution_epoch')::bigint,decode(current_setting('rss.storage_lineage'),'hex'))").bind(tenant().to_string()).bind(r.request().operation().to_string()).bind(&c.generation).bind(serde_json::to_value(&object)?).execute(owner).await?;
    sqlx::query("UPDATE rss_transactional_messaging.consumer_dead_letter SET capsule=NULL WHERE id=$1::uuid").bind(id.to_string()).execute(owner).await?;
    sqlx::query("UPDATE rss_transactional_messaging.archive_jobs SET purged=true WHERE operation_id=$1::uuid").bind(r.request().operation().to_string()).execute(owner).await?;
    expire(owner, &r).await?;
    assert_eq!(
        settled(invoke(repository, store, &r).await)?,
        Outcome::Purged
    );
    tokio::time::sleep(Duration::from_secs(4)).await;
    expire(owner, &r).await?;
    assert_eq!(
        settled(invoke(repository, store, &r).await)?,
        Outcome::Retained
    );
    minio
        .delete_expired_version(
            &object.key,
            object
                .version
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("version"))?,
        )
        .await?;
    expire(owner, &r).await?;
    assert_eq!(
        settled(invoke(repository, store, &r).await)?,
        Outcome::Reconciled
    );
    assert_eq!(
        repository.receipt(&r, deadline()).await?,
        Some(Outcome::Reconciled)
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM rss_transactional_messaging.consumer_dead_letter WHERE id=$1::uuid").bind(id.to_string()).fetch_one(owner).await?,1);
    Ok(())
}

// A caller-controlled temporary relation must never replace the trusted HOT table.
async fn temporary_table_shadow(raw: &sqlx::PgPool) -> anyhow::Result<()> {
    let mut tx = raw.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant().to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("CREATE TEMP TABLE consumer_dead_letter(shadow boolean) ON COMMIT DROP")
        .execute(&mut *tx)
        .await?;
    let result = sqlx::query("SELECT rss_transactional_messaging.archive_claim(gen_random_uuid(),gen_random_uuid(),1,decode(repeat('00',32),'hex'),172800,604800,false,30000)")
        .execute(&mut *tx).await;
    let error = result
        .err()
        .context("nonexistent trusted source must be rejected")?;
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("P0002"),
        "trusted table lookup, not temporary table resolution: {error}"
    );
    tx.rollback().await?;
    Ok(())
}

async fn adversarial_schema(config: &PgConfig, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let cases = [
        (
            "CREATE FUNCTION rss_transactional_messaging.rogue_archive() RETURNS void LANGUAGE sql SECURITY DEFINER AS 'SELECT NULL::void'",
            "DROP FUNCTION rss_transactional_messaging.rogue_archive()",
        ),
        (
            "CREATE POLICY rogue ON rss_transactional_messaging.archive_jobs USING(true)",
            "DROP POLICY rogue ON rss_transactional_messaging.archive_jobs",
        ),
        (
            "ALTER POLICY archive_tenant ON rss_transactional_messaging.archive_objects USING(true)",
            "ALTER POLICY archive_tenant ON rss_transactional_messaging.archive_objects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "CREATE ROLE archive_privileged NOLOGIN BYPASSRLS; GRANT archive_privileged TO archive_worker",
            "REVOKE archive_privileged FROM archive_worker; DROP ROLE archive_privileged",
        ),
        (
            "ALTER TABLE rss_transactional_messaging.archive_jobs ALTER COLUMN request_digest DROP NOT NULL",
            "ALTER TABLE rss_transactional_messaging.archive_jobs ALTER COLUMN request_digest SET NOT NULL",
        ),
        (
            "ALTER TABLE rss_transactional_messaging.archive_jobs DROP CONSTRAINT archive_jobs_request_digest_check",
            "ALTER TABLE rss_transactional_messaging.archive_jobs ADD CONSTRAINT archive_jobs_request_digest_check CHECK(octet_length(request_digest)=32)",
        ),
        (
            "ALTER TABLE rss_transactional_messaging.archive_objects ALTER COLUMN verified SET DEFAULT true",
            "ALTER TABLE rss_transactional_messaging.archive_objects ALTER COLUMN verified SET DEFAULT false",
        ),
        (
            "GRANT UPDATE(capsule) ON rss_transactional_messaging.consumer_dead_letter TO archive_worker",
            "REVOKE UPDATE(capsule) ON rss_transactional_messaging.consumer_dead_letter FROM archive_worker",
        ),
    ];
    let function = "rss_transactional_messaging.archive_claim(uuid,uuid,bigint,bytea,bigint,bigint,boolean,bigint)";
    let function_cases=[
        (format!("ALTER FUNCTION {function} RESET ALL"),format!("ALTER FUNCTION {function} SET search_path=pg_catalog,rss_transactional_messaging,pg_temp")),
        (format!("ALTER FUNCTION {function} SECURITY INVOKER"),format!("ALTER FUNCTION {function} SECURITY DEFINER")),
        (format!("ALTER FUNCTION {function} SET search_path=public"),format!("ALTER FUNCTION {function} SET search_path=pg_catalog,rss_transactional_messaging,pg_temp")),
        (format!("GRANT EXECUTE ON FUNCTION {function} TO PUBLIC"),format!("REVOKE EXECUTE ON FUNCTION {function} FROM PUBLIC")),
        (format!("REVOKE EXECUTE ON FUNCTION {function} FROM archive_worker"),format!("GRANT EXECUTE ON FUNCTION {function} TO archive_worker")),
        (format!("CREATE ROLE archive_function_owner NOLOGIN; GRANT USAGE,CREATE ON SCHEMA rss_transactional_messaging TO archive_function_owner; ALTER FUNCTION {function} OWNER TO archive_function_owner; REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM archive_function_owner; GRANT archive_function_owner TO archive_worker"),format!("REVOKE archive_function_owner FROM archive_worker; ALTER FUNCTION {function} OWNER TO CURRENT_USER; REVOKE ALL ON SCHEMA rss_transactional_messaging FROM archive_function_owner; DROP ROLE archive_function_owner")),
        ("CREATE FUNCTION rss_transactional_messaging.archive_claim(text) RETURNS void LANGUAGE sql SECURITY DEFINER AS 'SELECT NULL::void'; REVOKE ALL ON FUNCTION rss_transactional_messaging.archive_claim(text) FROM PUBLIC; CREATE ROLE archive_extra NOLOGIN; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.archive_claim(text) TO archive_extra; GRANT archive_extra TO archive_worker".into(),"REVOKE archive_extra FROM archive_worker; DROP FUNCTION rss_transactional_messaging.archive_claim(text); DROP ROLE archive_extra".into()),
    ];
    let search_path_cases = [
        "rss_transactional_messaging.archive_claim(uuid,uuid,bigint,bytea,bigint,bigint,boolean,bigint)",
        "rss_transactional_messaging.archive_prepare(uuid,uuid,bytea,jsonb,bytea)",
        "rss_transactional_messaging.archive_record(uuid,uuid,bytea,uuid,jsonb)",
        "rss_transactional_messaging.archive_purge(uuid,uuid,bytea,jsonb)",
        "rss_transactional_messaging.archive_missing(uuid,uuid,bytea,uuid,jsonb)",
        "rss_transactional_messaging.archive_fault(uuid,uuid,bytea,text)",
        "rss_transactional_messaging.archive_fence(uuid,uuid,bytea)",
    ].map(|function| (
        format!("ALTER FUNCTION {function} SET search_path=pg_catalog,rss_transactional_messaging"),
        format!("ALTER FUNCTION {function} SET search_path=pg_catalog,rss_transactional_messaging,pg_temp"),
    ));
    for (corrupt, repair) in cases
        .into_iter()
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .chain(function_cases)
        .chain(search_path_cases)
    {
        // Audited: all statements and substituted identifiers are fixed fixture literals.
        sqlx::raw_sql(sqlx::AssertSqlSafe(corrupt.as_str()))
            .execute(owner)
            .await?;
        assert!(
            matches!(
                PgArchiveRepository::connect(
                    config.clone(),
                    Timer::new(),
                    fence_fixture::binding()
                )
                .await,
                Err(Error::StorageContract)
            ),
            "{corrupt}"
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(repair.as_str()))
            .execute(owner)
            .await?;
    }
    PgArchiveRepository::connect(config.clone(), Timer::new(), fence_fixture::binding())
        .await?
        .close()
        .await;
    Ok(())
}

async fn fair_scan(repository: &PgArchiveRepository, owner: &sqlx::PgPool) -> anyhow::Result<()> {
    let id = seed(owner, "scan-fairness").await?;
    let r = request(id, 1, Hold::Release).await?;
    settled(repository.claim(&r, deadline()).await)?;
    // More unresolved unknown PUTs than a batch must not monopolize every retry.
    sqlx::query("INSERT INTO rss_transactional_messaging.archive_objects(tenant_id,operation_id,generation,object) SELECT $1::uuid,$2::uuid,gen_random_uuid(),jsonb_build_object('key','unknown-'||n,'checksum',to_jsonb(array_fill(0,ARRAY[32])),'length',1,'version',NULL,'retainUntil',1) FROM generate_series(1,130) n")
        .bind(tenant().to_string()).bind(r.request().operation().to_string()).execute(owner).await?;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..3 {
        expire(owner, &r).await?;
        let c = settled(repository.claim(&r, deadline()).await)?;
        assert_eq!(c.retired.len(), 64);
        seen.extend(c.retired.into_iter().map(|o| o.key));
    }
    assert_eq!(seen.len(), 130);
    Ok(())
}
async fn fault_receipt(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let id = seed(owner, "fault-receipt").await?;
    let r = request(id, 1, Hold::Release).await?;
    assert_eq!(
        settled(invoke(repository, store, &r).await)?,
        Outcome::Purged
    );
    expire(owner, &r).await?;
    let result = invoke(
        repository,
        &FaultStore {
            real: store,
            repository,
            fault: Fault::MissingCommitUnknown,
        },
        &r,
    )
    .await;
    assert!(result.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true,
        |_| false
    ));
    assert_eq!(
        repository.receipt(&r, deadline()).await,
        Err(Error::Missing)
    );
    expire(owner, &r).await?;
    assert_eq!(
        repository
            .claim(&r, deadline())
            .await
            .fold(|_| None, Some, Some, Some, Some, Some),
        Some(Error::Missing)
    );
    Ok(())
}
async fn interrupted_fault_receipt(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let id = seed(owner, "fault-write-interrupted").await?;
    let r = request(id, 1, Hold::Release).await?;
    assert_eq!(
        settled(invoke(repository, store, &r).await)?,
        Outcome::Purged
    );
    expire(owner, &r).await?;
    let clock = Timer::new();
    let deadlines = ExecutionDeadlines::from_budget(
        &clock,
        ExecutionBudget::new(Duration::from_secs(2), Duration::from_millis(500))?,
    )?;
    let result = execute(
        repository,
        &FaultStore {
            real: store,
            repository,
            fault: Fault::MissingCommitPending,
        },
        &HotKey(Key(1)),
        &ArchiveKey(ArchiveFixtureKey),
        &r,
        &clock,
        deadlines,
        &Observe,
    )
    .await;
    assert!(
        result.fold(
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| true,
            |_| false
        ),
        "old receipt must not settle the interrupted integrity-fault write"
    );
    assert_eq!(
        repository.receipt(&r, deadline()).await?,
        Some(Outcome::Purged),
        "fault did not commit, so the old receipt still exists"
    );
    Ok(())
}

// Produces authenticated bytes with an unsupported format: checksum-only verification would accept it.
struct FutureFormatKey;
impl rss_data_protection::Aead for FutureFormatKey {
    fn seal(
        &self,
        p: &[u8],
        a: &rss_data_protection::DerivedAad,
    ) -> Result<rss_data_protection::CiphertextEnvelope, rss_data_protection::AeadError> {
        let mut v: serde_json::Value =
            serde_json::from_slice(p).map_err(|_| rss_data_protection::AeadError::Seal)?;
        v["version"] = serde_json::json!(2);
        let bytes = serde_json::to_vec(&v).map_err(|_| rss_data_protection::AeadError::Seal)?;
        rss_data_protection::Aead::seal(&ArchiveFixtureKey, &bytes, a)
    }
    fn open(
        &self,
        c: &rss_data_protection::CiphertextEnvelope,
        a: &rss_data_protection::DerivedAad,
    ) -> Result<rss_data_protection::Plaintext, rss_data_protection::AeadError> {
        rss_data_protection::Aead::open(&ArchiveFixtureKey, c, a)
    }
}
async fn unreadable_archive(
    repository: &PgArchiveRepository,
    store: &rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let id = seed(owner, "unreadable-archive").await?;
    let r = request(id, 1, Hold::Release).await?;
    let clock = Timer::new();
    let deadlines = ExecutionDeadlines::from_budget(
        &clock,
        ExecutionBudget::new(Duration::from_secs(10), Duration::from_secs(2))?,
    )?;
    let attempt = execute(
        repository,
        store,
        &HotKey(Key(1)),
        &ArchiveKey(FutureFormatKey),
        &r,
        &clock,
        deadlines,
        &Observe,
    )
    .await;
    assert_eq!(
        attempt.fold(|_| None, Some, Some, Some, Some, Some),
        Some(Error::Evidence)
    );
    assert!(is_hot(owner, id).await?);
    Ok(())
}

async fn adapter_errors(sdk: &Client, minio: &testkit::MinioTlsFixture) -> anyhow::Result<()> {
    let denied = Unverified::new(sdk.clone(), minio.neighbor_bucket().into())?
        .verify(&Wall, deadline())
        .await;
    assert!(
        matches!(denied, Err(Error::StorageContract)),
        "real IAM denial must not be transient or missing"
    );
    for (bucket, versioned) in [
        (minio.unversioned_bucket(), false),
        (minio.unlocked_bucket(), true),
    ] {
        let posture = sdk.get_bucket_versioning().bucket(bucket).send().await?;
        assert_eq!(
            posture.status() == Some(&aws_sdk_s3::types::BucketVersioningStatus::Enabled),
            versioned
        );
        assert!(
            matches!(
                Unverified::new(sdk.clone(), bucket.into())?
                    .verify(&Wall, deadline())
                    .await,
                Err(Error::StorageContract)
            ),
            "readable invalid bucket must not mint a capability"
        );
    }
    let unavailable_client = Client::from_conf(
        sdk.config()
            .to_builder()
            .endpoint_url("https://127.0.0.1:1")
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(1))
            .build(),
    );
    assert!(matches!(
        Unverified::new(unavailable_client, minio.archive_bucket().into())?
            .verify(&Wall, deadline())
            .await,
        Err(Error::Unavailable)
    ));
    Ok(())
}

async fn lease_budget(
    repository: &PgArchiveRepository,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let id = seed(owner, "lease-budget").await?;
    let r = request(id, 1, Hold::Release).await?;
    let clock = Timer::new();
    let cutoff = AbsoluteDeadline::from_timeout(&clock, Duration::from_secs(40))?;
    settled(repository.claim(&r, cutoff.operation(&clock)).await)?;
    let remaining:f64=sqlx::query_scalar("SELECT extract(epoch FROM lease_until-clock_timestamp())::double precision FROM rss_transactional_messaging.archive_jobs WHERE operation_id=$1::uuid").bind(r.request().operation().to_string()).fetch_one(owner).await?;
    assert!(
        remaining > 39.0,
        "lease should cover the accepted 40-second operation, got {remaining}"
    );
    let other = request(seed(owner, "lease-too-long").await?, 1, Hold::Release).await?;
    let cutoff = AbsoluteDeadline::from_timeout(&clock, Duration::from_secs(301))?;
    assert_eq!(
        repository
            .claim(&other, cutoff.operation(&clock))
            .await
            .fold(|_| None, Some, |_| None, |_| None, |_| None, |_| None),
        Some(Error::Invalid)
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.archive_jobs WHERE operation_id=$1::uuid",
    )
    .bind(other.request().operation().to_string())
    .fetch_one(owner)
    .await?;
    assert_eq!(
        count, 0,
        "oversized budget must be rejected before claim I/O"
    );
    Ok(())
}
