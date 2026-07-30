//! Assembly-private fixture for the exact SettingsOnly production artifact.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diport::Clock as _;
use futures::Stream;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{PgPool, Row as _};
use testkit::{
    ContainerService, MinioTlsFixture, PgTlsFixture, PostgresTestLogin, RabbitTlsFixture,
    RedisTlsFixture, VaultTlsFixture, integration_container_labels, minio_tls_archive,
    postgres_tls, provision_postgres_test_logins_with_private_ca, rabbitmq_tls, redis_tls,
    vault_tls,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[path = "generated/spiffe_workload.rs"]
mod spiffe_workload;

use spiffe_workload::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use spiffe_workload::{X509svid, X509svidRequest, X509svidResponse};

const TENANT: &str = "00000000-0000-4000-8000-000000000187";
const SPIFFE_ID: &str = "spiffe://rss.local/ns/rss/sa/settingsonly";
const INGRESS_SPIFFE_ID: &str = "spiffe://rss.local/ns/rss/sa/ingress-gateway";
const DENIED_INGRESS_SPIFFE_ID: &str = "spiffe://rss.local/ns/rss/sa/denied-ingress";
const ISSUER: &str = "https://issuer.settingsonly.test";
const AUDIENCE: &str = "rss-settingsonly";
const JWT_KID: &str = "settingsonly-production-artifact";
const SETTINGS_TOPIC: &str = "settings.config-version-changed";
const CONFIG_PATH: &str = "/fixtures/settingsonly.toml";
const SECRET_PATH: &str = "/var/run/rss/secrets/serving-secret-bundle";
const WORKLOAD_DIRECTORY: &str = "/run/rss-spiffe";
const WORKLOAD_SOCKET: &str = "/run/rss-spiffe/workload.sock";
const WORKLOAD_ENDPOINT: &str = "unix:///run/rss-spiffe/workload.sock";
const TEST_TIMEOUT: Duration = Duration::from_secs(90);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const PG_WRITER_PASSWORD: &str = "settingsonly-writer-production-1875";
const PG_READER_PASSWORD: &str = "settingsonly-reader-production-1875";
const PG_DLX_ARCHIVER_PASSWORD: &str = "settingsonly-dlx-archiver-production-1875";
const PG_DLX_VERIFIER_PASSWORD: &str = "settingsonly-dlx-verifier-production-1875";
const PG_DLX_PURGER_PASSWORD: &str = "settingsonly-dlx-purger-production-1875";
const TENANT_AUTHORITY_KEY: &str = "settingsonly-tenant-authority-key-1875";
const CONFIG_TRANSIT_KEY: &str = "settings-config-value";
const DLX_HOT_TRANSIT_KEY: &str = "settings-dlx-hot";
const DLX_ARCHIVE_TRANSIT_KEY: &str = "settings-dlx-archive";
static UNIQUE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceCase {
    InputReady,
    L2Join,
    Sigkill,
    Sigterm,
}

impl EvidenceCase {
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::InputReady => "SETTINGSONLY-T3-INPUT-READY-01",
            Self::L2Join => "SETTINGSONLY-T3-L2-JOIN-01",
            Self::Sigkill => "SETTINGSONLY-T3-SIGKILL-01",
            Self::Sigterm => "SETTINGSONLY-T3-SIGTERM-01",
        }
    }

    #[allow(dead_code, reason = "source-level artifact inventory projection")]
    pub(crate) const fn test_name(self) -> &'static str {
        match self {
            Self::InputReady => "settingsonly_image_mount_spiffe_readiness_join",
            Self::L2Join => "settingsonly_image_pg_outbox_amqp_inbox_join",
            Self::Sigkill => "settingsonly_image_sigkill_redelivery_join",
            Self::Sigterm => "settingsonly_image_sigterm_drain_join",
        }
    }

    async fn dispatch(self, fixture: &mut Fixture) -> anyhow::Result<CaseCompletion> {
        match self {
            Self::InputReady => fixture.input_ready().await,
            Self::L2Join => fixture.l2_join().await,
            Self::Sigkill => fixture.sigkill().await,
            Self::Sigterm => fixture.sigterm().await,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Fixture,
    Image,
    Ready,
    Published,
    Unacked,
    Killed,
    Inflight,
    Drained,
}

#[derive(Clone, Copy)]
enum BrokerDelivery {
    Unacked,
    Ready,
    Empty,
}

struct ReadyReceipt(());
struct RejectedReceipt {
    key: String,
    event_id: String,
}
struct RejectedNoEffectReceipt {
    key: String,
    event_id: String,
}
struct DeniedReceipt {
    key: String,
    event_id: String,
}
struct DeniedNoEffectReceipt(());
struct TerminalReceipt {
    event_id: String,
}
struct UnackedReceipt {
    event_id: String,
    barrier: InboxBarrier,
}
struct KilledReceipt {
    event_id: String,
    barrier: InboxBarrier,
}
struct InflightReceipt {
    event_id: String,
    barrier: InboxBarrier,
}
struct DrainedReceipt(FrontendAddresses);
struct CaseCompletion {
    case: EvidenceCase,
}

pub(crate) async fn run_case(case: EvidenceCase) -> anyhow::Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("journeys crate must have a repository parent")?;
    let mut fixture = Fixture::start(repository, case.id()).await?;
    let result = case.dispatch(&mut fixture).await.and_then(|completion| {
        ensure!(completion.case == case, "case completion identity drift");
        Ok(())
    });
    fixture.finish(result).await
}

struct Fixture {
    evidence_id: &'static str,
    phase: Phase,
    root: Option<FixtureRoot>,
    cleanup: CleanupSupervisor,
    _postgres: PgTlsFixture,
    _redis: RedisTlsFixture,
    _rabbit: RabbitTlsFixture,
    rabbit_container: String,
    _vault: VaultTlsFixture,
    _minio: MinioTlsFixture,
    pool: PgPool,
    image: Option<ProductionImage>,
    workload: WorkloadApi,
    ingress: WorkloadApi,
    denied_ingress: WorkloadApi,
    client: reqwest::Client,
    denied_client: reqwest::Client,
    token: String,
    files: FixtureFiles,
    process: Option<ImageProcess>,
}

struct BootstrapProviders {
    postgres: PgTlsFixture,
    redis: RedisTlsFixture,
    rabbit: RabbitTlsFixture,
    rabbit_container: String,
    vault: VaultTlsFixture,
    minio: MinioTlsFixture,
}

impl BootstrapProviders {
    async fn start(cleanup: &mut CleanupSupervisor) -> anyhow::Result<Self> {
        let postgres = postgres_tls().await.context("start PostgreSQL TLS")?;
        cleanup.record_published_container(postgres.params().port, "postgres:16-alpine")?;
        let redis = redis_tls().await.context("start Redis TLS")?;
        cleanup.record_published_container(endpoint_port(redis.url())?, "redis:7.4-alpine")?;
        let rabbit = start_rabbit().await.context("start RabbitMQ TLS")?;
        let rabbit_container = cleanup.record_published_container(
            endpoint_port(rabbit.publisher_url())?,
            "rabbitmq:3.13.6-management-alpine",
        )?;
        let vault = vault_tls().await.context("start Vault TLS")?;
        cleanup.record_published_container(
            endpoint_port(vault.endpoint_url())?,
            "hashicorp/vault:1.17.6",
        )?;
        let minio = minio_tls_archive().await.context("start MinIO TLS")?;
        cleanup.record_published_container(
            endpoint_port(minio.workload().endpoint_url())?,
            "minio/minio:RELEASE.2025-02-28T09-55-16Z",
        )?;
        Ok(Self {
            postgres,
            redis,
            rabbit,
            rabbit_container,
            vault,
            minio,
        })
    }
}

impl Fixture {
    async fn start(repository: &Path, evidence_id: &'static str) -> anyhow::Result<Self> {
        Self::start_inner(repository, evidence_id)
            .await
            .with_context(|| {
                format!(
                    "{evidence_id}: fixture startup failed; phase={:?}",
                    Phase::Fixture
                )
            })
    }

    async fn start_inner(repository: &Path, evidence_id: &'static str) -> anyhow::Result<Self> {
        let repository = repository.canonicalize()?;
        let root = FixtureRoot::create()?;
        let mut cleanup = CleanupSupervisor::start(&root)?;
        let providers = BootstrapProviders::start(&mut cleanup).await?;
        let ports = RuntimePorts::allocate()?;
        let network = ProviderNetwork::start(&root, &providers, &mut cleanup).await?;
        let files = FixtureFiles::create(&root, &providers, &network, ports)?;
        let pool = connect_owner(&providers.postgres, files.postgres_ca()).await?;
        sqlx::migrate!("../adapters/postgres/migrations")
            .run(&pool)
            .await
            .context("run PostgreSQL migrations")?;
        register_projection_generation(&pool).await?;
        provision_roles(&providers.postgres).await?;
        let vault_tokens = provision_vault(&providers.vault).await?;
        let issued_at = runtime::support::SystemClock
            .now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        let federated = FederatedInput::new(issued_at)?;
        files.write_instance(
            &providers.rabbit,
            &providers.redis,
            &providers.minio,
            &vault_tokens,
            &federated,
        )?;
        let identities =
            IdentitySet::generate(SPIFFE_ID, INGRESS_SPIFFE_ID, DENIED_INGRESS_SPIFFE_ID)?;
        let ingress = WorkloadApi::start_host(identities.ingress).await?;
        let client = mtls_client(ingress.endpoint()).await?;
        let denied_ingress = WorkloadApi::start_host(identities.denied_ingress).await?;
        let denied_client = mtls_client(denied_ingress.endpoint()).await?;
        let workload = WorkloadApi::start(identities.workload, &root, &mut cleanup).await?;
        let image = ProductionImage::build(&repository, &mut cleanup).await?;
        let mut fixture = Self {
            evidence_id,
            phase: Phase::Fixture,
            root: Some(root),
            cleanup,
            _postgres: providers.postgres,
            _redis: providers.redis,
            _rabbit: providers.rabbit,
            rabbit_container: providers.rabbit_container,
            _vault: providers.vault,
            _minio: providers.minio,
            pool,
            image: Some(image),
            workload,
            ingress,
            denied_ingress,
            client,
            denied_client,
            token: federated.token,
            files,
            process: None,
        };
        fixture.spawn().await?;
        Ok(fixture)
    }

    async fn input_ready(&mut self) -> anyhow::Result<CaseCompletion> {
        self.workload.wait_request().await?;
        let rejected = self.assert_business_not_accepting().await?;
        let rejected = self.prove_rejected_no_effect(rejected).await?;
        self.workload.release_identity()?;
        let ready = self.wait_ready().await?;
        let rejected = self.prove_rejection_remains_no_effect(rejected).await?;
        let denied = self.assert_denied_identity_not_accepted().await?;
        let denied = self.prove_denied_no_effect(denied).await?;
        let event_id = self
            .publish("artifact.input-ready", "artifact-input-ready-value")
            .await?;
        let terminal = self.wait_terminal(&event_id).await?;
        self.assert_single_durable_effect("artifact.input-ready", &event_id)
            .await?;
        self.inspect_runtime_boundary().await?;
        Ok(Self::complete_input_ready(
            ready, rejected, denied, terminal,
        ))
    }

    async fn l2_join(&mut self) -> anyhow::Result<CaseCompletion> {
        self.workload.release_identity()?;
        let _ready = self.wait_ready().await?;
        let event_id = self.publish("artifact.l2", "artifact-l2-value").await?;
        let terminal: TerminalReceipt = self.wait_terminal(&event_id).await?;
        ensure!(
            terminal.event_id == event_id,
            "terminal receipt identity drift"
        );
        self.assert_single_durable_effect("artifact.l2", &event_id)
            .await?;
        Ok(Self::complete_l2(terminal))
    }

    async fn sigkill(&mut self) -> anyhow::Result<CaseCompletion> {
        self.workload.release_identity()?;
        let _ready = self.wait_ready().await?;
        let event_id = event_id("artifact.sigkill");
        let barrier = InboxBarrier::install(&self.pool, &event_id).await?;
        let published = self
            .publish("artifact.sigkill", "artifact-sigkill-value")
            .await?;
        ensure!(published == event_id, "event identity drift");
        let receipt = self.observe_unacked(event_id, barrier).await?;
        let killed = self.kill_unacked(receipt).await?;
        let terminal = self.restart_killed(killed).await?;
        Ok(Self::complete_sigkill(terminal))
    }

    async fn sigterm(&mut self) -> anyhow::Result<CaseCompletion> {
        self.workload.release_identity()?;
        let _ready = self.wait_ready().await?;
        let event_id = event_id("artifact.sigterm");
        let barrier = InboxBarrier::install(&self.pool, &event_id).await?;
        let published = self
            .publish("artifact.sigterm", "artifact-sigterm-value")
            .await?;
        ensure!(published == event_id, "event identity drift");
        let inflight = self.observe_inflight(event_id, barrier).await?;
        let drained = self.drain_inflight(inflight).await?;
        let drained = self.assert_drained(drained).await?;
        Ok(Self::complete_sigterm(drained))
    }

    async fn spawn(&mut self) -> anyhow::Result<()> {
        ensure!(self.process.is_none(), "image process is already owned");
        let image = self
            .image
            .as_ref()
            .context("production image unavailable")?;
        let process = image
            .spawn(
                &self.files,
                self.workload.volume_mount()?,
                &mut self.cleanup,
            )
            .await
            .with_context(|| self.failure("spawn exact production image"))?;
        self.process = Some(process);
        self.phase = Phase::Image;
        Ok(())
    }

    async fn assert_business_not_accepting(&self) -> anyhow::Result<RejectedReceipt> {
        let key = "artifact.not-ready".to_owned();
        let event_id = event_id(&key);
        let primary = self
            .process
            .as_ref()
            .context("image process unavailable")?
            .frontends
            .primary;
        let result = self
            .client
            .post(format!("https://{primary}/api/v1/settings/configs"))
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(json!({"key":key, "value":"blocked"}).to_string())
            .timeout(Duration::from_secs(2))
            .send()
            .await;
        match result {
            Err(error) if error.is_connect() && !error.is_timeout() => {}
            Err(error) => anyhow::bail!(
                "{}: pre-ready mutation did not fail with a closed connection: {error}; phase={:?}",
                self.evidence_id,
                self.phase
            ),
            Ok(response) => {
                let status = response.status();
                let body = response.bytes().await.context("read pre-ready rejection")?;
                let envelope: Value = serde_json::from_slice(&body)
                    .context("pre-ready 503 omitted canonical JSON error envelope")?;
                ensure!(
                    status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                        && envelope.pointer("/error/code").and_then(Value::as_str)
                            == Some("ERR_CORE_UNAVAILABLE"),
                    "{}: pre-ready mutation returned non-closed response {status}: {}",
                    self.evidence_id,
                    String::from_utf8_lossy(&body)
                );
            }
        }
        Ok(RejectedReceipt { key, event_id })
    }

    async fn prove_rejected_no_effect(
        &self,
        receipt: RejectedReceipt,
    ) -> anyhow::Result<RejectedNoEffectReceipt> {
        self.assert_no_durable_effect(&receipt.key, &receipt.event_id)
            .await?;
        Ok(RejectedNoEffectReceipt {
            key: receipt.key,
            event_id: receipt.event_id,
        })
    }

    async fn prove_rejection_remains_no_effect(
        &self,
        receipt: RejectedNoEffectReceipt,
    ) -> anyhow::Result<RejectedNoEffectReceipt> {
        self.assert_no_durable_effect(&receipt.key, &receipt.event_id)
            .await?;
        Ok(receipt)
    }

    async fn assert_denied_identity_not_accepted(&self) -> anyhow::Result<DeniedReceipt> {
        let key = "artifact.denied-ingress".to_owned();
        let event_id = event_id(&key);
        let primary = self
            .process
            .as_ref()
            .context("image process unavailable")?
            .frontends
            .primary;
        let result = self
            .denied_client
            .post(format!("https://{primary}/api/v1/settings/configs"))
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(json!({"key":key, "value":"must-not-commit"}).to_string())
            .timeout(Duration::from_secs(2))
            .send()
            .await;
        match result {
            Err(error) if error.is_connect() && !error.is_timeout() => {}
            Err(error) => anyhow::bail!(
                "{}: denied SPIFFE identity did not fail at the mTLS connection boundary: {error}",
                self.evidence_id
            ),
            Ok(response) => anyhow::bail!(
                "{}: denied SPIFFE identity reached HTTP and returned {}",
                self.evidence_id,
                response.status()
            ),
        }
        Ok(DeniedReceipt { key, event_id })
    }

    async fn prove_denied_no_effect(
        &self,
        receipt: DeniedReceipt,
    ) -> anyhow::Result<DeniedNoEffectReceipt> {
        self.assert_no_durable_effect(&receipt.key, &receipt.event_id)
            .await?;
        Ok(DeniedNoEffectReceipt(()))
    }

    async fn wait_ready(&mut self) -> anyhow::Result<ReadyReceipt> {
        let health = self
            .process
            .as_ref()
            .context("image process unavailable")?
            .frontends
            .health;
        let url = format!("http://{health}/health/v1/readyz");
        let evidence = self.evidence_id;
        let process = self.process.as_mut().context("image process unavailable")?;
        let body = tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                process.ensure_running()?;
                if let Ok(response) = reqwest::get(&url).await
                    && response.status().is_success()
                {
                    return response.bytes().await.context("read readiness response");
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .with_context(|| format!("{evidence}: readiness timed out; {}", process.diagnostics()))??;
        let response: Readyz =
            serde_json::from_slice(&body).context("decode readiness response")?;
        ensure!(
            response.overall == "healthy",
            "readyz aggregate was {}",
            response.overall
        );
        let expected: HashSet<&str> = settingsonly::test_support::production_required_probe_names()
            .into_iter()
            .collect();
        let observed: HashSet<&str> = response
            .checks
            .iter()
            .filter(|check| check.status == "healthy")
            .map(|check| check.name.as_str())
            .collect();
        ensure!(
            response.checks.len() == expected.len()
                && observed.len() == response.checks.len()
                && observed == expected,
            "readyz required-probe closure drift: expected={expected:?} observed={observed:?} body={}",
            String::from_utf8_lossy(&body)
        );
        self.phase = Phase::Ready;
        Ok(ReadyReceipt(()))
    }

    async fn inspect_runtime_boundary(&mut self) -> anyhow::Result<()> {
        let process = self.process.as_ref().context("image process unavailable")?;
        let output = docker_output([
            "inspect",
            "--type",
            "container",
            "--format",
            r#"{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{json .Config.User}}|{{json .Path}}|{{json .HostConfig.ReadonlyRootfs}}|{{json .Mounts}}"#,
            process.name(),
        ])
        .await?;
        let boundary = String::from_utf8(output.stdout)?;
        ensure!(
            boundary.contains(r#"["/usr/local/bin/settingsonly-server"]"#)
                && boundary.contains("65532")
                && boundary.contains("\"/usr/local/bin/settingsonly-server\"|true|"),
            "OCI runtime boundary drift: {boundary}"
        );
        let mounts_json = boundary
            .trim_end()
            .rsplit_once('|')
            .map(|(_, mounts)| mounts)
            .context("OCI inspect omitted mounts")?;
        let mounts: Vec<RuntimeMount> = serde_json::from_str(mounts_json)?;
        ensure!(
            mounts.len() == 4,
            "runtime mount set was not closed: {mounts_json}"
        );
        for (destination, source) in [
            ("/fixtures", self.files.public_path.display().to_string()),
            (SECRET_PATH, self.files.secret_path.display().to_string()),
            ("/etc/hosts", self.files.hosts_path.display().to_string()),
        ] {
            ensure!(
                mounts.iter().any(|mount| mount.destination == destination
                    && mount.source == Path::new(&source)
                    && !mount.rw),
                "runtime omitted exact read-only mount {} -> {destination}: {mounts_json}",
                source
            );
        }
        let workload_source = self.workload.mount_source()?;
        ensure!(
            mounts
                .iter()
                .any(|mount| mount.destination == WORKLOAD_DIRECTORY
                    && mount.name.as_deref() == Some(workload_source)
                    && !mount.rw),
            "runtime omitted exact read-only SPIFFE volume {workload_source}: {mounts_json}"
        );
        self.inspect_network_boundary(process.name()).await?;
        Ok(())
    }

    async fn inspect_network_boundary(&self, container: &str) -> anyhow::Result<()> {
        let ports_output = docker_output([
            "inspect",
            "--format",
            "{{json .NetworkSettings.Ports}}",
            container,
        ])
        .await?;
        let published: Value = serde_json::from_slice(&ports_output.stdout)?;
        let published = published
            .as_object()
            .context("runtime published-port map was not an object")?;
        let expected: HashSet<String> = self
            .files
            .ports
            .frontends()
            .into_iter()
            .map(|port| format!("{port}/tcp"))
            .collect();
        let externally_bound: HashSet<String> = published
            .iter()
            .filter(|(_, bindings)| bindings.as_array().is_some_and(|items| !items.is_empty()))
            .map(|(key, _)| key.clone())
            .collect();
        ensure!(
            externally_bound == expected,
            "runtime published-port set was not exact: {}",
            Value::Object(published.clone())
        );
        for (key, bindings) in published
            .iter()
            .filter(|(_, bindings)| bindings.as_array().is_some_and(|items| !items.is_empty()))
        {
            let binding = bindings
                .as_array()
                .and_then(|items| items.first())
                .context("published frontend omitted its host binding")?;
            ensure!(
                binding.get("HostIp").and_then(Value::as_str) == Some("127.0.0.1")
                    && binding
                        .get("HostPort")
                        .and_then(Value::as_str)
                        .is_some_and(|port| port.parse::<u16>().is_ok_and(|port| port != 0)),
                "frontend {key} was not dynamically loopback-published: {binding}"
            );
        }
        let networks = docker_output([
            "inspect",
            "--format",
            "{{json .NetworkSettings.Networks}}",
            container,
        ])
        .await?;
        let networks = String::from_utf8(networks.stdout)?;
        ensure!(
            networks.contains(&self.files.network_name)
                && networks.contains(&self.files.network_alias)
                && !networks.contains("\"host\""),
            "runtime network ownership/alias drift: {networks}"
        );
        for backend in self.files.ports.backends() {
            let key = format!("{backend}/tcp");
            let mut command = Command::new("docker");
            command.args(["port", container, &key]);
            let output = run_command(command, Duration::from_secs(5)).await?;
            ensure!(
                !output.status.success() && output.stdout.is_empty(),
                "raw backend {key} was published to the test client"
            );
            let directly_reachable = tokio::time::timeout(
                Duration::from_millis(250),
                TcpStream::connect((Ipv4Addr::LOCALHOST, backend)),
            )
            .await
            .is_ok_and(|result| result.is_ok());
            ensure!(
                !directly_reachable,
                "raw backend port {backend} was directly reachable from the test client"
            );
        }
        Ok(())
    }

    async fn publish(&mut self, key: &str, value: &str) -> anyhow::Result<String> {
        let primary = self
            .process
            .as_ref()
            .context("image process unavailable")?
            .frontends
            .primary;
        let response = self
            .client
            .post(format!("https://{primary}/api/v1/settings/configs"))
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(json!({"key": key, "value": value}).to_string())
            .send()
            .await
            .with_context(|| self.failure("publish Settings config"))?;
        let status = response.status();
        let body = response.bytes().await?;
        ensure!(
            status == reqwest::StatusCode::CREATED,
            "publish returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
        let receipt: PublishResponse = serde_json::from_slice(&body)?;
        ensure!(
            receipt.data.key == key && receipt.data.version == 1,
            "publish receipt drift"
        );
        self.phase = Phase::Published;
        Ok(event_id(key))
    }

    async fn wait_terminal(&mut self, event_id: &str) -> anyhow::Result<TerminalReceipt> {
        self.wait_db(event_id, "done").await?;
        self.wait_broker_delivery(event_id, BrokerDelivery::Empty)
            .await?;
        self.phase = Phase::Published;
        Ok(TerminalReceipt {
            event_id: event_id.to_owned(),
        })
    }

    async fn wait_claimed(&mut self, event_id: &str) -> anyhow::Result<()> {
        self.wait_db(event_id, "claimed").await
    }

    async fn observe_unacked(
        &mut self,
        event_id: String,
        barrier: InboxBarrier,
    ) -> anyhow::Result<UnackedReceipt> {
        self.wait_claimed(&event_id).await?;
        self.wait_broker_delivery(&event_id, BrokerDelivery::Unacked)
            .await?;
        self.phase = Phase::Unacked;
        Ok(UnackedReceipt { event_id, barrier })
    }

    async fn observe_inflight(
        &mut self,
        event_id: String,
        barrier: InboxBarrier,
    ) -> anyhow::Result<InflightReceipt> {
        self.wait_claimed(&event_id).await?;
        barrier.wait_for_waiter(&self.pool).await?;
        self.phase = Phase::Inflight;
        Ok(InflightReceipt { event_id, barrier })
    }

    async fn wait_broker_delivery(
        &self,
        event_id: &str,
        wanted: BrokerDelivery,
    ) -> anyhow::Result<()> {
        let mut observed = "unobserved".to_owned();
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                let output = docker_output([
                    "exec",
                    &self.rabbit_container,
                    "rabbitmqctl",
                    "-q",
                    "list_queues",
                    "-p",
                    "rss_acl",
                    "name",
                    "messages_ready",
                    "messages_unacknowledged",
                    "--formatter",
                    "json",
                ])
                .await?;
                let queues: Value = serde_json::from_slice(&output.stdout)?;
                let queue = queues
                    .as_array()
                    .and_then(|rows| {
                        rows.iter().find(|row| {
                            row.get("name").and_then(Value::as_str) == Some(SETTINGS_TOPIC)
                        })
                    })
                    .context("exact Settings queue omitted from RabbitMQ state")?;
                let ready = queue
                    .get("messages_ready")
                    .and_then(Value::as_u64)
                    .context("RabbitMQ omitted messages_ready")?;
                let unacked = queue
                    .get("messages_unacknowledged")
                    .and_then(Value::as_u64)
                    .context("RabbitMQ omitted messages_unacknowledged")?;
                observed = format!("ready={ready}, unacked={unacked}");
                let matched = match wanted {
                    BrokerDelivery::Unacked => unacked == 1,
                    BrokerDelivery::Ready => ready == 1 && unacked == 0,
                    BrokerDelivery::Empty => ready == 0 && unacked == 0,
                };
                if matched {
                    return anyhow::Ok(());
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .with_context(|| {
            format!(
                "{}: broker delivery barrier timed out for {event_id}; observed={observed}",
                self.evidence_id
            )
        })??;
        Ok(())
    }

    async fn wait_db(&mut self, event_id: &str, wanted: &str) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        let evidence = self.evidence_id;
        let process = self.process.as_mut().context("image process unavailable")?;
        let mut last = "missing".to_owned();
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                process.ensure_running()?;
                let row = sqlx::query(
                    "SELECT status, receive_count FROM inbox_receipts WHERE event_id = $1",
                )
                .bind(event_id)
                .fetch_optional(&pool)
                .await?;
                if let Some(row) = row {
                    let status: String = row.try_get("status")?;
                    let count: i32 = row.try_get("receive_count")?;
                    last = format!("status={status}, receive_count={count}");
                    if status == wanted {
                        return anyhow::Ok(());
                    }
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .with_context(|| {
            format!(
                "{evidence}: inbox wait timed out; expected={wanted}; observed={last}; {}",
                process.diagnostics()
            )
        })??;
        Ok(())
    }

    async fn assert_single_durable_effect(&self, key: &str, event_id: &str) -> anyhow::Result<()> {
        let (configs, outbox, inbox): (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 AND version = 1 AND deleted = false), (SELECT count(*) FROM outbox WHERE event_id = $3 AND status = 'published'), (SELECT count(*) FROM inbox_receipts WHERE event_id = $3 AND status = 'done')",
        )
        .bind(TENANT)
        .bind(key)
        .bind(event_id)
        .fetch_one(&self.pool)
        .await?;
        ensure!(
            configs == 1 && outbox == 1 && inbox == 1,
            "durable producer effect was not unique after redelivery: config={configs} outbox={outbox} inbox={inbox} event_id={event_id}"
        );
        Ok(())
    }

    async fn assert_no_durable_effect(&self, key: &str, event_id: &str) -> anyhow::Result<()> {
        let (configs, outbox, inbox): (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2), (SELECT count(*) FROM outbox WHERE event_id = $3), (SELECT count(*) FROM inbox_receipts WHERE event_id = $3)",
        )
        .bind(TENANT)
        .bind(key)
        .bind(event_id)
        .fetch_one(&self.pool)
        .await?;
        ensure!(
            configs == 0 && outbox == 0 && inbox == 0,
            "durable no-effect violated: config={configs} outbox={outbox} inbox={inbox} key={key} event_id={event_id}"
        );
        Ok(())
    }

    async fn kill_unacked(&mut self, mut receipt: UnackedReceipt) -> anyhow::Result<KilledReceipt> {
        let mut process = self.process.take().context("image process unavailable")?;
        let frontends = process.frontends;
        process.signal("KILL").await?;
        let status = process.wait().await?;
        ensure!(
            !status.success(),
            "SIGKILL unexpectedly exited successfully"
        );
        wait_frontends_unreachable(frontends).await?;
        self.wait_broker_delivery(&receipt.event_id, BrokerDelivery::Ready)
            .await?;
        receipt.barrier.release().await?;
        self.phase = Phase::Killed;
        Ok(KilledReceipt {
            event_id: receipt.event_id,
            barrier: receipt.barrier,
        })
    }

    async fn restart_killed(&mut self, receipt: KilledReceipt) -> anyhow::Result<TerminalReceipt> {
        self.spawn().await?;
        let _ready = self.wait_ready().await?;
        let terminal: TerminalReceipt = self.wait_terminal(&receipt.event_id).await?;
        ensure!(
            terminal.event_id == receipt.event_id,
            "terminal receipt identity drift"
        );
        receipt.barrier.remove(&self.pool).await?;
        self.assert_single_durable_effect("artifact.sigkill", &receipt.event_id)
            .await?;
        Ok(terminal)
    }

    async fn drain_inflight(
        &mut self,
        mut receipt: InflightReceipt,
    ) -> anyhow::Result<DrainedReceipt> {
        let process = self.process.as_mut().context("image process unavailable")?;
        process.signal("TERM").await?;
        wait_listener_closed(
            &self.client,
            self.process
                .as_ref()
                .context("image process unavailable")?
                .frontends
                .primary,
        )
        .await?;
        receipt.barrier.release().await?;
        self.wait_db_after_signal(&receipt.event_id, "done").await?;
        self.wait_broker_delivery(&receipt.event_id, BrokerDelivery::Empty)
            .await?;
        let mut process = self.process.take().context("image process unavailable")?;
        let frontends = process.frontends;
        let status = process.wait().await?;
        ensure!(
            status.success(),
            "SIGTERM process exited with {status}; {}",
            process.diagnostics()
        );
        receipt.barrier.remove(&self.pool).await?;
        self.phase = Phase::Drained;
        Ok(DrainedReceipt(frontends))
    }

    async fn wait_db_after_signal(&self, event_id: &str, wanted: &str) -> anyhow::Result<()> {
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                let status: Option<String> =
                    sqlx::query_scalar("SELECT status FROM inbox_receipts WHERE event_id = $1")
                        .bind(event_id)
                        .fetch_optional(&self.pool)
                        .await?;
                if status.as_deref() == Some(wanted) {
                    return anyhow::Ok(());
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .context("inflight transaction did not complete during drain")??;
        Ok(())
    }

    async fn assert_drained(&self, receipt: DrainedReceipt) -> anyhow::Result<DrainedReceipt> {
        for address in [receipt.0.primary, receipt.0.admin, receipt.0.health] {
            ensure!(
                TcpStream::connect(address).await.is_err(),
                "published mTLS listener {address} remained reachable"
            );
        }
        Ok(receipt)
    }

    fn complete_input_ready(
        _ready: ReadyReceipt,
        _rejected: RejectedNoEffectReceipt,
        _denied: DeniedNoEffectReceipt,
        _terminal: TerminalReceipt,
    ) -> CaseCompletion {
        CaseCompletion {
            case: EvidenceCase::InputReady,
        }
    }

    fn complete_l2(_terminal: TerminalReceipt) -> CaseCompletion {
        CaseCompletion {
            case: EvidenceCase::L2Join,
        }
    }

    fn complete_sigkill(_terminal: TerminalReceipt) -> CaseCompletion {
        CaseCompletion {
            case: EvidenceCase::Sigkill,
        }
    }

    fn complete_sigterm(_drained: DrainedReceipt) -> CaseCompletion {
        CaseCompletion {
            case: EvidenceCase::Sigterm,
        }
    }

    fn failure(&self, action: &str) -> String {
        format!(
            "{}: {action}; phase={:?}; {}",
            self.evidence_id,
            self.phase,
            self.process.as_ref().map_or_else(
                || "logs=<unavailable>".to_owned(),
                ImageProcess::diagnostics
            )
        )
    }

    async fn finish(mut self, result: anyhow::Result<()>) -> anyhow::Result<()> {
        let failure = self.failure("case failed");
        let mut errors = Vec::new();
        if let Some(mut process) = self.process.take()
            && let Err(error) = process.force_cleanup().await
        {
            errors.push(format!("stop image: {error:#}"));
        }
        errors.extend(self.close_spiffe_fixtures().await);
        if let Some(image) = self.image.take()
            && let Err(error) = image.remove().await
        {
            errors.push(format!("remove image: {error:#}"));
        }
        if tokio::time::timeout(Duration::from_secs(10), self.pool.close())
            .await
            .is_err()
        {
            errors.push("close PostgreSQL owner pool: timed out after 10s".to_owned());
        }
        if let Err(error) = self.cleanup.cleanup().await {
            errors.push(format!("remove owned Docker resources: {error:#}"));
        }
        if let Some(root) = self.root.take()
            && let Err(error) = root.remove()
        {
            errors.push(format!("remove fixture root: {error:#}"));
        }
        match (result, errors.is_empty()) {
            (Ok(()), true) => Ok(()),
            (Ok(()), false) => anyhow::bail!(
                "{}: cleanup failed: {}",
                self.evidence_id,
                errors.join("; ")
            ),
            (Err(error), true) => Err(error).context(failure),
            (Err(error), false) => Err(error).with_context(|| {
                format!("{}; cleanup also failed: {}", failure, errors.join("; "))
            }),
        }
    }

    async fn close_spiffe_fixtures(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        if let Err(error) = self.workload.close().await {
            errors.push(format!("stop SPIFFE fixture: {error:#}"));
        }
        if let Err(error) = self.ingress.close().await {
            errors.push(format!("stop ingress SPIFFE fixture: {error:#}"));
        }
        if let Err(error) = self.denied_ingress.close().await {
            errors.push(format!("stop denied ingress SPIFFE fixture: {error:#}"));
        }
        errors
    }
}

async fn start_rabbit() -> anyhow::Result<RabbitTlsFixture> {
    let mut last = None;
    for _attempt in 0..3 {
        match rabbitmq_tls(SETTINGS_TOPIC).await {
            Ok(rabbit) => return Ok(rabbit),
            Err(error) => {
                last = Some(error);
                tokio::task::yield_now().await;
            }
        }
    }
    match last {
        Some(error) => Err(error),
        None => anyhow::bail!("RabbitMQ fixture made no startup attempt"),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Readyz {
    overall: String,
    checks: Vec<ReadyCheck>,
}

#[derive(Deserialize)]
struct RuntimeMount {
    #[serde(rename = "Name", default)]
    name: Option<String>,
    #[serde(rename = "Source")]
    source: PathBuf,
    #[serde(rename = "Destination")]
    destination: String,
    #[serde(rename = "RW")]
    rw: bool,
}

#[derive(Deserialize)]
struct ReadyCheck {
    name: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishResponse {
    data: PublishData,
}

#[derive(Deserialize)]
struct PublishData {
    key: String,
    version: i64,
}

fn event_id(key: &str) -> String {
    format!("{SETTINGS_TOPIC}:{TENANT}:{key}:v1")
}

async fn wait_listener_closed(client: &reqwest::Client, address: SocketAddr) -> anyhow::Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if client
                .get(format!("https://{address}/"))
                .send()
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .with_context(|| format!("listener {address} did not stop accepting"))
}

async fn wait_frontends_unreachable(frontends: FrontendAddresses) -> anyhow::Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if futures::future::join_all([
                TcpStream::connect(frontends.primary),
                TcpStream::connect(frontends.admin),
                TcpStream::connect(frontends.health),
            ])
            .await
            .into_iter()
            .all(|connection| connection.is_err())
            {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .context("published runtime ports were not released after SIGKILL")
}

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn create() -> anyhow::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "rss-settingsonly-artifact-{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(path))
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn remove(self) -> anyhow::Result<()> {
        fs::remove_dir_all(&self.0).context("remove SettingsOnly fixture root")
    }
}

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.0);
    }
}

enum CleanupResource {
    Container(String),
    Volume(String),
    Network(String),
    Image(String),
}

impl CleanupResource {
    fn manifest_line(&self) -> String {
        match self {
            Self::Container(value) => format!("container {value}\n"),
            Self::Volume(value) => format!("volume {value}\n"),
            Self::Network(value) => format!("network {value}\n"),
            Self::Image(value) => format!("image {value}\n"),
        }
    }

    fn docker_args(&self) -> [&str; 3] {
        match self {
            Self::Container(value) => ["rm", "--force", value],
            Self::Volume(value) => ["volume", "rm", value],
            Self::Network(value) => ["network", "rm", value],
            Self::Image(value) => ["image", "rm", value],
        }
    }

    const fn cleanup_phase(&self) -> u8 {
        match self {
            Self::Container(_) => 0,
            Self::Volume(_) => 1,
            Self::Network(_) => 2,
            Self::Image(_) => 3,
        }
    }
}

/// A process-external owner for exact Docker objects created by this fixture.
///
/// CI already has scope-label cleanup, but local command timeouts kill the Rust test before async
/// destructors can run. This tiny watchdog consumes only exact IDs resolved by published port or
/// collision-resistant names reserved before creation; it never scans or deletes by image/prefix.
struct CleanupSupervisor {
    manifest: PathBuf,
    child: Option<Child>,
    resources: Vec<CleanupResource>,
}

impl CleanupSupervisor {
    fn start(root: &FixtureRoot) -> anyhow::Result<Self> {
        let manifest = root.join("owned-docker-resources");
        File::create(&manifest)?;
        let script = r#"
parent="$1"
manifest="$2"
root="$3"
while kill -0 "$parent" 2>/dev/null; do sleep 1; done
for wanted in container volume network image; do
  while read -r kind value; do
    test "$kind" = "$wanted" || continue
    case "$kind" in
      container) docker rm --force "$value" >/dev/null 2>&1 || true ;;
      volume) docker volume rm "$value" >/dev/null 2>&1 || true ;;
      network) docker network rm "$value" >/dev/null 2>&1 || true ;;
      image) docker image rm "$value" >/dev/null 2>&1 || true ;;
    esac
  done < "$manifest"
done
rm -f "$manifest"
rm -rf -- "$root"
"#;
        let child = Command::new("/bin/sh")
            .args([
                "-c",
                script,
                "settingsonly-cleanup-watch",
                &std::process::id().to_string(),
                manifest
                    .to_str()
                    .context("cleanup manifest path is not UTF-8")?,
                root.0
                    .to_str()
                    .context("cleanup fixture root path is not UTF-8")?,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn exact-resource cleanup watchdog")?;
        Ok(Self {
            manifest,
            child: Some(child),
            resources: Vec::new(),
        })
    }

    fn record_published_container(&mut self, port: u16, image: &str) -> anyhow::Result<String> {
        let output = Command::new("docker")
            .args([
                "ps",
                "--filter",
                &format!("publish={port}"),
                "--format",
                "{{.ID}} {{.Image}}",
            ])
            .output()?;
        let output = ensure_success(output, "resolve owned provider container")?;
        let rendered = String::from_utf8_lossy(&output.stdout);
        let matches: Vec<&str> = rendered
            .lines()
            .filter_map(|line| {
                let (id, actual_image) = line.split_once(' ')?;
                (actual_image == image).then_some(id)
            })
            .collect();
        ensure!(
            matches.len() == 1,
            "expected one {image} container publishing {port}, found {}",
            matches.len()
        );
        let id = matches[0].to_owned();
        self.record(CleanupResource::Container(id.clone()))?;
        Ok(id)
    }

    fn record(&mut self, resource: CleanupResource) -> anyhow::Result<()> {
        let line = resource.manifest_line();
        ensure!(
            !line.contains('\t') && !line[..line.len() - 1].contains('\n'),
            "Docker ownership token contains a line break"
        );
        OpenOptions::new()
            .append(true)
            .open(&self.manifest)?
            .write_all(line.as_bytes())?;
        self.resources.push(resource);
        Ok(())
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        let mut failures = Vec::new();
        for phase in 0..=3 {
            for resource in self
                .resources
                .iter()
                .rev()
                .filter(|resource| resource.cleanup_phase() == phase)
            {
                let mut command = Command::new("docker");
                command.args(resource.docker_args());
                match run_command(command, Duration::from_secs(30)).await {
                    Ok(output)
                        if output.status.success()
                            || String::from_utf8_lossy(&output.stderr)
                                .to_ascii_lowercase()
                                .contains("no such") => {}
                    Ok(output) => failures.push(format!(
                        "{:?}: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    )),
                    Err(error) => failures.push(format!("{error:#}")),
                }
            }
        }
        self.resources.clear();
        if let Some(mut child) = self.child.take() {
            let _result = child.kill();
            let _result = child.wait();
        }
        let _result = fs::remove_file(&self.manifest);
        ensure!(failures.is_empty(), "{}", failures.join("; "));
        Ok(())
    }
}

impl Drop for CleanupSupervisor {
    fn drop(&mut self) {
        for phase in 0..=3 {
            for resource in self
                .resources
                .iter()
                .rev()
                .filter(|resource| resource.cleanup_phase() == phase)
            {
                let _output = Command::new("docker")
                    .args(resource.docker_args())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .output();
            }
        }
        if let Some(child) = self.child.as_mut() {
            let _result = child.kill();
            let _result = child.wait();
        }
    }
}

fn endpoint_port(endpoint: &str) -> anyhow::Result<u16> {
    url::Url::parse(endpoint)?
        .port()
        .context("provider endpoint omitted its published port")
}

#[derive(Clone, Copy)]
struct RuntimePorts {
    backend_primary: u16,
    backend_admin: u16,
    backend_health: u16,
    frontend_primary: u16,
    frontend_admin: u16,
    frontend_health: u16,
}

impl RuntimePorts {
    fn allocate() -> anyhow::Result<Self> {
        let mut listeners = Vec::with_capacity(6);
        for _ in 0..6 {
            listeners.push(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?);
        }
        let mut ports = listeners
            .iter()
            .map(|listener| listener.local_addr().map(|address| address.port()));
        let allocated = Self {
            backend_primary: ports.next().context("backend primary port")??,
            backend_admin: ports.next().context("backend admin port")??,
            backend_health: ports.next().context("backend health port")??,
            frontend_primary: ports.next().context("frontend primary port")??,
            frontend_admin: ports.next().context("frontend admin port")??,
            frontend_health: ports.next().context("frontend health port")??,
        };
        drop(listeners);
        Ok(allocated)
    }

    const fn backends(self) -> [u16; 3] {
        [
            self.backend_primary,
            self.backend_admin,
            self.backend_health,
        ]
    }

    const fn frontends(self) -> [u16; 3] {
        [
            self.frontend_primary,
            self.frontend_admin,
            self.frontend_health,
        ]
    }
}

struct ProviderNetwork {
    name: String,
    alias: String,
    hosts_path: PathBuf,
}

impl ProviderNetwork {
    async fn start(
        root: &FixtureRoot,
        providers: &BootstrapProviders,
        cleanup: &mut CleanupSupervisor,
    ) -> anyhow::Result<Self> {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::Relaxed)
        );
        let name = format!("rss-settingsonly-artifact-{suffix}");
        let alias = format!("settingsonly-runtime-{suffix}");
        cleanup.record(CleanupResource::Network(name.clone()))?;
        let mut network = Command::new("docker");
        network.args(["network", "create", "--driver", "bridge"]);
        add_labels(&mut network, false)?;
        network.arg(&name);
        ensure_success(
            run_command(network, Duration::from_secs(30)).await?,
            "create owned SettingsOnly network",
        )?;

        let relay_name = format!("{name}-provider-relay");
        cleanup.record(CleanupResource::Container(relay_name.clone()))?;
        let mut ports = vec![
            providers.postgres.params().port,
            endpoint_port(providers.redis.url())?,
            endpoint_port(providers.rabbit.publisher_url())?,
            endpoint_port(providers.rabbit.subscriber_url())?,
            endpoint_port(providers.vault.endpoint_url())?,
            endpoint_port(providers.minio.workload().endpoint_url())?,
        ];
        ports.sort_unstable();
        ports.dedup();
        let mut script = String::from(
            "set -eu\npids=\"\"\ntrap 'kill $pids 2>/dev/null || true' EXIT HUP INT TERM\n",
        );
        for port in ports {
            script.push_str(&format!(
                "socat TCP4-LISTEN:{port},bind=0.0.0.0,reuseaddr,fork TCP4:host.docker.internal:{port} & pids=\"$pids $!\"\n"
            ));
        }
        script.push_str("wait\n");
        let mut relay = Command::new("docker");
        relay.args([
            "run",
            "--detach",
            "--name",
            &relay_name,
            "--network",
            &name,
            "--network-alias",
            "providers",
            "--add-host",
            "host.docker.internal:host-gateway",
        ]);
        add_labels(&mut relay, false)?;
        relay.args([
            "--entrypoint",
            "/bin/sh",
            "alpine/socat:1.8.0.3",
            "-ec",
            &script,
        ]);
        ensure_success(
            run_command(relay, Duration::from_secs(30)).await?,
            "start owned provider relay",
        )?;
        let inspect = docker_output([
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            &relay_name,
        ])
        .await?;
        let relay_ip = String::from_utf8(inspect.stdout)?.trim().to_owned();
        ensure!(
            !relay_ip.is_empty(),
            "provider relay omitted its network IP"
        );
        let hosts_path = root.join("runtime-hosts");
        fs::write(&hosts_path, format!("{relay_ip} localhost\n"))?;
        Ok(Self {
            name,
            alias,
            hosts_path,
        })
    }
}

struct FixtureFiles {
    public_path: PathBuf,
    secret_path: PathBuf,
    log_path: PathBuf,
    postgres_ca: PathBuf,
    config: String,
    ports: RuntimePorts,
    network_name: String,
    network_alias: String,
    hosts_path: PathBuf,
}

impl FixtureFiles {
    fn create(
        root: &FixtureRoot,
        providers: &BootstrapProviders,
        network: &ProviderNetwork,
        ports: RuntimePorts,
    ) -> anyhow::Result<Self> {
        let public_path = root.join("public");
        let secret_directory = root.join("secret");
        let log_path = root.join("logs");
        fs::create_dir(&public_path)?;
        fs::create_dir(&secret_directory)?;
        fs::create_dir(&log_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&secret_directory, fs::Permissions::from_mode(0o700))?;
        }
        for (name, pem) in [
            ("postgres-ca.pem", providers.postgres.ca_pem()),
            ("redis-ca.pem", providers.redis.ca_pem()),
            ("amqp-ca.pem", providers.rabbit.ca_pem()),
            ("vault-ca.pem", providers.vault.ca_pem()),
            ("s3-ca.pem", providers.minio.ca_pem()),
        ] {
            fs::write(public_path.join(name), pem).with_context(|| format!("write {name}"))?;
        }
        let pg = providers.postgres.params();
        let config = format!(
            r#"schemaVersion = 2
profile = "production"
topology = "durable-isolated"
[listeners]
requestBudgetMs = 15000
[listeners.primary]
bind = "127.0.0.1:{}"
[listeners.admin]
bind = "127.0.0.1:{}"
[listeners.health]
bind = "127.0.0.1:{}"
[federated]
issuer = "{ISSUER}"
audience = "{AUDIENCE}"
jwksPath = "/fixtures/federated.jwks.json"
refreshSeconds = 5
trustedKinds = ["user", "admin"]
[postgres]
host = "{}"
port = {}
database = "{}"
sslMode = "verifyFull"
sslRootCertPath = "/fixtures/postgres-ca.pem"
readinessSeconds = 5
[postgres.writer]
maxConnections = 5
[postgres.reader]
maxConnections = 5
[postgres.dlxArchiver]
maxConnections = 2
[postgres.dlxVerifier]
maxConnections = 2
[postgres.dlxPurger]
maxConnections = 2
[vault]
addr = "{}"
caCertPemPath = "/fixtures/vault-ca.pem"
transitMount = "transit"
settingsKeyName = "{CONFIG_TRANSIT_KEY}"
readinessSeconds = 2
[[vault.tenantStoreAllowlist]]
tenantId = "{TENANT}"
storeId = "vault"
mount = "secret"
kvPathPrefix = "tenants/settings"
[eventing]
amqpCaCertPemPath = "/fixtures/amqp-ca.pem"
publisherConfirmTimeoutMs = 5000
[redis]
caCertPemPath = "/fixtures/redis-ca.pem"
readinessSeconds = 2
[tenantAuthority]
ttlSeconds = 3600
clockSkewSeconds = 60
[dlx]
hotKeyName = "{DLX_HOT_TRANSIT_KEY}"
archiveKeyName = "{DLX_ARCHIVE_TRANSIT_KEY}"
readinessSeconds = 2
[s3]
endpoint = "{}"
region = "us-east-1"
archiveBucket = "{}"
forcePathStyle = true
caCertPemPath = "/fixtures/s3-ca.pem"
readinessSeconds = 2
[readiness]
startupTimeoutSeconds = 60
[drain]
totalSeconds = 60
"#,
            ports.backend_primary,
            ports.backend_admin,
            ports.backend_health,
            pg.host,
            pg.port,
            pg.database,
            providers.vault.endpoint_url(),
            providers.minio.workload().endpoint_url(),
            providers.minio.archive_bucket(),
        );
        Ok(Self {
            public_path,
            secret_path: secret_directory.join("serving-secret-bundle"),
            log_path,
            postgres_ca: root.join("public/postgres-ca.pem"),
            config,
            ports,
            network_name: network.name.clone(),
            network_alias: network.alias.clone(),
            hosts_path: network.hosts_path.clone(),
        })
    }

    fn postgres_ca(&self) -> &Path {
        &self.postgres_ca
    }

    fn write_instance(
        &self,
        rabbit: &RabbitTlsFixture,
        redis: &RedisTlsFixture,
        minio: &MinioTlsFixture,
        vault: &VaultTokens,
        federated: &FederatedInput,
    ) -> anyhow::Result<()> {
        fs::write(self.public_path.join("settingsonly.toml"), &self.config)?;
        fs::write(
            self.public_path.join("federated.jwks.json"),
            &federated.jwks,
        )?;
        let secrets = json!({
            "pgWriterPassword": PG_WRITER_PASSWORD,
            "pgReaderPassword": PG_READER_PASSWORD,
            "pgDlxArchiverPassword": PG_DLX_ARCHIVER_PASSWORD,
            "pgDlxVerifierPassword": PG_DLX_VERIFIER_PASSWORD,
            "pgDlxPurgerPassword": PG_DLX_PURGER_PASSWORD,
            "vaultToken": vault.config,
            "settingsAmqpPublisherUrl": rabbit.publisher_url(),
            "settingsAmqpSubscriberUrl": rabbit.subscriber_url(),
            "redisUrl": redis.url(),
            "tenantAuthorityKey": TENANT_AUTHORITY_KEY,
            "dlxHotVaultToken": vault.dlx_hot,
            "dlxArchiveVaultToken": vault.dlx_archive,
            "s3AccessKeyId": minio.workload().access_key_id(),
            "s3SecretAccessKey": minio.workload().secret_access_key(),
        });
        write_private(self.secret_path.clone(), &serde_json::to_vec(&secrets)?)
    }
}

fn write_private(path: PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        ensure!(
            file.metadata()?.permissions().mode() & 0o077 == 0,
            "secret mount source is not private"
        );
    }
    Ok(())
}

async fn connect_owner(postgres: &PgTlsFixture, ca: &Path) -> anyhow::Result<PgPool> {
    let pg = postgres.params();
    let options = PgConnectOptions::new()
        .host(&pg.host)
        .port(pg.port)
        .database(&pg.database)
        .username(&pg.username)
        .password(&pg.password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca);
    PgPoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .context("connect PostgreSQL owner")
}

async fn register_projection_generation(pool: &PgPool) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    for binding in generated::event::PROJECTION_INPUTS {
        sqlx::query("SELECT rss_register_projection_input_binding($1, $2, $3, $4, $5)")
            .bind(generated::event::PROJECTION_INPUT_GENERATION)
            .bind(binding.contract_id())
            .bind(binding.version())
            .bind(binding.schema_hash())
            .bind(binding.topic())
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn provision_roles(postgres: &PgTlsFixture) -> anyhow::Result<()> {
    provision_postgres_test_logins_with_private_ca(
        postgres.params(),
        postgres.ca_pem().as_bytes(),
        &[
            PostgresTestLogin::new("rss_app", PG_WRITER_PASSWORD),
            PostgresTestLogin::new("rss_app_read", PG_READER_PASSWORD),
            PostgresTestLogin::new("rss_dlx_archiver", PG_DLX_ARCHIVER_PASSWORD),
            PostgresTestLogin::new("rss_dlx_verifier", PG_DLX_VERIFIER_PASSWORD),
            PostgresTestLogin::new("rss_dlx_purger", PG_DLX_PURGER_PASSWORD),
        ],
    )
    .await
    .context("provision production PostgreSQL roles")
}

struct VaultTokens {
    config: String,
    dlx_hot: String,
    dlx_archive: String,
}

async fn provision_vault(vault: &VaultTlsFixture) -> anyhow::Result<VaultTokens> {
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(vault.ca_pem().as_bytes())?)
        .build()?;
    let root = vault.root_token();
    vault_write(
        &client,
        vault,
        root,
        "sys/mounts/transit",
        json!({"type":"transit"}),
    )
    .await?;
    for key in [
        CONFIG_TRANSIT_KEY,
        DLX_HOT_TRANSIT_KEY,
        DLX_ARCHIVE_TRANSIT_KEY,
    ] {
        vault_write(
            &client,
            vault,
            root,
            &format!("transit/keys/{key}"),
            json!({"type":"aes256-gcm96", "derived":true}),
        )
        .await?;
    }
    vault_write(
        &client,
        vault,
        root,
        &format!(
            "secret/data/tenants/settings/{}",
            vault::SECRET_RESOLVER_READINESS_KEY
        ),
        json!({"data":{"value":"settingsonly-vault-readiness-1875"}}),
    )
    .await?;
    let policies = [
        (
            "settings-config",
            format!(
                r#"path "transit/encrypt/{CONFIG_TRANSIT_KEY}" {{ capabilities=["update"] }}\npath "transit/decrypt/{CONFIG_TRANSIT_KEY}" {{ capabilities=["update"] }}\npath "transit/rewrap/{CONFIG_TRANSIT_KEY}" {{ capabilities=["update"] }}\npath "secret/data/tenants/settings/*" {{ capabilities=["read"] }}\npath "secret/metadata/tenants/settings/*" {{ capabilities=["read","list"] }}"#
            ),
        ),
        (
            "settings-dlx-hot",
            format!(
                r#"path "transit/encrypt/{DLX_HOT_TRANSIT_KEY}" {{ capabilities=["update"] }}\npath "transit/decrypt/{DLX_HOT_TRANSIT_KEY}" {{ capabilities=["update"] }}"#
            ),
        ),
        (
            "settings-dlx-archive",
            format!(
                r#"path "transit/encrypt/{DLX_ARCHIVE_TRANSIT_KEY}" {{ capabilities=["update"] }}\npath "transit/decrypt/{DLX_ARCHIVE_TRANSIT_KEY}" {{ capabilities=["update"] }}"#
            ),
        ),
    ];
    for (name, policy) in &policies {
        let policy = policy.replace(r"\n", "\n");
        vault_write(
            &client,
            vault,
            root,
            &format!("sys/policies/acl/{name}"),
            json!({"policy":policy}),
        )
        .await?;
    }
    Ok(VaultTokens {
        config: vault_token(&client, vault, root, "settings-config").await?,
        dlx_hot: vault_token(&client, vault, root, "settings-dlx-hot").await?,
        dlx_archive: vault_token(&client, vault, root, "settings-dlx-archive").await?,
    })
}

async fn vault_write(
    client: &reqwest::Client,
    vault: &VaultTlsFixture,
    token: &str,
    path: &str,
    body: Value,
) -> anyhow::Result<Value> {
    let response = client
        .post(format!("{}/v1/{path}", vault.endpoint_url()))
        .header("X-Vault-Token", token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&body)?)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status.is_success(),
        "Vault {path} returned {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    if bytes.is_empty() {
        Ok(json!({}))
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}

async fn vault_token(
    client: &reqwest::Client,
    vault: &VaultTlsFixture,
    root: &str,
    policy: &str,
) -> anyhow::Result<String> {
    let value = vault_write(
        client,
        vault,
        root,
        "auth/token/create",
        json!({"policies":[policy],"ttl":"30m"}),
    )
    .await?;
    value
        .pointer("/auth/client_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .context("Vault omitted client token")
}

struct FederatedInput {
    jwks: String,
    token: String,
}

impl FederatedInput {
    fn new(issued_at: u64) -> anyhow::Result<Self> {
        let key =
            SigningKey::from_slice(&[0x31; 32]).map_err(|_| anyhow::anyhow!("build ES256 key"))?;
        let point = key.verifying_key().to_encoded_point(false);
        let jwks = json!({"keys":[{
            "kty":"EC", "crv":"P-256", "kid":JWT_KID, "alg":"ES256", "use":"sig",
            "x":URL_SAFE_NO_PAD.encode(point.x().context("ES256 x coordinate")?),
            "y":URL_SAFE_NO_PAD.encode(point.y().context("ES256 y coordinate")?)
        }]})
        .to_string();
        let expires_at = issued_at
            .checked_add(
                diport::TokenProfile::FederatedAccess
                    .policy()
                    .maximum_lifetime()
                    .as_secs(),
            )
            .context("JWT expiry overflow")?;
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({"alg":"ES256","typ":"at+jwt","kid":JWT_KID}),
        )?);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "sub":"settingsonly-production-artifact", "tenant_id":TENANT, "kind":"admin",
            "iat":issued_at, "exp":expires_at, "iss":ISSUER, "aud":AUDIENCE,
            "token_use":"access", "permissions":["settings.config-publish"]
        }))?);
        let signing_input = format!("{header}.{payload}");
        let signature: Signature = key.sign(signing_input.as_bytes());
        Ok(Self {
            jwks,
            token: format!(
                "{signing_input}.{}",
                URL_SAFE_NO_PAD.encode(signature.to_bytes())
            ),
        })
    }
}

struct ProductionImage {
    tag: String,
}

impl ProductionImage {
    async fn build(repository: &Path, cleanup: &mut CleanupSupervisor) -> anyhow::Result<Self> {
        let tag = format!(
            "rss-settingsonly:artifact-{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::Relaxed)
        );
        cleanup.record(CleanupResource::Image(tag.clone()))?;
        let mut command = Command::new("docker");
        command.args(["build", "--target", "settingsonly-runtime", "--tag", &tag]);
        add_labels(&mut command, true)?;
        command.arg(repository);
        ensure_success(
            run_command(command, COMMAND_TIMEOUT).await?,
            "build settingsonly-runtime",
        )?;
        let image = Self { tag };
        let inspect = docker_output([
            "image",
            "inspect",
            "--format",
            r#"{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{json .Config.User}}"#,
            &image.tag,
        ])
        .await?;
        let shape = String::from_utf8(inspect.stdout)?;
        ensure!(
            shape.contains(r#"["/usr/local/bin/settingsonly-server"]"#) && shape.contains("65532"),
            "built image boundary drift: {shape}"
        );
        Ok(image)
    }

    async fn spawn(
        &self,
        files: &FixtureFiles,
        workload_mount: &str,
        cleanup: &mut CleanupSupervisor,
    ) -> anyhow::Result<ImageProcess> {
        let name = format!(
            "rss-settingsonly-artifact-{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::Relaxed)
        );
        cleanup.record(CleanupResource::Container(name.clone()))?;
        let log_path = files.log_path.join(format!("{name}.log"));
        let stdout = File::create(&log_path)?;
        let stderr = stdout.try_clone()?;
        let ports = files.ports;
        let mut command = Command::new("docker");
        command.args([
            "run",
            "--name",
            &name,
            "--network",
            &files.network_name,
            "--network-alias",
            &files.network_alias,
            "--read-only",
        ]);
        add_labels(&mut command, false)?;
        command
            .args(["--publish", &format!("127.0.0.1::{}", ports.frontend_primary)])
            .args(["--publish", &format!("127.0.0.1::{}", ports.frontend_admin)])
            .args(["--publish", &format!("127.0.0.1::{}", ports.frontend_health)])
            .args(["--volume", &format!("{}:/fixtures:ro", files.public_path.display())])
            .args(["--volume", &format!("{}:{SECRET_PATH}:ro", files.secret_path.display())])
            .args(["--volume", &format!("{}:/etc/hosts:ro", files.hosts_path.display())])
            .args(["--mount", workload_mount])
            .args(["--env", "RSS_DEPLOYMENT_POD_IP=127.0.0.1"])
            .args(["--env", &format!("RSS_DEPLOYMENT_PRIMARY_PORT={}", ports.frontend_primary)])
            .args(["--env", &format!("RSS_DEPLOYMENT_ADMIN_PORT={}", ports.frontend_admin)])
            .args(["--env", &format!("RSS_DEPLOYMENT_HEALTH_PORT={}", ports.frontend_health)])
            .args(["--env", &format!("RSS_DEPLOYMENT_MTLS_SPIFFE_ALLOW_SET=[\"{INGRESS_SPIFFE_ID}\"]")])
            .args(["--env", &format!("SPIFFE_ENDPOINT_SOCKET={WORKLOAD_ENDPOINT}")])
            .args(["--env", "RSS_BUILD_SOURCE_REVISION=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
            .args(["--env", "RSS_DECLARED_IMAGE_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
            .arg(&self.tag)
            .args(["--config", CONFIG_PATH])
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let child = command.spawn().context("spawn Docker image process")?;
        let mut process = ImageProcess {
            child: Some(child),
            name,
            log_path,
            frontends: FrontendAddresses::default(),
        };
        process.wait_started().await?;
        process.frontends = FrontendAddresses {
            primary: published_port(&process.name, ports.frontend_primary).await?,
            admin: published_port(&process.name, ports.frontend_admin).await?,
            health: published_port(&process.name, ports.frontend_health).await?,
        };
        Ok(process)
    }

    async fn remove(self) -> anyhow::Result<()> {
        ensure_success(
            docker_output(["image", "rm", &self.tag]).await?,
            "remove owned image",
        )
        .map(|_| ())
    }
}

impl Drop for ProductionImage {
    fn drop(&mut self) {
        let _output = Command::new("docker")
            .args(["image", "rm", &self.tag])
            .output();
    }
}

#[derive(Clone, Copy)]
struct FrontendAddresses {
    primary: SocketAddr,
    admin: SocketAddr,
    health: SocketAddr,
}

impl Default for FrontendAddresses {
    fn default() -> Self {
        let unset = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        Self {
            primary: unset,
            admin: unset,
            health: unset,
        }
    }
}

async fn published_port(name: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let key = format!("{port}/tcp");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(output) = docker_output(["port", name, &key]).await {
                let rendered = String::from_utf8_lossy(&output.stdout);
                if let Some(value) = rendered.lines().next()
                    && let Some(host_port) = value.rsplit(':').next()
                    && let Ok(host_port) = host_port.parse::<u16>()
                {
                    return anyhow::Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, host_port)));
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .context("frontend relay port was not published")?
}

struct ImageProcess {
    child: Option<Child>,
    name: String,
    log_path: PathBuf,
    frontends: FrontendAddresses,
}

impl ImageProcess {
    fn name(&self) -> &str {
        &self.name
    }

    async fn wait_started(&self) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Ok(output) = docker_output([
                    "inspect",
                    "--type",
                    "container",
                    "--format",
                    "{{.State.Running}}",
                    &self.name,
                ])
                .await
                    && String::from_utf8_lossy(&output.stdout).trim() == "true"
                {
                    return anyhow::Ok(());
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .with_context(|| format!("image container did not start; {}", self.diagnostics()))??;
        Ok(())
    }

    fn ensure_running(&mut self) -> anyhow::Result<()> {
        if let Some(status) = self
            .child
            .as_mut()
            .context("image process reaped")?
            .try_wait()?
        {
            anyhow::bail!("image exited early with {status}; {}", self.diagnostics());
        }
        Ok(())
    }

    async fn signal(&self, signal: &str) -> anyhow::Result<()> {
        ensure_success(
            docker_output(["kill", "--signal", signal, &self.name]).await?,
            "signal image",
        )
        .map(|_| ())
    }

    async fn wait(&mut self) -> anyhow::Result<ExitStatus> {
        let child = self.child.as_mut().context("image process reaped")?;
        let status = tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if let Some(status) = child.try_wait()? {
                    return anyhow::Ok(status);
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .with_context(|| format!("image did not exit; {}", self.diagnostics()))??;
        Ok(status)
    }

    async fn force_cleanup(&mut self) -> anyhow::Result<()> {
        if self
            .child
            .as_mut()
            .context("image process reaped")?
            .try_wait()?
            .is_none()
        {
            ensure_success(
                docker_output(["rm", "--force", &self.name]).await?,
                "force-remove owned image container",
            )?;
            let _status = self.wait().await?;
        }
        Ok(())
    }

    fn diagnostics(&self) -> String {
        let mut bytes = fs::read(&self.log_path).unwrap_or_default();
        const LIMIT: usize = 32 * 1024;
        if bytes.len() > LIMIT {
            bytes.drain(..bytes.len() - LIMIT);
        }
        format!(
            "container={}; log_tail={}",
            self.name,
            String::from_utf8_lossy(&bytes)
        )
    }
}

impl Drop for ImageProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _result = child.kill();
            let _result = child.wait();
        }
        let _output = Command::new("docker")
            .args(["rm", "--force", &self.name])
            .output();
    }
}

fn add_labels(command: &mut Command, image: bool) -> anyhow::Result<()> {
    if let Some(mut labels) = integration_container_labels(ContainerService::Server)? {
        if image {
            labels.insert(
                "io.rss.integration.resource-kind".to_owned(),
                "image".to_owned(),
            );
        }
        for (key, value) in labels {
            command.args(["--label", &format!("{key}={value}")]);
        }
    }
    Ok(())
}

async fn docker_output<const N: usize>(args: [&str; N]) -> anyhow::Result<Output> {
    let mut command = Command::new("docker");
    command.args(args);
    let output = run_command(command, COMMAND_TIMEOUT).await?;
    ensure_success(output, "Docker command")
}

async fn run_command(mut command: Command, timeout: Duration) -> anyhow::Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut command = tokio::process::Command::from(command);
    command.kill_on_drop(true);
    tokio::time::timeout(timeout, command.output())
        .await
        .context("external command timed out")?
        .context("execute external command")
}

fn ensure_success(output: Output, action: &str) -> anyhow::Result<Output> {
    ensure!(
        output.status.success(),
        "{action} failed with {}: stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

struct InboxBarrier {
    lock_key: i64,
    connection: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
}

impl InboxBarrier {
    async fn install(pool: &PgPool, event_id: &str) -> anyhow::Result<Self> {
        let lock_key: i64 = sqlx::query_scalar("SELECT hashtextextended($1, 1875)")
            .bind(event_id)
            .fetch_one(pool)
            .await?;
        let mut connection = pool.acquire().await?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(lock_key)
            .execute(&mut *connection)
            .await?;
        sqlx::query(
            r#"CREATE OR REPLACE FUNCTION rss_settingsonly_artifact_block_done() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_id = TG_ARGV[0] AND NEW.status = 'done' THEN PERFORM pg_advisory_xact_lock(hashtextextended(NEW.event_id, 1875)); END IF; RETURN NEW; END $$"#,
        ).execute(pool).await?;
        // PostgreSQL grants function EXECUTE to PUBLIC by default. Leaving that grant in place
        // changes the production writer's complete effective-capability fingerprint, so the
        // restart would correctly reject the fixture-created privilege as authority drift.
        sqlx::query(
            "REVOKE ALL ON FUNCTION rss_settingsonly_artifact_block_done() FROM PUBLIC, rss_app, rss_app_read",
        )
        .execute(pool)
        .await?;
        let writer_can_execute: bool = sqlx::query_scalar(
            "SELECT has_function_privilege('rss_app', 'rss_settingsonly_artifact_block_done()', 'EXECUTE')",
        )
        .fetch_one(pool)
        .await?;
        ensure!(
            !writer_can_execute,
            "barrier function polluted the production writer capability catalog"
        );
        sqlx::query(
            "DROP TRIGGER IF EXISTS rss_settingsonly_artifact_block_done ON inbox_receipts",
        )
        .execute(pool)
        .await?;
        let escaped = event_id.replace('\'', "''");
        sqlx::query(&format!("CREATE TRIGGER rss_settingsonly_artifact_block_done BEFORE UPDATE ON inbox_receipts FOR EACH ROW EXECUTE FUNCTION rss_settingsonly_artifact_block_done('{escaped}')"))
            .execute(pool)
            .await?;
        Ok(Self {
            lock_key,
            connection: Some(connection),
        })
    }

    async fn release(&mut self) -> anyhow::Result<()> {
        let mut connection = self.connection.take().context("barrier already released")?;
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(self.lock_key)
            .execute(&mut *connection)
            .await?;
        Ok(())
    }

    async fn wait_for_waiter(&self, pool: &PgPool) -> anyhow::Result<()> {
        let mut observed = 0_i64;
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                observed = sqlx::query_scalar(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = (($1::bigint >> 32) & 4294967295)::oid AND objid = ($1::bigint & 4294967295)::oid AND NOT granted",
                )
                .bind(self.lock_key)
                .fetch_one(pool)
                .await?;
                if observed == 1 {
                    return anyhow::Ok(());
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .with_context(|| {
            format!(
                "advisory-lock waiter barrier timed out for key={}; observed_waiters={observed}",
                self.lock_key
            )
        })??;
        Ok(())
    }

    async fn remove(self, pool: &PgPool) -> anyhow::Result<()> {
        sqlx::query(
            "DROP TRIGGER IF EXISTS rss_settingsonly_artifact_block_done ON inbox_receipts",
        )
        .execute(pool)
        .await?;
        sqlx::query("DROP FUNCTION IF EXISTS rss_settingsonly_artifact_block_done()")
            .execute(pool)
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
struct IdentityMaterial {
    spiffe_id: String,
    leaf_der: Vec<u8>,
    private_key_der: Vec<u8>,
    bundle_der: Vec<u8>,
}

struct IdentitySet {
    workload: IdentityMaterial,
    ingress: IdentityMaterial,
    denied_ingress: IdentityMaterial,
}

impl IdentitySet {
    fn generate(
        workload_id: &str,
        ingress_id: &str,
        denied_ingress_id: &str,
    ) -> anyhow::Result<Self> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate()?)?;
        Ok(Self {
            workload: sign_identity(workload_id, &ca)?,
            ingress: sign_identity(ingress_id, &ca)?,
            denied_ingress: sign_identity(denied_ingress_id, &ca)?,
        })
    }
}

fn sign_identity(
    id: &str,
    ca: &CertifiedIssuer<'static, KeyPair>,
) -> anyhow::Result<IdentityMaterial> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.subject_alt_names = vec![SanType::URI(id.try_into()?)];
    let leaf = params.signed_by(&key, ca)?;
    Ok(IdentityMaterial {
        spiffe_id: id.to_owned(),
        leaf_der: leaf.der().to_vec(),
        private_key_der: key.serialize_der(),
        bundle_der: ca.der().to_vec(),
    })
}

async fn mtls_client(endpoint: &str) -> anyhow::Result<reqwest::Client> {
    // ref: maxlambrecht/rust-spiffe spiffe/src/workload_api/client/x509.rs
    let source = spiffe::X509Source::builder()
        .endpoint(endpoint)
        .initial_sync_timeout(Duration::from_secs(10))
        .build()
        .await
        .context("initialize ingress X509 source")?;
    let config = spiffe_rustls::mtls_client(source)
        .trust_domain_policy(spiffe_rustls::LocalOnly(spiffe::TrustDomain::new(
            "rss.local",
        )?))
        .authorize(spiffe_rustls::authorizer::exact([SPIFFE_ID])?)
        .with_alpn_protocols([b"http/1.1"])
        .build()?;
    reqwest::Client::builder()
        .no_proxy()
        .use_preconfigured_tls(config)
        .https_only(true)
        .timeout(Duration::from_secs(10))
        .build()
        .context("build SPIFFE mTLS client")
}

enum WorkloadIncoming {
    Tcp(TcpListener),
    Unix(tokio::net::UnixListener),
}

impl Stream for WorkloadIncoming {
    type Item = std::io::Result<WorkloadStream>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match &mut *self {
            Self::Tcp(listener) => match listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(WorkloadStream::Tcp(stream)))),
                Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
                Poll::Pending => Poll::Pending,
            },
            Self::Unix(listener) => match listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(WorkloadStream::Unix(stream)))),
                Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

enum WorkloadStream {
    Tcp(TcpStream),
    Unix(tokio::net::UnixStream),
}

impl tokio::io::AsyncRead for WorkloadStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl tokio::io::AsyncWrite for WorkloadStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, bytes),
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, bytes),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl tonic::transport::server::Connected for WorkloadStream {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

struct WorkloadApi {
    endpoint: String,
    mount: Option<String>,
    socket_dir: Option<PathBuf>,
    bridge: Option<DockerUdsBridge>,
    release: Option<tokio::sync::watch::Sender<bool>>,
    observed: tokio::sync::watch::Receiver<bool>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

impl WorkloadApi {
    async fn start(
        material: IdentityMaterial,
        root: &FixtureRoot,
        cleanup: &mut CleanupSupervisor,
    ) -> anyhow::Result<Self> {
        let tls = WorkloadBridgeTls::generate(root)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let bridge = DockerUdsBridge::start(address.port(), &tls, cleanup).await?;
        Self::serve(
            material,
            WorkloadIncoming::Tcp(listener),
            WORKLOAD_ENDPOINT.to_owned(),
            Some(bridge.mount.clone()),
            Some(tls.directory.clone()),
            Some(bridge),
            Some(tls.server_config()?),
        )
        .await
    }

    async fn start_host(material: IdentityMaterial) -> anyhow::Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "rss-settingsonly-ingress-spiffe-{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let socket = directory.join("workload.sock");
        let listener = tokio::net::UnixListener::bind(&socket)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        }
        let mut api = Self::serve(
            material,
            WorkloadIncoming::Unix(listener),
            format!("unix://{}", socket.display()),
            None,
            Some(directory),
            None,
            None,
        )
        .await?;
        api.release_identity()?;
        Ok(api)
    }

    async fn serve(
        material: IdentityMaterial,
        incoming: WorkloadIncoming,
        endpoint: String,
        mount: Option<String>,
        socket_dir: Option<PathBuf>,
        bridge: Option<DockerUdsBridge>,
        tls: Option<tonic::transport::ServerTlsConfig>,
    ) -> anyhow::Result<Self> {
        let response = Arc::new(X509svidResponse {
            svids: vec![X509svid {
                spiffe_id: material.spiffe_id,
                x509_svid: material.leaf_der.into(),
                x509_svid_key: material.private_key_der.into(),
                bundle: material.bundle_der.into(),
                hint: String::new(),
            }],
            crl: Vec::new(),
            federated_bundles: Default::default(),
        });
        let (release, released) = tokio::sync::watch::channel(false);
        let (observed_sender, observed) = tokio::sync::watch::channel(false);
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut server = tonic::transport::Server::builder();
            if let Some(tls) = tls {
                server = server
                    .tls_config(tls)
                    .context("configure authenticated SPIFFE bridge")?;
            }
            server
                .add_service(SpiffeWorkloadApiServer::new(SpiffeWorkloadService {
                    response,
                    released,
                    observed: observed_sender,
                }))
                .serve_with_incoming_shutdown(incoming, async {
                    let _result = receiver.await;
                })
                .await
                .context("serve fixture Workload API")
        });
        Ok(Self {
            endpoint,
            mount,
            socket_dir,
            bridge,
            release: Some(release),
            observed,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }
    fn volume_mount(&self) -> anyhow::Result<&str> {
        self.mount
            .as_deref()
            .context("container Workload API omitted its private UDS mount")
    }

    fn mount_source(&self) -> anyhow::Result<&str> {
        self.bridge
            .as_ref()
            .map(|bridge| bridge.volume.as_str())
            .context("container Workload API omitted its authenticated UDS bridge")
    }

    fn release_identity(&mut self) -> anyhow::Result<()> {
        let release = self
            .release
            .take()
            .context("SPIFFE identity already released")?;
        release.send(true).context("release SPIFFE identity")
    }

    async fn wait_request(&mut self) -> anyhow::Result<()> {
        tokio::time::timeout(TEST_TIMEOUT, self.observed.wait_for(|value| *value))
            .await
            .context("runtime did not request its SPIFFE identity")??;
        Ok(())
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _result = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
            let _result = task.await;
        }
        if let Some(mut bridge) = self.bridge.take() {
            bridge.close().await?;
        }
        if let Some(directory) = self.socket_dir.take() {
            fs::remove_dir_all(directory)?;
        }
        Ok(())
    }
}

impl Drop for WorkloadApi {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.shutdown.take();
        self.bridge.take();
        if let Some(directory) = self.socket_dir.take() {
            let _result = fs::remove_dir_all(directory);
        }
    }
}

struct WorkloadBridgeTls {
    directory: PathBuf,
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
}

impl WorkloadBridgeTls {
    fn generate(root: &FixtureRoot) -> anyhow::Result<Self> {
        let directory = root.join("workload-bridge-tls");
        fs::create_dir(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "settingsonly-workload-bridge-ca");
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;

        let server_key = KeyPair::generate()?;
        let mut server = CertificateParams::default();
        server.is_ca = IsCa::ExplicitNoCa;
        server
            .distinguished_name
            .push(rcgen::DnType::CommonName, "host.docker.internal");
        server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server.subject_alt_names = vec![SanType::DnsName("host.docker.internal".try_into()?)];
        let server_cert = server.signed_by(&server_key, &ca)?;

        let client_key = KeyPair::generate()?;
        let mut client = CertificateParams::default();
        client.is_ca = IsCa::ExplicitNoCa;
        client
            .distinguished_name
            .push(rcgen::DnType::CommonName, "settingsonly-workload-bridge");
        client.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client.signed_by(&client_key, &ca)?;

        let ca_pem = ca.pem();
        let server_cert_pem = server_cert.pem();
        let server_key_pem = server_key.serialize_pem();
        let client_cert_pem = client_cert.pem();
        let client_key_pem = client_key.serialize_pem();
        for (name, bytes) in [
            ("ca.pem", ca_pem.as_bytes()),
            ("client.pem", client_cert_pem.as_bytes()),
            ("client-key.pem", client_key_pem.as_bytes()),
        ] {
            write_private(directory.join(name), bytes)?;
        }
        Ok(Self {
            directory,
            ca_pem,
            server_cert_pem,
            server_key_pem,
        })
    }

    fn server_config(&self) -> anyhow::Result<tonic::transport::ServerTlsConfig> {
        Ok(tonic::transport::ServerTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(
                &self.server_cert_pem,
                &self.server_key_pem,
            ))
            .client_ca_root(tonic::transport::Certificate::from_pem(&self.ca_pem)))
    }
}

struct DockerUdsBridge {
    name: String,
    volume: String,
    mount: String,
}

impl DockerUdsBridge {
    async fn start(
        port: u16,
        tls: &WorkloadBridgeTls,
        cleanup: &mut CleanupSupervisor,
    ) -> anyhow::Result<Self> {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::Relaxed)
        );
        let name = format!("rss-settingsonly-spiffe-bridge-{suffix}");
        let volume = format!("rss-settingsonly-spiffe-{suffix}");
        cleanup.record(CleanupResource::Container(name.clone()))?;
        cleanup.record(CleanupResource::Volume(volume.clone()))?;
        ensure_success(
            docker_output(["volume", "create", &volume]).await?,
            "create private SPIFFE volume",
        )?;
        let socket = format!(
            "UNIX-LISTEN:{WORKLOAD_SOCKET},fork,unlink-early,uid=65532,gid=65532,mode=0600"
        );
        let upstream = format!(
            "OPENSSL:host.docker.internal:{port},cert=/tls/client.pem,key=/tls/client-key.pem,cafile=/tls/ca.pem,verify=1,commonname=host.docker.internal"
        );
        let mut command = Command::new("docker");
        command.args(["run", "--detach", "--name", &name]);
        add_labels(&mut command, false)?;
        command
            .args(["--add-host", "host.docker.internal:host-gateway"])
            .args(["--volume", &format!("{volume}:{WORKLOAD_DIRECTORY}")])
            .args(["--volume", &format!("{}:/tls:ro", tls.directory.display())])
            .args(["alpine/socat:1.8.0.3", "-d", "-d", &socket, &upstream]);
        ensure_success(
            run_command(command, Duration::from_secs(30)).await?,
            "start authenticated SPIFFE UDS bridge",
        )?;
        let mount = format!("type=volume,source={volume},target={WORKLOAD_DIRECTORY},readonly");
        let bridge = Self {
            name,
            volume,
            mount,
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if docker_output(["exec", &bridge.name, "test", "-S", WORKLOAD_SOCKET])
                    .await
                    .is_ok()
                {
                    return;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .context("authenticated SPIFFE bridge did not create its private socket")?;
        Ok(bridge)
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        ensure_success(
            docker_output(["rm", "--force", &self.name]).await?,
            "remove authenticated SPIFFE bridge",
        )?;
        ensure_success(
            docker_output(["volume", "rm", "--force", &self.volume]).await?,
            "remove private SPIFFE volume",
        )?;
        Ok(())
    }
}

impl Drop for DockerUdsBridge {
    fn drop(&mut self) {
        let _output = Command::new("docker")
            .args(["rm", "--force", &self.name])
            .output();
        let _output = Command::new("docker")
            .args(["volume", "rm", "--force", &self.volume])
            .output();
    }
}

#[derive(Clone)]
struct SpiffeWorkloadService {
    response: Arc<X509svidResponse>,
    released: tokio::sync::watch::Receiver<bool>,
    observed: tokio::sync::watch::Sender<bool>,
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for SpiffeWorkloadService {
    type FetchX509svidStream =
        Pin<Box<dyn Stream<Item = Result<X509svidResponse, tonic::Status>> + Send>>;

    async fn fetch_x509svid(
        &self,
        request: tonic::Request<X509svidRequest>,
    ) -> Result<tonic::Response<Self::FetchX509svidStream>, tonic::Status> {
        if request
            .metadata()
            .get("workload.spiffe.io")
            .and_then(|value| value.to_str().ok())
            != Some("true")
        {
            return Err(tonic::Status::invalid_argument(
                "workload.spiffe.io metadata must be true",
            ));
        }
        self.observed
            .send(true)
            .map_err(|_| tonic::Status::unavailable("SPIFFE request observer closed"))?;
        let mut released = self.released.clone();
        released
            .wait_for(|value| *value)
            .await
            .map_err(|_| tonic::Status::unavailable("SPIFFE identity gate closed"))?;
        let response = self.response.as_ref().clone();
        let stream: Self::FetchX509svidStream =
            Box::pin(futures::stream::once(async move { Ok(response) }));
        Ok(tonic::Response::new(stream))
    }
}
