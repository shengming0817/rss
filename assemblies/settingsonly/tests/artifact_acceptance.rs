//! Executable-artifact acceptance for the settingsonly binary and runtime image.

use std::fs::{self, File};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

const IMAGE_ENV: &str = "RSS_SETTINGSONLY_ACCEPTANCE_IMAGE";
const HELP_USAGE: &str = "Usage: settingsonly-server --config <path>";
const IMAGE_CONFIG_PATH: &str = "/fixtures/settingsonly-image.toml";
const MISSING_SECRET_ERROR: &str =
    "settings-only secret environment is missing: RSS_SETTINGSONLY_PG_READER_PASSWORD";
const SECRET_SENTINEL: &str = "settingsonly-artifact-secret-sentinel";
const SECRET_ENVIRONMENTS: [&str; 4] = [
    "RSS_SETTINGSONLY_PG_WRITER_PASSWORD",
    "RSS_SETTINGSONLY_PG_READER_PASSWORD",
    "RSS_SETTINGSONLY_PG_MIGRATOR_PASSWORD",
    "RSS_SETTINGSONLY_VAULT_TOKEN",
];
const READY_PATH: &str = "/health/v1/readyz";
const HEALTH_PATH: &str = "/health/v1/healthz";
const METRICS_PATH: &str = "/health/v1/metrics";
const SETTINGS_PATH: &str = "/api/v1/settings/configs/artifact-acceptance";
const ISSUER: &str = "https://issuer.settingsonly.test";
const AUDIENCE: &str = "rss-settingsonly-artifact";
const JWT_KID: &str = "settingsonly-artifact-es256";
const VAULT_TOKEN: &str = "settingsonly-artifact-vault-token";
const CONTAINER_PRIMARY_PROXY_PORT: u16 = 18_080;
const CONTAINER_HEALTH_PROXY_PORT: u16 = 18_083;
const PG_WRITER_ROLE: &str = "rss_app";
const PG_WRITER_PASSWORD: &str = "rss_app_settingsonly_artifact_pw";
const PG_READER_ROLE: &str = "rss_app_read";
const PG_READER_PASSWORD: &str = "rss_app_read_settingsonly_artifact_pw";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct ArtifactClock;

impl diport::Clock for ArtifactClock {
    #[allow(clippy::disallowed_methods)]
    // reason: the production Clock seam is consumed here; wall time is required for a currently
    // valid JWT minted by the external-artifact harness.
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[derive(Clone, Copy)]
enum Artifact<'a> {
    Binary(&'a str),
    Image(&'a str),
}

impl Artifact<'_> {
    fn execute_help(self) -> std::io::Result<Output> {
        match self {
            Self::Binary(path) => Command::new(path).arg("--help").output(),
            Self::Image(image) => Command::new("docker")
                .args(["run", "--rm", image, "--help"])
                .output(),
        }
    }

    fn execute_sample_without_secrets(self, sample: &Path) -> std::io::Result<Output> {
        match self {
            Self::Binary(path) => {
                let mut command = Command::new(path);
                command.arg("--config").arg(sample);
                for name in SECRET_ENVIRONMENTS {
                    command.env_remove(name);
                }
                command.env("RSS_SETTINGSONLY_PG_WRITER_PASSWORD", SECRET_SENTINEL);
                command.output()
            }
            Self::Image(image) => Command::new("docker")
                .args(["run", "--rm", "--env"])
                .arg(format!(
                    "RSS_SETTINGSONLY_PG_WRITER_PASSWORD={SECRET_SENTINEL}"
                ))
                .arg("--volume")
                .arg(format!("{}:{IMAGE_CONFIG_PATH}:ro", sample.display()))
                .arg(image)
                .args(["--config", IMAGE_CONFIG_PATH])
                .output(),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Binary(_) => "settingsonly-server binary",
            Self::Image(_) => "settingsonly-runtime image",
        }
    }

    fn spawn_live(
        self,
        fixture: &LiveFixture,
        config: &Path,
        primary: SocketAddr,
        health: SocketAddr,
    ) -> anyhow::Result<LiveProcess> {
        let label = self.label();
        let stdout_path = fixture
            .root
            .join(format!("{}.stdout", label.replace(' ', "-")));
        let stderr_path = fixture
            .root
            .join(format!("{}.stderr", label.replace(' ', "-")));
        let stdout = File::create(&stdout_path).context("create artifact stdout capture")?;
        let stderr = File::create(&stderr_path).context("create artifact stderr capture")?;
        let mut command = match self {
            Self::Binary(path) => {
                let mut command = Command::new(path);
                command.arg("--config").arg(config);
                command
            }
            Self::Image(image) => {
                let container_name = fixture.container_name();
                let mut command = Command::new("docker");
                command
                    .args(["run", "--rm", "--name"])
                    .arg(&container_name)
                    .args(["--publish"])
                    .arg(format!(
                        "127.0.0.1:{}:{CONTAINER_PRIMARY_PROXY_PORT}",
                        primary.port()
                    ))
                    .args(["--publish"])
                    .arg(format!(
                        "127.0.0.1:{}:{CONTAINER_HEALTH_PROXY_PORT}",
                        health.port()
                    ))
                    .args(["--volume"])
                    .arg(format!("{}:/fixtures:ro", fixture.root.display()));
                for name in SECRET_ENVIRONMENTS {
                    command.args(["--env", name]);
                }
                command.arg(image).args(["--config", IMAGE_CONFIG_PATH]);
                command.env("RSS_SETTINGSONLY_CONTAINER_NAME", &container_name);
                command
            }
        };
        command
            .env("RSS_SETTINGSONLY_PG_WRITER_PASSWORD", PG_WRITER_PASSWORD)
            .env("RSS_SETTINGSONLY_PG_READER_PASSWORD", PG_READER_PASSWORD)
            .env(
                "RSS_SETTINGSONLY_PG_MIGRATOR_PASSWORD",
                &fixture.pg.params().password,
            )
            .env("RSS_SETTINGSONLY_VAULT_TOKEN", VAULT_TOKEN)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let container_name = matches!(self, Self::Image(_)).then(|| fixture.container_name());
        let mut child = command
            .spawn()
            .with_context(|| format!("spawn live {label}"))?;
        let proxy_container_name = if let Some(container_name) = &container_name {
            match start_loopback_proxy(container_name, primary, health) {
                Ok(proxy) => Some(proxy),
                Err(error) => {
                    let _output = Command::new("docker")
                        .args(["rm", "--force", container_name])
                        .output();
                    let _result = child.wait();
                    return Err(error);
                }
            }
        } else {
            None
        };
        Ok(LiveProcess {
            child,
            container_name,
            proxy_container_name,
            label,
            stdout_path,
            stderr_path,
        })
    }
}

fn assert_executable_contract(artifact: Artifact<'_>) -> anyhow::Result<()> {
    let label = artifact.label();
    let output = artifact
        .execute_help()
        .with_context(|| format!("execute {label}"))?;
    assert!(
        output.status.success(),
        "{label} --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout =
        String::from_utf8(output.stdout).with_context(|| format!("{label} help was not UTF-8"))?;
    assert!(
        stdout.contains(HELP_USAGE),
        "{label} did not expose the production CLI contract: {stdout}"
    );
    for required in [
        "RSS_SETTINGSONLY_PG_WRITER_PASSWORD",
        READY_PATH,
        METRICS_PATH,
    ] {
        assert!(
            stdout.contains(required),
            "{label} help omitted `{required}`: {stdout}"
        );
    }

    let sample = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("settingsonly.example.toml")
        .canonicalize()
        .context("locate committed settingsonly sample")?;
    let output = artifact
        .execute_sample_without_secrets(&sample)
        .with_context(|| format!("execute {label} with committed sample"))?;
    assert!(
        !output.status.success(),
        "{label} unexpectedly started without its closed secret contract"
    );
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        diagnostics.contains(MISSING_SECRET_ERROR),
        "{label} did not enter the production config/secret funnel: {diagnostics}"
    );
    assert!(
        !diagnostics.contains(SECRET_SENTINEL),
        "{label} leaked secret material: {diagnostics}"
    );
    Ok(())
}

fn assert_live_deployment_contract(
    binary: Artifact<'_>,
    image: Artifact<'_>,
) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build settingsonly artifact acceptance runtime")?
        .block_on(async move {
            let fixture = LiveFixture::start().await?;
            exercise_live_artifact(binary, &fixture).await?;
            exercise_live_artifact(image, &fixture).await?;
            fixture.shutdown().await
        })
}

struct LiveFixture {
    root: PathBuf,
    pg: testkit::PgFixture,
    vault: VaultTlsFixture,
    signing_key: SigningKey,
}

impl LiveFixture {
    async fn start() -> anyhow::Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "rss-settingsonly-artifact-{}-{}",
            std::process::id(),
            FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).context("create settingsonly artifact fixture directory")?;
        let pg = testkit::env_or_postgres()
            .await
            .context("provision settingsonly artifact postgres")?;
        testkit::provision_postgres_test_logins(
            pg.params(),
            &[
                testkit::PostgresTestLogin::new(PG_WRITER_ROLE, PG_WRITER_PASSWORD),
                testkit::PostgresTestLogin::new(PG_READER_ROLE, PG_READER_PASSWORD),
            ],
        )
        .await
        .context("provision settingsonly artifact serving logins")?;
        let vault = VaultTlsFixture::start(&root).await?;
        let signing_key = SigningKey::from_slice(&[0x35; 32])
            .map_err(|_| anyhow::anyhow!("build fixture signing key"))?;
        fs::write(
            root.join("federated.jwks.json"),
            jwks_document(&signing_key),
        )
        .context("write fixture JWKS")?;
        Ok(Self {
            root,
            pg,
            vault,
            signing_key,
        })
    }

    fn container_name(&self) -> String {
        format!("rss-settingsonly-artifact-{}", std::process::id())
    }

    async fn reserve_addresses(&self) -> anyhow::Result<(SocketAddr, SocketAddr)> {
        let primary = TcpListener::bind("127.0.0.1:0")
            .await
            .context("reserve artifact Primary address")?;
        let health = TcpListener::bind("127.0.0.1:0")
            .await
            .context("reserve artifact Health address")?;
        let addresses = (
            primary.local_addr().context("read Primary address")?,
            health.local_addr().context("read Health address")?,
        );
        drop((primary, health));
        Ok(addresses)
    }

    fn write_config(
        &self,
        artifact: Artifact<'_>,
        primary: SocketAddr,
        health: SocketAddr,
    ) -> anyhow::Result<PathBuf> {
        let (jwks_path, ca_path, vault_host, filename) = match artifact {
            Artifact::Binary(_) => (
                self.root.join("federated.jwks.json").display().to_string(),
                self.root.join("vault-ca.pem").display().to_string(),
                "127.0.0.1",
                "settingsonly-binary.toml",
            ),
            Artifact::Image(_) => (
                "/fixtures/federated.jwks.json".to_owned(),
                "/fixtures/vault-ca.pem".to_owned(),
                "host.docker.internal",
                "settingsonly-image.toml",
            ),
        };
        let pg = self.pg.params();
        let pg_host = match artifact {
            Artifact::Image(_) if pg.host == "localhost" || pg.host == "127.0.0.1" => {
                "host.docker.internal"
            }
            _ => &pg.host,
        };
        let document = format!(
            r#"schemaVersion = 1

[listeners]
requestBudgetMs = 30000

[listeners.primary]
bind = "{primary}"

[listeners.health]
bind = "{health}"

[federated]
issuer = "{ISSUER}"
audience = "{AUDIENCE}"
jwksPath = "{jwks_path}"
refreshSeconds = 1
trustedKinds = ["user"]

[postgres]
host = "{pg_host}"
port = {pg_port}
database = "{pg_database}"
sslMode = "prefer"
readinessSeconds = 1

[postgres.writer]
username = "{pg_writer_username}"
maxConnections = 4
password = {{ kind = "environmentRef", name = "RSS_SETTINGSONLY_PG_WRITER_PASSWORD" }}

[postgres.reader]
username = "{pg_reader_username}"
maxConnections = 4
password = {{ kind = "environmentRef", name = "RSS_SETTINGSONLY_PG_READER_PASSWORD" }}

[postgres.migrator]
username = "{pg_migrator_username}"
password = {{ kind = "environmentRef", name = "RSS_SETTINGSONLY_PG_MIGRATOR_PASSWORD" }}

[vault]
addr = "https://{vault_host}:{vault_port}"
caCertPemPath = "{ca_path}"
transitMount = "transit"
settingsKeyName = "settings-config"
token = {{ kind = "environmentRef", name = "RSS_SETTINGSONLY_VAULT_TOKEN" }}
readinessSeconds = 1

[[vault.tenantStoreAllowlist]]
tenantId = "00000000-0000-4000-8000-000000000147"
storeId = "vault"
mount = "secret"
kvPathPrefix = "tenants/settings"
"#,
            pg_host = pg_host,
            pg_port = pg.port,
            pg_database = pg.database,
            pg_writer_username = PG_WRITER_ROLE,
            pg_reader_username = PG_READER_ROLE,
            pg_migrator_username = pg.username,
            vault_port = self.vault.port,
        );
        let path = self.root.join(filename);
        fs::write(&path, document).context("write live settingsonly config")?;
        Ok(path)
    }

    fn valid_token(&self) -> String {
        let now = diport::Clock::now(&ArtifactClock)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let payload = serde_json::json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iat": now,
            "exp": now + 900,
            "token_use": "access",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "kind": "user",
            "tenant_id": "00000000-0000-4000-8000-000000000147",
            "sid": "7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8",
            "jti": "d8dbe849-1d7e-49aa-b68a-a7b41ed252df",
            "auth_time": now,
            "authn_epoch": 7
        });
        let header = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"alg":"ES256","typ":"at+jwt","kid":"{JWT_KID}"}}"#
        ));
        let body = URL_SAFE_NO_PAD.encode(payload.to_string());
        let signing_input = format!("{header}.{body}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    async fn shutdown(self) -> anyhow::Result<()> {
        self.vault.shutdown().await?;
        fs::remove_dir_all(&self.root).context("remove settingsonly artifact fixture directory")
    }
}

struct LiveProcess {
    child: Child,
    container_name: Option<String>,
    proxy_container_name: Option<String>,
    label: &'static str,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl LiveProcess {
    fn diagnostics(&self) -> String {
        let stdout = fs::read_to_string(&self.stdout_path)
            .unwrap_or_else(|error| format!("<failed to read stdout: {error}>"));
        let stderr = fs::read_to_string(&self.stderr_path)
            .unwrap_or_else(|error| format!("<failed to read stderr: {error}>"));
        format!(
            "{label} stdout:\n{stdout}\n{label} stderr:\n{stderr}",
            label = self.label
        )
    }

    fn send_sigterm(&self) -> anyhow::Result<()> {
        let output = if let Some(name) = &self.container_name {
            Command::new("docker")
                .args(["kill", "--signal", "TERM", name])
                .output()
                .context("send SIGTERM to settingsonly image")?
        } else {
            Command::new("/bin/kill")
                .args(["-TERM", &self.child.id().to_string()])
                .output()
                .context("send SIGTERM to settingsonly binary")?
        };
        ensure!(
            output.status.success(),
            "send SIGTERM to {} failed: {}",
            self.label,
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    async fn wait(&mut self) -> anyhow::Result<ExitStatus> {
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if let Some(status) = self.child.try_wait().context("poll live artifact")? {
                    return Ok(status);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .with_context(|| format!("{} did not drain within total timeout", self.label))?
    }

    async fn force_cleanup(&mut self) {
        self.stop_proxy();
        if self.child.try_wait().ok().flatten().is_none() {
            if let Some(name) = &self.container_name {
                let _output = Command::new("docker")
                    .args(["rm", "--force", name])
                    .output();
            } else {
                let _result = self.child.kill();
            }
        }
        let _result = self.child.wait();
    }

    fn stop_proxy(&mut self) {
        if let Some(name) = self.proxy_container_name.take() {
            let _output = Command::new("docker")
                .args(["rm", "--force", &name])
                .output();
        }
    }
}

fn start_loopback_proxy(
    target: &str,
    primary: SocketAddr,
    health: SocketAddr,
) -> anyhow::Result<String> {
    let proxy_name = format!("{target}-loopback-proxy");
    let script = format!(
        "nc -lk -p {CONTAINER_PRIMARY_PROXY_PORT} -e nc 127.0.0.1 {} & \
         nc -lk -p {CONTAINER_HEALTH_PROXY_PORT} -e nc 127.0.0.1 {} & wait",
        primary.port(),
        health.port()
    );
    let mut last_error = String::new();
    for _attempt in 0..50 {
        let output = Command::new("docker")
            .args(["run", "--rm", "--detach", "--name"])
            .arg(&proxy_name)
            .args([
                "--network",
                &format!("container:{target}"),
                "alpine:3.20",
                "sh",
                "-c",
            ])
            .arg(&script)
            .output()
            .context("start settingsonly loopback proxy")?;
        if output.status.success() {
            return Ok(proxy_name);
        }
        last_error = String::from_utf8_lossy(&output.stderr).into_owned();
        std::thread::sleep(Duration::from_millis(50));
    }
    anyhow::bail!("start settingsonly loopback proxy: {last_error}")
}

async fn exercise_live_artifact(
    artifact: Artifact<'_>,
    fixture: &LiveFixture,
) -> anyhow::Result<()> {
    let (primary, health) = fixture.reserve_addresses().await?;
    let config = fixture.write_config(artifact, primary, health)?;
    let mut process = artifact.spawn_live(fixture, &config, primary, health)?;
    let result = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .context("build artifact acceptance client")?;
        wait_until_ready(&client, health, &mut process).await?;
        assert_health_contract(&client, health).await?;
        assert_primary_contract(&client, primary, &fixture.valid_token()).await?;
        process.send_sigterm()?;
        let status = process.wait().await?;
        ensure!(
            status.success(),
            "{} did not exit cleanly after SIGTERM: {status}\n{}",
            artifact.label(),
            process.diagnostics()
        );
        process.stop_proxy();
        assert_port_released(primary, "Primary").await?;
        assert_port_released(health, "Health").await
    }
    .await;
    if result.is_err() {
        process.force_cleanup().await;
    }
    result.with_context(|| process.diagnostics())
}

async fn wait_until_ready(
    client: &reqwest::Client,
    health: SocketAddr,
    process: &mut LiveProcess,
) -> anyhow::Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if let Some(status) = process
                .child
                .try_wait()
                .context("poll artifact before ready")?
            {
                anyhow::bail!("artifact exited before ready: {status}");
            }
            if let Ok(response) = client
                .get(format!("http://{health}{READY_PATH}"))
                .send()
                .await
                && response.status() == reqwest::StatusCode::OK
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("artifact did not become ready")?
}

async fn assert_health_contract(
    client: &reqwest::Client,
    health: SocketAddr,
) -> anyhow::Result<()> {
    let ready = client
        .get(format!("http://{health}{READY_PATH}"))
        .send()
        .await
        .context("request artifact readyz")?;
    let status = ready.status();
    let body = ready.text().await.context("read artifact readyz")?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "readyz was {status}: {body}"
    );
    for probe in [
        "configs_ready",
        "keyprovider_ready",
        "vault_secret_resolver_ready",
        "federated_access_token_jwks_ready",
    ] {
        ensure!(body.contains(probe), "readyz omitted {probe}: {body}");
    }
    ensure!(
        client
            .get(format!("http://{health}{HEALTH_PATH}"))
            .send()
            .await
            .context("request artifact healthz")?
            .status()
            == reqwest::StatusCode::OK,
        "healthz was not healthy"
    );
    let metrics = client
        .get(format!("http://{health}{METRICS_PATH}"))
        .send()
        .await
        .context("request artifact metrics")?;
    ensure!(
        metrics.status() == reqwest::StatusCode::OK,
        "metrics was not 200"
    );
    Ok(())
}

async fn assert_primary_contract(
    client: &reqwest::Client,
    primary: SocketAddr,
    token: &str,
) -> anyhow::Result<()> {
    let url = format!("http://{primary}{SETTINGS_PATH}");
    ensure!(
        client.get(&url).send().await?.status() == reqwest::StatusCode::UNAUTHORIZED,
        "Primary without credentials was not 401"
    );
    ensure!(
        client.get(url).bearer_auth(token).send().await?.status() == reqwest::StatusCode::FORBIDDEN,
        "Primary with valid federated JWT was not terminal 403"
    );
    Ok(())
}

async fn assert_port_released(address: SocketAddr, label: &str) -> anyhow::Result<()> {
    let listener = tokio::time::timeout(TEST_TIMEOUT, TcpListener::bind(address))
        .await
        .with_context(|| format!("timed out rebinding {label}"))?
        .with_context(|| format!("rebind {label}"))?;
    drop(listener);
    Ok(())
}

struct VaultTlsFixture {
    port: u16,
    token: CancellationToken,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl VaultTlsFixture {
    async fn start(root: &Path) -> anyhow::Result<Self> {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName,
            ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
        };
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;
        fs::write(root.join("vault-ca.pem"), ca.pem()).context("write Vault fixture CA")?;

        let signing_key = KeyPair::generate()?;
        let mut server_params = CertificateParams::default();
        server_params.subject_alt_names = vec![
            SanType::IpAddress("127.0.0.1".parse()?),
            SanType::DnsName("host.docker.internal".try_into()?),
        ];
        server_params.is_ca = IsCa::ExplicitNoCa;
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = server_params.signed_by(&signing_key, &ca)?;
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private_key)
            .context("build Vault fixture TLS config")?;
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .context("bind Vault TLS fixture")?;
        let address = listener.local_addr().context("read Vault TLS address")?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let token = CancellationToken::new();
        let task_token = token.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = task_token.cancelled() => return Ok(()),
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.context("accept Vault TLS connection")?;
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            if let Ok(stream) = acceptor.accept(stream).await {
                                let _result = serve_vault_request(stream).await;
                            }
                        });
                    }
                }
            }
        });
        Ok(Self {
            port: address.port(),
            token,
            task,
        })
    }

    async fn shutdown(self) -> anyhow::Result<()> {
        self.token.cancel();
        self.task.await.context("join Vault TLS fixture")?
    }
}

async fn serve_vault_request(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
) -> anyhow::Result<()> {
    let request = read_http_request(&mut stream).await?;
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("Vault fixture request omitted header terminator")?;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let mut request_line = headers
        .lines()
        .next()
        .context("Vault fixture request line")?
        .split(' ');
    let method = request_line.next().context("Vault fixture method")?;
    let path = request_line.next().context("Vault fixture path")?;
    let body = &request[header_end + 4..];
    let (status, response) = vault_response(method, path, body)?;
    let rendered = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    );
    stream.write_all(rendered.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn read_http_request(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
) -> anyhow::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .context("read Vault fixture request timed out")??;
        ensure!(read > 0, "Vault fixture request closed early");
        request.extend_from_slice(&buffer[..read]);
        ensure!(
            request.len() <= 64 * 1024,
            "Vault fixture request exceeded limit"
        );
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if request.len() >= header_end + 4 + content_length {
                return Ok(request);
            }
        }
    }
}

fn vault_response(method: &str, path: &str, body: &[u8]) -> anyhow::Result<(&'static str, String)> {
    if method == "POST" && path == "/v1/transit/encrypt/settings-config" {
        return Ok((
            "200 OK",
            r#"{"data":{"ciphertext":"vault:v1:cnNzLXJlYWR5","key_version":1}}"#.to_owned(),
        ));
    }
    if method == "POST" && path == "/v1/transit/decrypt/settings-config" {
        let payload: serde_json::Value = serde_json::from_slice(body)?;
        let expected = readiness_context("00000000-0000-4000-8000-000000000147")?;
        if payload.get("context").and_then(serde_json::Value::as_str) == Some(expected.as_str()) {
            return Ok((
                "200 OK",
                format!(
                    r#"{{"data":{{"plaintext":"{}"}}}}"#,
                    STANDARD.encode(b"rss-keyprovider-ready")
                ),
            ));
        }
        return Ok((
            "400 Bad Request",
            r#"{"errors":["ciphertext verification failed"]}"#.to_owned(),
        ));
    }
    if method == "GET" && path.starts_with("/v1/secret/data/tenants/settings/.rss-readiness") {
        return Ok((
            "200 OK",
            r#"{"data":{"data":{"value":"ready"}}}"#.to_owned(),
        ));
    }
    Ok(("404 Not Found", r#"{"errors":["not found"]}"#.to_owned()))
}

fn readiness_context(tenant: &str) -> anyhow::Result<String> {
    let tenant = vocab::TenantId::parse(tenant)?;
    let aad = secure::ProtectionContext::authenticated_request(
        tenant,
        "readiness.probe",
        "settings.config.value",
        1,
    )?
    .derive();
    Ok(STANDARD.encode(aad.as_canonical_bytes()))
}

fn jwks_document(signing_key: &SigningKey) -> String {
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().map_or(&[][..], AsRef::as_ref));
    let y = URL_SAFE_NO_PAD.encode(point.y().map_or(&[][..], AsRef::as_ref));
    format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{JWT_KID}","alg":"ES256","x":"{x}","y":"{y}"}}]}}"#
    )
}

#[test]
fn settingsonly_server_binary_is_an_executable_artifact() -> anyhow::Result<()> {
    assert_executable_contract(Artifact::Binary(env!("CARGO_BIN_EXE_settingsonly-server")))
}

#[test]
#[ignore = "run through hack/settingsonly-artifact-acceptance.sh with a freshly built image"]
fn settingsonly_runtime_image_is_an_executable_artifact() -> anyhow::Result<()> {
    let image = std::env::var(IMAGE_ENV)
        .with_context(|| format!("{IMAGE_ENV} must name the freshly built image"))?;
    anyhow::ensure!(!image.trim().is_empty(), "{IMAGE_ENV} must not be empty");
    assert_executable_contract(Artifact::Image(&image))
}

#[test]
#[ignore = "requires Docker for hermetic Postgres and the freshly built settingsonly image"]
fn settingsonly_binary_and_image_are_live_deployments() -> anyhow::Result<()> {
    let image = std::env::var(IMAGE_ENV)
        .with_context(|| format!("{IMAGE_ENV} must name the freshly built image"))?;
    anyhow::ensure!(!image.trim().is_empty(), "{IMAGE_ENV} must not be empty");
    assert_live_deployment_contract(
        Artifact::Binary(env!("CARGO_BIN_EXE_settingsonly-server")),
        Artifact::Image(&image),
    )
}
