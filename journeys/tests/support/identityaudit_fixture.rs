//! Journey-only executable fixture for the production IdentityAudit binary and provider closure.

use std::fs::{self, File};
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use tokio_util::sync::CancellationToken;
use url::Url;

const TENANT: &str = "00000000-0000-4000-8000-000000000179";
const USERNAME: &str = "identityaudit-journey";
const PASSWORD: &str = "IdentityAudit-journey-password-1797!";
const WRITER_USERNAME: &str = "rss_app";
const WRITER_PASSWORD: &str = "identityaudit-writer-test-password";
const READER_USERNAME: &str = "rss_app_read";
const READER_PASSWORD: &str = "identityaudit-reader-test-password";
const AUDIT_ADMIN_USERNAME: &str = "rss_audit_admin";
const AUDIT_ADMIN_PASSWORD: &str = "identityaudit-audit-admin-test-password";
const VAULT_SIGNER_TOKEN: &str = "identityaudit-vault-signer-test-token";
const VAULT_DLX_TOKEN: &str = "identityaudit-vault-dlx-test-token";
const SIGNING_KEY_NAME: &str = "identityaudit-fixture-key";
const DLX_PAYLOAD_KEY_NAME: &str = "identityaudit-fixture-dlx-key";
const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const VAULT_TOKEN_HEADER: &str = "x-vault-token";
const PROFILE_PATH: &str = "/api/v1/identity/profile";
const READY_PATH: &str = "/health/v1/readyz";
const BINARY_OVERRIDE_ENV: &str = "RSS_IDENTITYAUDIT_TEST_BINARY";
const AUDIT_CHAIN_KEY: [u8; 32] = *b"identityaudit-audit-chain-key-01";
const TENANT_AUTHORITY_KEY: [u8; 32] = *b"identityaudit-tenant-auth-key-01";

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub struct PostgresTestLogin {
    username: &'static str,
    password: &'static str,
}

impl PostgresTestLogin {
    #[must_use]
    pub const fn username(self) -> &'static str {
        self.username
    }

    #[must_use]
    pub const fn password(self) -> &'static str {
        self.password
    }
}

#[must_use]
pub const fn postgres_serving_logins() -> [PostgresTestLogin; 3] {
    [
        PostgresTestLogin {
            username: WRITER_USERNAME,
            password: WRITER_PASSWORD,
        },
        PostgresTestLogin {
            username: READER_USERNAME,
            password: READER_PASSWORD,
        },
        PostgresTestLogin {
            username: AUDIT_ADMIN_USERNAME,
            password: AUDIT_ADMIN_PASSWORD,
        },
    ]
}

#[must_use]
pub const fn tenant() -> &'static str {
    TENANT
}

#[must_use]
pub const fn username() -> &'static str {
    USERNAME
}

#[must_use]
pub const fn password() -> &'static str {
    PASSWORD
}

#[must_use]
pub const fn audit_chain_key() -> &'static [u8; 32] {
    &AUDIT_CHAIN_KEY
}

pub struct FixtureProviders {
    postgres_host: String,
    postgres_port: u16,
    postgres_database: String,
    identity_amqp_url: String,
    redis_url: String,
}

impl FixtureProviders {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        postgres_host: impl Into<String>,
        postgres_port: u16,
        postgres_database: impl Into<String>,
        identity_amqp_url: impl Into<String>,
        redis_url: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let postgres_host = literal_loopback_host(postgres_host.into());
        ensure!(
            postgres_host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback()),
            "identityaudit fixture PostgreSQL must use a literal loopback address"
        );
        Ok(Self {
            postgres_host,
            postgres_port,
            postgres_database: postgres_database.into(),
            identity_amqp_url: literal_loopback_url(identity_amqp_url.into())?,
            redis_url: literal_loopback_url(redis_url.into())?,
        })
    }
}

impl std::fmt::Debug for FixtureProviders {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FixtureProviders(<provider coordinates>, <redacted>)")
    }
}

fn literal_loopback_host(host: String) -> String {
    if host.eq_ignore_ascii_case("localhost") {
        "127.0.0.1".to_owned()
    } else {
        host
    }
}

fn literal_loopback_url(raw: String) -> anyhow::Result<String> {
    let mut parsed = Url::parse(&raw).context("parse fixture provider URL")?;
    if parsed
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("localhost"))
    {
        parsed
            .set_host(Some("127.0.0.1"))
            .map_err(|_| anyhow::anyhow!("replace fixture loopback URL host"))?;
    }
    Ok(parsed.into())
}

pub struct LoginReceipt {
    session_id: String,
}

impl LoginReceipt {
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

impl std::fmt::Debug for LoginReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LoginReceipt(<redacted>)")
    }
}

struct FixtureRoot {
    path: PathBuf,
}

impl FixtureRoot {
    fn create() -> anyhow::Result<Self> {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rss-identityaudit-runtime-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).context("create identityaudit fixture directory")?;
        Ok(Self { path })
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn remove(self) -> anyhow::Result<()> {
        fs::remove_dir_all(self.path).context("remove identityaudit fixture directory")
    }
}

struct ChildLogs {
    stdout: PathBuf,
    stderr: PathBuf,
}

impl ChildLogs {
    fn new(root: &FixtureRoot) -> Self {
        Self {
            stdout: root.join("identityaudit.stdout"),
            stderr: root.join("identityaudit.stderr"),
        }
    }

    fn stdio(&self) -> anyhow::Result<(Stdio, Stdio)> {
        let stdout = File::create(&self.stdout).context("create identityaudit stdout capture")?;
        let stderr = File::create(&self.stderr).context("create identityaudit stderr capture")?;
        Ok((stdout.into(), stderr.into()))
    }

    fn diagnostics(&self) -> String {
        let stdout = fs::read_to_string(&self.stdout)
            .unwrap_or_else(|error| format!("<failed to read stdout: {error}>"));
        let stderr = fs::read_to_string(&self.stderr)
            .unwrap_or_else(|error| format!("<failed to read stderr: {error}>"));
        format!("identityaudit stdout:\n{stdout}\nidentityaudit stderr:\n{stderr}")
    }
}

struct VaultState {
    private_key: PathBuf,
    calls: AtomicUsize,
}

struct VaultFixture {
    address: SocketAddr,
    state: Arc<VaultState>,
    cancellation: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl VaultFixture {
    async fn start(root: &FixtureRoot) -> anyhow::Result<(Self, String)> {
        let private_key = root.join("vault-signing-key.pem");
        let public_key = root.join("vault-signing-public.der");
        run_openssl([
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            private_key
                .to_str()
                .context("fixture private key path is not UTF-8")?,
        ])?;
        run_openssl([
            "ec",
            "-in",
            private_key
                .to_str()
                .context("fixture private key path is not UTF-8")?,
            "-pubout",
            "-outform",
            "DER",
            "-out",
            public_key
                .to_str()
                .context("fixture public key path is not UTF-8")?,
        ])?;
        let jwks = jwks_from_spki(&fs::read(public_key).context("read fixture public key")?)?;
        let state = Arc::new(VaultState {
            private_key,
            calls: AtomicUsize::new(0),
        });
        let app = axum::Router::new()
            .route("/v1/transit/sign/{key}", post(vault_sign))
            .route("/v1/transit/encrypt/{key}", post(vault_encrypt))
            .route("/v1/transit/decrypt/{key}", post(vault_decrypt))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind fixture Vault listener")?;
        let address = listener
            .local_addr()
            .context("read fixture Vault address")?;
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();
        let task = tokio::spawn(async move {
            let _result = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await;
        });
        Ok((
            Self {
                address,
                state,
                cancellation,
                task,
            },
            jwks,
        ))
    }

    async fn shutdown(self) -> anyhow::Result<()> {
        self.cancellation.cancel();
        self.task.await.context("join fixture Vault server")?;
        Ok(())
    }
}

fn run_openssl<const N: usize>(arguments: [&str; N]) -> anyhow::Result<()> {
    let output = Command::new("/usr/bin/openssl")
        .args(arguments)
        .output()
        .context("run OpenSSL for IdentityAudit fixture")?;
    ensure!(output.status.success(), "OpenSSL fixture command failed");
    Ok(())
}

fn jwks_from_spki(spki: &[u8]) -> anyhow::Result<String> {
    let point = spki
        .windows(65)
        .rev()
        .find(|candidate| candidate[0] == 0x04)
        .context("P-256 public key point missing from SPKI")?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point[1..33]);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point[33..65]);
    Ok(format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{SIGNING_KEY_NAME}","alg":"ES256","x":"{x}","y":"{y}"}}]}}"#
    ))
}

async fn vault_sign(
    AxumPath(key): AxumPath<String>,
    State(state): State<Arc<VaultState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if key != SIGNING_KEY_NAME
        || headers
            .get(VAULT_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(VAULT_SIGNER_TOKEN)
        || body
            .get("marshaling_algorithm")
            .and_then(|value| value.as_str())
            != Some("jws")
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let input = body
        .get("input")
        .and_then(|value| value.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let message = base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let private_key = state.private_key.clone();
    let signature = tokio::task::spawn_blocking(move || sign_es256(&private_key, &message))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state.calls.fetch_add(1, Ordering::Relaxed);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
    Ok(Json(serde_json::json!({
        "data": { "signature": format!("vault:v1:{encoded}") }
    })))
}

async fn vault_encrypt(
    AxumPath(key): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if key != DLX_PAYLOAD_KEY_NAME
        || headers
            .get(VAULT_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(VAULT_DLX_TOKEN)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let plaintext = body
        .get("plaintext")
        .and_then(|value| value.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    base64::engine::general_purpose::STANDARD
        .decode(plaintext)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(serde_json::json!({
        "data": {
            "ciphertext": format!("vault:v1:{plaintext}"),
            "key_version": 1
        }
    })))
}

async fn vault_decrypt(
    AxumPath(key): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if key != DLX_PAYLOAD_KEY_NAME
        || headers
            .get(VAULT_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(VAULT_DLX_TOKEN)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let plaintext = body
        .get("ciphertext")
        .and_then(|value| value.as_str())
        .and_then(|value| value.strip_prefix("vault:v1:"))
        .ok_or(StatusCode::BAD_REQUEST)?;
    base64::engine::general_purpose::STANDARD
        .decode(plaintext)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(serde_json::json!({
        "data": { "plaintext": plaintext }
    })))
}

fn sign_es256(private_key: &Path, message: &[u8]) -> anyhow::Result<[u8; 64]> {
    let mut child = Command::new("/usr/bin/openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(private_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn OpenSSL ES256 signer")?;
    child
        .stdin
        .take()
        .context("take OpenSSL signer stdin")?
        .write_all(message)
        .context("write OpenSSL signing input")?;
    let output = child
        .wait_with_output()
        .context("wait for OpenSSL signer")?;
    ensure!(output.status.success(), "OpenSSL ES256 signing failed");
    der_ecdsa_to_p1363(&output.stdout)
}

fn der_ecdsa_to_p1363(der: &[u8]) -> anyhow::Result<[u8; 64]> {
    ensure!(
        der.len() >= 8 && der[0] == 0x30,
        "invalid ECDSA DER sequence"
    );
    let mut offset = 2_usize;
    ensure!(der.get(offset) == Some(&0x02), "ECDSA DER r is missing");
    let r_len = usize::from(
        *der.get(offset + 1)
            .context("ECDSA DER r length is missing")?,
    );
    offset += 2;
    let r = der
        .get(offset..offset + r_len)
        .context("ECDSA DER r is truncated")?;
    offset += r_len;
    ensure!(der.get(offset) == Some(&0x02), "ECDSA DER s is missing");
    let s_len = usize::from(
        *der.get(offset + 1)
            .context("ECDSA DER s length is missing")?,
    );
    offset += 2;
    let s = der
        .get(offset..offset + s_len)
        .context("ECDSA DER s is truncated")?;
    let mut raw = [0_u8; 64];
    copy_der_integer(r, &mut raw[..32])?;
    copy_der_integer(s, &mut raw[32..])?;
    Ok(raw)
}

fn copy_der_integer(integer: &[u8], output: &mut [u8]) -> anyhow::Result<()> {
    let integer = integer.strip_prefix(&[0]).unwrap_or(integer);
    ensure!(
        integer.len() <= output.len(),
        "ECDSA DER integer is oversized"
    );
    let start = output.len() - integer.len();
    output[start..].copy_from_slice(integer);
    Ok(())
}

pub struct RuntimeFixture {
    child: Option<Child>,
    secret_bundle: Option<ServingSecretBundle>,
    root: Option<FixtureRoot>,
    logs: ChildLogs,
    vault: Option<VaultFixture>,
    client: reqwest::Client,
    primary: SocketAddr,
    admin: SocketAddr,
    health: SocketAddr,
}

impl RuntimeFixture {
    pub async fn start(providers: FixtureProviders) -> anyhow::Result<Self> {
        let root = FixtureRoot::create()?;
        let logs = ChildLogs::new(&root);
        let (vault, jwks) = VaultFixture::start(&root).await?;
        let primary = reserve_address().await?;
        let admin = reserve_address().await?;
        let health = reserve_address().await?;
        ensure!(primary != admin && primary != health && admin != health);

        let jwks_path = root.join("oidc.jwks.json");
        let blocklist_path = root.join("password-blocklist.sha256");
        let config_path = root.join("identityaudit.toml");
        fs::write(&jwks_path, jwks).context("write fixture JWKS")?;
        fs::write(
            &blocklist_path,
            include_bytes!("../../../deploy/password-blocklist.demo.sha256"),
        )
        .context("write fixture password blocklist")?;
        let ca_path = system_ca_path()?;
        fs::write(
            &config_path,
            fixture_config(
                &providers,
                vault.address,
                primary,
                admin,
                health,
                &jwks_path,
                &blocklist_path,
                &ca_path,
            )?,
        )
        .context("write fixture IdentityAudit config")?;
        let secret_bundle = ServingSecretBundle::create(&root, &providers)?;

        let (stdout, stderr) = logs.stdio()?;
        let mut command = Command::new(identityaudit_binary()?);
        command
            .args([
                "--config",
                config_path.to_str().context("config path is not UTF-8")?,
            ])
            .env(
                "RSS_BUILD_SOURCE_SHA",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .env(
                "RSS_BUILD_IMAGE_DIGEST",
                "sha256:0dc0251564b714e89c8d098560ddfe69eb08c87fb85ac87323c54a7650126592",
            )
            .env(
                "RSS_IDENTITYAUDIT_TEST_SECRET_BUNDLE_PATH",
                &secret_bundle.path,
            )
            .env("RSS_DEPLOYMENT_POD_IP", "127.0.0.1")
            .env("RSS_DEPLOYMENT_PRIMARY_PORT", "8080")
            .env("RSS_DEPLOYMENT_ADMIN_PORT", "8081")
            .env("RSS_DEPLOYMENT_HEALTH_PORT", "8083")
            .env(
                "RSS_DEPLOYMENT_MTLS_SPIFFE_ALLOW_SET",
                "[\"spiffe://rss.local/ns/rss/sa/ingress-gateway\"]",
            )
            .env(
                "SPIFFE_ENDPOINT_SOCKET",
                "unix:///run/spire/sockets/agent.sock",
            )
            .env("RSS_IDENTITYAUDIT_TEST_MTLS", "1")
            .env_remove("RSS_AMQP_URL")
            .stdout(stdout)
            .stderr(stderr);
        let child = command.spawn().context("spawn identityaudit-server")?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .context("build IdentityAudit fixture HTTP client")?;
        Ok(Self {
            child: Some(child),
            secret_bundle: Some(secret_bundle),
            root: Some(root),
            logs,
            vault: Some(vault),
            client,
            primary,
            admin,
            health,
        })
    }

    pub async fn wait_until_ready(&mut self) -> anyhow::Result<()> {
        let readiness = tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                self.ensure_child_running()?;
                if self
                    .client
                    .get(format!("http://{}{READY_PATH}", self.health))
                    .send()
                    .await
                    .is_ok_and(|response| response.status() == StatusCode::OK)
                {
                    tokio::net::TcpStream::connect(self.primary)
                        .await
                        .context("connect ready Primary listener")?;
                    tokio::net::TcpStream::connect(self.admin)
                        .await
                        .context("connect ready Admin listener")?;
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        match readiness {
            Ok(result) => result,
            Err(_) => anyhow::bail!(
                "identityaudit did not become ready: {}",
                self.logs.diagnostics()
            ),
        }
    }

    pub async fn login(&mut self) -> anyhow::Result<LoginReceipt> {
        let response = self
            .client
            .post(format!("http://{}/api/v1/identity/login", self.primary))
            .header("x-tenant-id", TENANT)
            .header("content-type", "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "username": USERNAME,
                    "password": PASSWORD,
                }))
                .context("encode IdentityAudit login request")?,
            )
            .send()
            .await
            .context("request IdentityAudit login")?;
        let status = response.status();
        let body = response
            .text()
            .await
            .context("read IdentityAudit login body")?;
        ensure!(
            status == StatusCode::CREATED,
            "login returned {status}: {body}"
        );
        let decoded: serde_json::Value =
            serde_json::from_str(&body).context("decode IdentityAudit login response")?;
        let data = decoded
            .get("data")
            .context("login response data is missing")?;
        let session_id = data
            .get("sessionId")
            .and_then(|value| value.as_str())
            .context("login response sessionId is missing")?
            .to_owned();
        let access_token = data
            .get("accessToken")
            .and_then(|value| value.as_str())
            .context("login response accessToken is missing")?;
        ensure!(
            self.vault
                .as_ref()
                .is_some_and(|vault| vault.state.calls.load(Ordering::Relaxed) > 0),
            "login did not call the fixture Vault Transit provider"
        );
        let auth_probe = self
            .client
            .get(format!("http://{}{PROFILE_PATH}", self.primary))
            .bearer_auth(access_token)
            .send()
            .await
            .context("request authenticated profile audit probe")?;
        ensure!(
            auth_probe.status() == StatusCode::OK,
            "authenticated self-profile probe must succeed, got {}",
            auth_probe.status()
        );
        Ok(LoginReceipt { session_id })
    }

    pub fn send_sigterm(&mut self) -> anyhow::Result<()> {
        let child = self
            .child
            .as_ref()
            .context("identityaudit child is absent")?;
        let output = Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .output()
            .context("send SIGTERM to identityaudit-server")?;
        ensure!(
            output.status.success(),
            "identityaudit SIGTERM command failed"
        );
        Ok(())
    }

    pub async fn wait_for_drain(&mut self) -> anyhow::Result<()> {
        let mut child = self.child.take().context("identityaudit child is absent")?;
        let status = tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if let Some(status) = child.try_wait().context("poll identityaudit child")? {
                    return Ok::<_, anyhow::Error>(status);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("identityaudit did not drain after SIGTERM")??;
        ensure!(
            status.success(),
            "identityaudit exited with {status}: {}",
            self.logs.diagnostics()
        );
        for (address, label) in [
            (self.primary, "Primary"),
            (self.admin, "Admin"),
            (self.health, "Health"),
        ] {
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .with_context(|| format!("rebind drained {label} listener"))?;
            drop(listener);
        }
        if let Some(vault) = self.vault.take() {
            vault.shutdown().await?;
        }
        if let Some(root) = self.root.take() {
            root.remove()?;
        }
        if let Some(secret_bundle) = self.secret_bundle.take() {
            secret_bundle.remove()?;
        }
        Ok(())
    }

    fn ensure_child_running(&mut self) -> anyhow::Result<()> {
        let child = self
            .child
            .as_mut()
            .context("identityaudit child is absent")?;
        if let Some(status) = child.try_wait().context("poll identityaudit child")? {
            anyhow::bail!(
                "identityaudit exited before readiness with {status}: {}",
                self.logs.diagnostics()
            );
        }
        Ok(())
    }
}

impl Drop for RuntimeFixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _result = child.kill();
            let _result = child.wait();
        }
        if let Some(vault) = self.vault.take() {
            vault.cancellation.cancel();
            vault.task.abort();
        }
        if let Some(root) = self.root.take() {
            let _result = fs::remove_dir_all(root.path);
        }
        if let Some(secret_bundle) = self.secret_bundle.take() {
            let _result = secret_bundle.remove();
        }
    }
}

struct ServingSecretBundle {
    path: PathBuf,
}

impl ServingSecretBundle {
    fn create(root: &FixtureRoot, providers: &FixtureProviders) -> anyhow::Result<Self> {
        let path = root.join("serving-secret-bundle.json");
        let mut file = File::create(&path).context("create IdentityAudit secret bundle")?;
        let document = serde_json::json!({
            "pgWriterPassword": WRITER_PASSWORD,
            "pgReaderPassword": READER_PASSWORD,
            "pgAuditAdminPassword": AUDIT_ADMIN_PASSWORD,
            "vaultSignerToken": VAULT_SIGNER_TOKEN,
            "vaultDlxToken": VAULT_DLX_TOKEN,
            "identityAmqpUrl": providers.identity_amqp_url,
            "redisUrl": providers.redis_url,
            "auditChainKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(AUDIT_CHAIN_KEY),
            "tenantAuthorityKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(TENANT_AUTHORITY_KEY),
        });
        serde_json::to_writer(&mut file, &document).context("write secret bundle")?;
        file.sync_all().context("sync secret bundle")?;
        Ok(Self { path })
    }

    fn remove(self) -> anyhow::Result<()> {
        if self.path.exists() {
            fs::remove_file(&self.path).context("remove secret bundle")?;
        }
        Ok(())
    }
}

async fn reserve_address() -> anyhow::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("reserve IdentityAudit listener address")?;
    let address = listener
        .local_addr()
        .context("read reserved listener address")?;
    drop(listener);
    Ok(address)
}

fn identityaudit_binary() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os(BINARY_OVERRIDE_ENV) {
        return executable(PathBuf::from(path));
    }
    let current = std::env::current_exe().context("locate journey test executable")?;
    if let Some(debug) = current.parent().and_then(Path::parent) {
        let candidate = debug.join("identityaudit-server");
        if candidate.is_file() {
            return executable(candidate);
        }
    }
    if let Some(target) = std::env::var_os("CARGO_TARGET_DIR") {
        let candidate = PathBuf::from(target).join("debug/identityaudit-server");
        if candidate.is_file() {
            return executable(candidate);
        }
    }
    anyhow::bail!("identityaudit-server is not built; build it first or set {BINARY_OVERRIDE_ENV}")
}

fn executable(path: PathBuf) -> anyhow::Result<PathBuf> {
    ensure!(path.is_file(), "identityaudit-server path is not a file");
    Ok(path)
}

fn system_ca_path() -> anyhow::Result<PathBuf> {
    [
        PathBuf::from("/etc/ssl/cert.pem"),
        PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .context("system CA bundle is unavailable")
}

#[allow(clippy::too_many_arguments)]
fn fixture_config(
    providers: &FixtureProviders,
    vault: SocketAddr,
    primary: SocketAddr,
    admin: SocketAddr,
    health: SocketAddr,
    jwks: &Path,
    blocklist: &Path,
    ca: &Path,
) -> anyhow::Result<String> {
    let jwks = jwks.to_str().context("JWKS path is not UTF-8")?;
    let blocklist = blocklist.to_str().context("blocklist path is not UTF-8")?;
    let ca = ca.to_str().context("CA path is not UTF-8")?;
    Ok(format!(
        r#"schemaVersion = 1

[listeners]
requestBudgetMs = 5000
[listeners.primary]
bind = "{primary}"
[listeners.admin]
bind = "{admin}"
[listeners.health]
bind = "{health}"

[identity]
issuer = "https://identityaudit.fixture.invalid"
audience = "rss-identityaudit-fixture"
keyId = "{SIGNING_KEY_NAME}"
accessTtlSeconds = 900
authGrantTtlSeconds = 3600
refreshTtlSeconds = 3600
passwordBlocklistPath = "{blocklist}"

[oidc]
issuer = "https://identityaudit.fixture.invalid"
audience = "rss-identityaudit-fixture"
jwksPath = "{jwks}"
refreshSeconds = 5

[postgres.connection]
host = "{}"
port = {}
database = "{}"
sslMode = "disable"
[postgres.writer]
username = "{WRITER_USERNAME}"
maxConnections = 5
[postgres.reader]
username = "{READER_USERNAME}"
maxConnections = 5
[postgres.auditAdmin]
username = "{AUDIT_ADMIN_USERNAME}"
maxConnections = 3

[vault]
addr = "http://{vault}"
caCertPemPath = "{ca}"
transitMount = "transit"
signingKeyName = "{SIGNING_KEY_NAME}"
dlxPayloadKeyName = "{DLX_PAYLOAD_KEY_NAME}"
readinessSeconds = 5

[eventing]
auditChainKeyId = 1
tenantAuthorityTtlSeconds = 3600
tenantAuthorityClockSkewSeconds = 60
"#,
        providers.postgres_host, providers.postgres_port, providers.postgres_database,
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn der_signature_conversion_preserves_fixed_width_components() {
        let mut der = vec![0x30, 0x46, 0x02, 0x21, 0];
        der.extend([0x80; 32]);
        der.extend([0x02, 0x21, 0]);
        der.extend([0x81; 32]);
        let raw = der_ecdsa_to_p1363(&der).expect("valid DER signature");
        assert_eq!(&raw[..32], &[0x80; 32]);
        assert_eq!(&raw[32..], &[0x81; 32]);
    }
}
