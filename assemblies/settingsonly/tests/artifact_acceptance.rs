//! Executable-artifact acceptance for the settingsonly binary and runtime image.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use tokio::net::TcpListener;

const IMAGE_ENV: &str = "RSS_SETTINGSONLY_ACCEPTANCE_IMAGE";
const PRODUCTION_FIXTURE_DIR_ENV: &str = "RSS_SETTINGSONLY_PRODUCTION_FIXTURE_DIR";
const PRIMARY_ADDR_ENV: &str = "RSS_SETTINGSONLY_PRODUCTION_PRIMARY_ADDR";
const ADMIN_ADDR_ENV: &str = "RSS_SETTINGSONLY_PRODUCTION_ADMIN_ADDR";
const HEALTH_ADDR_ENV: &str = "RSS_SETTINGSONLY_PRODUCTION_HEALTH_ADDR";
const PUBLISH_TOKEN_ENV: &str = "RSS_SETTINGSONLY_PRODUCTION_PUBLISH_TOKEN";
const INVENTORY_TOKEN_ENV: &str = "RSS_SETTINGSONLY_PRODUCTION_INVENTORY_TOKEN";
const WRONG_PERMISSION_TOKEN_ENV: &str = "RSS_SETTINGSONLY_PRODUCTION_WRONG_PERMISSION_TOKEN";
const HELP_USAGE: &str = "Usage: settingsonly-server --config <path>";
const IMAGE_CONFIG_PATH: &str = "/fixtures/settingsonly-image.toml";
const SECRET_BUNDLE_PATH: &str = "/var/run/rss/secrets/serving-secret-bundle";
const MISSING_SECRET_ERROR: &str = "settings-only secret bundle could not be read: NotFound";
const READY_PATH: &str = "/health/v1/readyz";
const HEALTH_PATH: &str = "/health/v1/healthz";
const METRICS_PATH: &str = "/health/v1/metrics";
const SETTINGS_PATH: &str = "/api/v1/settings/configs";
const INVENTORY_PATH: &str = "/api/v1/runtime/inventory";
const CONTAINER_PRIMARY_PROXY_PORT: u16 = 18_080;
const CONTAINER_ADMIN_PROXY_PORT: u16 = 18_082;
const CONTAINER_HEALTH_PROXY_PORT: u16 = 18_083;
const PG_WRITER_PASSWORD: &str = "rss_app_settingsonly_artifact_pw";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

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

    fn execute_sample_without_secret_bundle(self, sample: &Path) -> std::io::Result<Output> {
        match self {
            Self::Binary(path) => Command::new(path).arg("--config").arg(sample).output(),
            Self::Image(image) => Command::new("docker")
                .args(["run", "--rm"])
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
        admin: SocketAddr,
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
                        "127.0.0.1:{}:{CONTAINER_ADMIN_PROXY_PORT}",
                        admin.port()
                    ))
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
                    .arg(format!("{}:/fixtures:ro", fixture.root.display()))
                    .args(["--volume"])
                    .arg(format!(
                        "{}:{SECRET_BUNDLE_PATH}:ro",
                        fixture.root.join("serving-secret-bundle").display()
                    ));
                command.arg(image).args(["--config", IMAGE_CONFIG_PATH]);
                command.env("RSS_SETTINGSONLY_CONTAINER_NAME", &container_name);
                command
            }
        };
        command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let container_name = matches!(self, Self::Image(_)).then(|| fixture.container_name());
        let mut child = command
            .spawn()
            .with_context(|| format!("spawn live {label}"))?;
        let proxy_container_name = if let Some(container_name) = &container_name {
            match start_loopback_proxy(container_name, primary, admin, health) {
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
        "schemaVersion=2",
        SECRET_BUNDLE_PATH,
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
        .execute_sample_without_secret_bundle(&sample)
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
        !diagnostics.contains(PG_WRITER_PASSWORD),
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
    primary: SocketAddr,
    admin: SocketAddr,
    health: SocketAddr,
    publish_token: String,
    inventory_token: String,
    wrong_permission_token: String,
}

impl LiveFixture {
    async fn start() -> anyhow::Result<Self> {
        let root = required_path(PRODUCTION_FIXTURE_DIR_ENV)?;
        anyhow::ensure!(
            root.is_dir(),
            "{PRODUCTION_FIXTURE_DIR_ENV} must name a directory"
        );
        for required in [
            root.join("settingsonly-binary.toml"),
            root.join("settingsonly-image.toml"),
            root.join("serving-secret-bundle"),
        ] {
            anyhow::ensure!(
                required.is_file(),
                "production fixture omitted {}",
                required.display()
            );
        }
        let installed_bundle = Path::new(SECRET_BUNDLE_PATH);
        anyhow::ensure!(
            installed_bundle.is_file(),
            "production fixture must install its fixed secret bundle at {SECRET_BUNDLE_PATH}"
        );
        anyhow::ensure!(
            fs::read(installed_bundle)? == fs::read(root.join("serving-secret-bundle"))?,
            "installed fixed secret bundle differs from the production fixture bundle"
        );
        validate_secret_bundle(&root.join("serving-secret-bundle"))?;
        Ok(Self {
            root,
            primary: required_addr(PRIMARY_ADDR_ENV)?,
            admin: required_addr(ADMIN_ADDR_ENV)?,
            health: required_addr(HEALTH_ADDR_ENV)?,
            publish_token: required_secret(PUBLISH_TOKEN_ENV)?,
            inventory_token: required_secret(INVENTORY_TOKEN_ENV)?,
            wrong_permission_token: required_secret(WRONG_PERMISSION_TOKEN_ENV)?,
        })
    }

    fn container_name(&self) -> String {
        format!("rss-settingsonly-artifact-{}", std::process::id())
    }

    async fn reserve_addresses(&self) -> anyhow::Result<(SocketAddr, SocketAddr, SocketAddr)> {
        Ok((self.primary, self.admin, self.health))
    }

    fn write_config(
        &self,
        artifact: Artifact<'_>,
        _primary: SocketAddr,
        _admin: SocketAddr,
        _health: SocketAddr,
    ) -> anyhow::Result<PathBuf> {
        let filename = match artifact {
            Artifact::Binary(_) => "settingsonly-binary.toml",
            Artifact::Image(_) => "settingsonly-image.toml",
        };
        let path = self.root.join(filename);
        let document = fs::read_to_string(&path).context("read production settingsonly config")?;
        let value: toml::Value =
            toml::from_str(&document).context("parse production settingsonly config")?;
        let schema: serde_json::Value =
            serde_json::from_slice(include_bytes!("../config.schema.json"))
                .context("parse committed settingsonly config schema")?;
        let validator = jsonschema::draft7::options()
            .should_validate_formats(true)
            .build(&schema)
            .context("build committed settingsonly config validator")?;
        let instance = serde_json::to_value(&value)?;
        validator.validate(&instance).map_err(|errors| {
            anyhow::anyhow!(
                "production fixture config violates the committed v2 schema: {} errors",
                errors.count()
            )
        })?;
        anyhow::ensure!(value.get("schemaVersion").and_then(toml::Value::as_integer) == Some(2));
        anyhow::ensure!(value.get("profile").and_then(toml::Value::as_str) == Some("production"));
        anyhow::ensure!(
            value.get("topology").and_then(toml::Value::as_str) == Some("durable-isolated")
        );
        Ok(path)
    }

    async fn shutdown(self) -> anyhow::Result<()> {
        Ok(())
    }
}

fn required_path(name: &'static str) -> anyhow::Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|value| !value.as_os_str().is_empty())
        .with_context(|| format!("{name} must name the installed production fixture"))
}

fn required_addr(name: &'static str) -> anyhow::Result<SocketAddr> {
    std::env::var(name)
        .with_context(|| format!("{name} is required by the production fixture"))?
        .parse()
        .with_context(|| format!("parse {name}"))
}

fn required_secret(name: &'static str) -> anyhow::Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    anyhow::ensure!(!value.trim().is_empty(), "{name} must not be empty");
    Ok(value)
}

fn validate_secret_bundle(path: &Path) -> anyhow::Result<()> {
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(path)?).context("parse production secret bundle")?;
    let object = document
        .as_object()
        .context("production secret bundle must be a JSON object")?;
    let expected = [
        "pgWriterPassword",
        "pgReaderPassword",
        "pgDlxArchiverPassword",
        "pgDlxVerifierPassword",
        "pgDlxPurgerPassword",
        "vaultToken",
        "settingsAmqpPublisherUrl",
        "settingsAmqpSubscriberUrl",
        "redisUrl",
        "tenantAuthorityKey",
        "dlxHotVaultToken",
        "dlxArchiveVaultToken",
        "s3AccessKeyId",
        "s3SecretAccessKey",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected,
        "production secret bundle keys drifted from the closed v2 contract"
    );
    anyhow::ensure!(
        object
            .values()
            .all(|value| value.as_str().is_some_and(|value| !value.is_empty())),
        "production secret bundle contains a missing, non-string, or empty value"
    );
    anyhow::ensure!(
        object["settingsAmqpPublisherUrl"]
            .as_str()
            .is_some_and(|value| value.starts_with("amqps://")),
        "production fixture must use publisher AMQPS credentials"
    );
    anyhow::ensure!(
        object["settingsAmqpSubscriberUrl"]
            .as_str()
            .is_some_and(|value| value.starts_with("amqps://")),
        "production fixture must use subscriber AMQPS credentials"
    );
    anyhow::ensure!(
        object["settingsAmqpPublisherUrl"] != object["settingsAmqpSubscriberUrl"],
        "production fixture must separate publisher and subscriber AMQP credentials"
    );
    anyhow::ensure!(
        object["redisUrl"]
            .as_str()
            .is_some_and(|value| value.starts_with("rediss://")),
        "production fixture must use REDISS"
    );
    let vault_tokens = [
        object["vaultToken"].as_str().unwrap_or_default(),
        object["dlxHotVaultToken"].as_str().unwrap_or_default(),
        object["dlxArchiveVaultToken"].as_str().unwrap_or_default(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        vault_tokens.len() == 3,
        "production fixture must use three independent Vault tokens"
    );
    Ok(())
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
    admin: SocketAddr,
    health: SocketAddr,
) -> anyhow::Result<String> {
    let proxy_name = format!("{target}-loopback-proxy");
    let script = format!(
        "nc -lk -p {CONTAINER_PRIMARY_PROXY_PORT} -e nc 127.0.0.1 {} & \
         nc -lk -p {CONTAINER_ADMIN_PROXY_PORT} -e nc 127.0.0.1 {} & \
         nc -lk -p {CONTAINER_HEALTH_PROXY_PORT} -e nc 127.0.0.1 {} & wait",
        primary.port(),
        admin.port(),
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
    let (primary, admin, health) = fixture.reserve_addresses().await?;
    let config = fixture.write_config(artifact, primary, admin, health)?;
    let mut process = artifact.spawn_live(fixture, &config, primary, admin, health)?;
    let result = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .context("build artifact acceptance client")?;
        wait_until_ready(&client, health, &mut process).await?;
        assert_health_contract(&client, health).await?;
        assert_primary_contract(
            &client,
            primary,
            &fixture.publish_token,
            &fixture.wrong_permission_token,
        )
        .await?;
        assert_admin_inventory_contract(
            &client,
            admin,
            &fixture.inventory_token,
            &fixture.wrong_permission_token,
        )
        .await?;
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
        assert_port_released(admin, "Admin").await?;
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
    publish_token: &str,
    wrong_permission_token: &str,
) -> anyhow::Result<()> {
    let request = || {
        client
            .post(format!("http://{primary}{SETTINGS_PATH}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(r#"{"key":"artifact.acceptance","value":"enabled"}"#)
    };
    ensure!(
        request().send().await?.status() == reqwest::StatusCode::UNAUTHORIZED,
        "Primary without credentials was not 401"
    );
    let denied = request().bearer_auth(wrong_permission_token).send().await?;
    ensure!(
        denied.status() == reqwest::StatusCode::FORBIDDEN,
        "Primary admitted a valid token carrying the wrong exact permission"
    );
    let allowed = request().bearer_auth(publish_token).send().await?;
    ensure!(
        allowed.status() == reqwest::StatusCode::CREATED,
        "Primary rejected settings.config-publish with {}: {}",
        allowed.status(),
        allowed.text().await?
    );
    Ok(())
}

async fn assert_admin_inventory_contract(
    client: &reqwest::Client,
    admin: SocketAddr,
    inventory_token: &str,
    wrong_permission_token: &str,
) -> anyhow::Result<()> {
    let url = format!("http://{admin}{INVENTORY_PATH}");
    ensure!(
        client.get(&url).send().await?.status() == reqwest::StatusCode::UNAUTHORIZED,
        "Admin inventory without credentials was not 401"
    );
    ensure!(
        client
            .get(&url)
            .bearer_auth(wrong_permission_token)
            .send()
            .await?
            .status()
            == reqwest::StatusCode::FORBIDDEN,
        "Admin inventory admitted a token carrying the wrong exact permission"
    );
    let response = client.get(url).bearer_auth(inventory_token).send().await?;
    let status = response.status();
    let body: serde_json::Value = serde_json::from_str(&response.text().await?)?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "Admin inventory was {status}: {body}"
    );
    ensure!(
        body["data"]["schemaVersion"] == 1,
        "inventory schema drift: {body}"
    );
    ensure!(
        body["data"]["listeners"]
            .as_array()
            .is_some_and(|value| value.len() == 3),
        "inventory listener closure drift: {body}"
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
#[ignore = "requires the installed TLS production fixture and freshly built settingsonly image"]
fn settingsonly_binary_and_image_are_live_deployments() -> anyhow::Result<()> {
    let image = std::env::var(IMAGE_ENV)
        .with_context(|| format!("{IMAGE_ENV} must name the freshly built image"))?;
    anyhow::ensure!(!image.trim().is_empty(), "{IMAGE_ENV} must not be empty");
    assert_live_deployment_contract(
        Artifact::Binary(env!("CARGO_BIN_EXE_settingsonly-server")),
        Artifact::Image(&image),
    )
}
