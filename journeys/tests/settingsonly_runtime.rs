//! Settings assembly lifecycle fixture: ready, request, SIGTERM, and exact drain.
//!
//! The parent test re-executes this integration-test binary for the ignored child target. Keeping
//! the server in a child process lets the journey deliver a real SIGTERM without risking Cargo's
//! test harness, while the child still enters the production `runtimeexec::launch` funnel through
//! the settingsonly crate's narrow, default-off test-support facade. This fixture replaces provider
//! construction and is therefore only library lifecycle evidence; this repository owns no
//! standalone binary, image, or product artifact for it.

use std::fs::{self, File};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use testkit::await_try;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const CHILD_ENV: &str = "RSS_SETTINGSONLY_JOURNEY_CHILD";
const PRIMARY_ADDR_ENV: &str = "RSS_SETTINGSONLY_JOURNEY_PRIMARY_ADDR";
const HEALTH_ADDR_ENV: &str = "RSS_SETTINGSONLY_JOURNEY_HEALTH_ADDR";
const READY_NOTIFY_ADDR_ENV: &str = "RSS_SETTINGSONLY_JOURNEY_READY_NOTIFY_ADDR";
const ACTIVATION_GATE_ADDR_ENV: &str = "RSS_SETTINGSONLY_JOURNEY_ACTIVATION_GATE_ADDR";
const SETTINGS_PATH: &str = "/api/v1/settings/configs/journey";
const READY_PATH: &str = "/health/v1/readyz";
const HEALTH_PATH: &str = "/health/v1/healthz";
const METRICS_PATH: &str = "/health/v1/metrics";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

type TestResult<T = ()> = anyhow::Result<T>;

struct ChildLogs {
    root: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl ChildLogs {
    fn create(discriminator: u16) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "rss-settingsonly-runtime-{}-{discriminator}",
            std::process::id()
        ));
        fs::create_dir_all(&root).context("create settingsonly journey log directory")?;
        Ok(Self {
            stdout: root.join("child.stdout"),
            stderr: root.join("child.stderr"),
            root,
        })
    }

    fn stdio(&self) -> TestResult<(Stdio, Stdio)> {
        let stdout = File::create(&self.stdout).context("create child stdout capture")?;
        let stderr = File::create(&self.stderr).context("create child stderr capture")?;
        Ok((Stdio::from(stdout), Stdio::from(stderr)))
    }

    fn diagnostics(&self) -> String {
        let stdout = fs::read_to_string(&self.stdout)
            .unwrap_or_else(|error| format!("<failed to read child stdout: {error}>"));
        let stderr = fs::read_to_string(&self.stderr)
            .unwrap_or_else(|error| format!("<failed to read child stderr: {error}>"));
        format!("child stdout:\n{stdout}\nchild stderr:\n{stderr}")
    }

    fn remove(self) -> TestResult {
        fs::remove_dir_all(&self.root).context("remove settingsonly journey log directory")
    }
}

async fn reserve_listener_addresses() -> TestResult<(SocketAddr, SocketAddr)> {
    let primary = TcpListener::bind("127.0.0.1:8080")
        .await
        .context("reserve Primary address")?;
    let health = TcpListener::bind("127.0.0.1:8083")
        .await
        .context("reserve Health address")?;
    let primary_addr = primary.local_addr().context("read Primary address")?;
    let health_addr = health.local_addr().context("read Health address")?;
    drop((primary, health));
    Ok((primary_addr, health_addr))
}

fn spawn_child(
    primary: SocketAddr,
    health: SocketAddr,
    ready_notify: SocketAddr,
    activation_gate: SocketAddr,
    logs: &ChildLogs,
) -> TestResult<Child> {
    let (stdout, stderr) = logs.stdio()?;
    let exact = settingsonly_lifecycle_subprocess_exact_name();
    Command::new(std::env::current_exe().context("locate settingsonly journey test binary")?)
        .args([
            "--ignored",
            "--exact",
            exact.as_str(),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .env(PRIMARY_ADDR_ENV, primary.to_string())
        .env(HEALTH_ADDR_ENV, health.to_string())
        .env(READY_NOTIFY_ADDR_ENV, ready_notify.to_string())
        .env(ACTIVATION_GATE_ADDR_ENV, activation_gate.to_string())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .context("spawn settingsonly journey child")
}

fn cleanup_failed_child(child: &mut Child) -> TestResult {
    if child
        .try_wait()
        .context("poll failed settingsonly child")?
        .is_none()
    {
        child.kill().context("kill failed settingsonly child")?;
        let _status = child.wait().context("reap failed settingsonly child")?;
    }
    Ok(())
}

async fn wait_for_child(child: &mut Child) -> TestResult<ExitStatus> {
    await_try(TEST_TIMEOUT, async || {
        child.try_wait().context("poll settingsonly child")
    })
    .await
    .context("settingsonly child did not drain within five seconds")
}

fn send_sigterm(child: &Child) -> TestResult {
    let output = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .output()
        .context("send SIGTERM to settingsonly child")?;
    ensure!(
        output.status.success(),
        "SIGTERM command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

async fn assert_health_contract(client: &reqwest::Client, health: SocketAddr) -> TestResult {
    let ready = client
        .get(format!("http://{health}{READY_PATH}"))
        .send()
        .await
        .context("request settingsonly readyz")?;
    let ready_status = ready.status();
    let body = ready.text().await.context("read readyz body")?;
    ensure!(
        ready_status == reqwest::StatusCode::OK,
        "readyz status was {ready_status}: {body}"
    );
    for probe in [
        "configs_ready",
        "keyprovider_ready",
        "vault_secret_resolver_ready",
        "federated_access_token_jwks_ready",
    ] {
        ensure!(
            body.contains(probe),
            "readyz omitted required probe {probe}: {body}"
        );
    }

    let healthz = client
        .get(format!("http://{health}{HEALTH_PATH}"))
        .send()
        .await
        .context("request settingsonly healthz")?;
    ensure!(
        healthz.status() == reqwest::StatusCode::OK,
        "healthz status was {}",
        healthz.status()
    );

    let metrics = client
        .get(format!("http://{health}{METRICS_PATH}"))
        .send()
        .await
        .context("request settingsonly metrics")?;
    ensure!(
        metrics.status() == reqwest::StatusCode::OK,
        "metrics status was {}",
        metrics.status()
    );
    ensure!(
        metrics
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/plain")),
        "metrics response did not use the Prometheus text content type"
    );
    Ok(())
}

async fn assert_primary_fails_closed(client: &reqwest::Client, primary: SocketAddr) -> TestResult {
    let url = format!("http://{primary}{SETTINGS_PATH}");
    let unauthenticated = client
        .get(&url)
        .send()
        .await
        .context("request Primary without credentials")?;
    ensure!(
        unauthenticated.status() == reqwest::StatusCode::UNAUTHORIZED,
        "Primary missing-token status was {}",
        unauthenticated.status()
    );

    let forbidden = client
        .get(url)
        .bearer_auth(settingsonly::test_support::valid_federated_token())
        .send()
        .await
        .context("request Primary with valid federated token")?;
    ensure!(
        forbidden.status() == reqwest::StatusCode::FORBIDDEN,
        "Primary valid-token status was {}",
        forbidden.status()
    );
    Ok(())
}

async fn assert_port_released(address: SocketAddr, label: &str) -> TestResult {
    let rebound = tokio::time::timeout(TEST_TIMEOUT, TcpListener::bind(address))
        .await
        .with_context(|| format!("timed out rebinding {label} address"))?
        .with_context(|| format!("rebind drained {label} address"))?;
    drop(rebound);
    Ok(())
}

async fn exercise_child(
    child: &mut Child,
    ready: &TcpListener,
    activation_gate: &TcpListener,
    primary: SocketAddr,
    health: SocketAddr,
) -> TestResult {
    let (mut gate_socket, _peer) = tokio::time::timeout(TEST_TIMEOUT, activation_gate.accept())
        .await
        .context("settingsonly child did not reach prepared-listener barrier")?
        .context("accept settingsonly activation gate")?;
    let mut prepared = [0_u8; 1];
    gate_socket
        .read_exact(&mut prepared)
        .await
        .context("read prepared-listener notification")?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(100), ready.accept())
            .await
            .is_err(),
        "settingsonly published ready before listener activation"
    );
    let pre_activation = reqwest::Client::builder()
        .timeout(Duration::from_millis(150))
        .build()
        .context("build pre-activation HTTP client")?;
    for address in [primary, health] {
        let result = pre_activation
            .get(format!("http://{address}{HEALTH_PATH}"))
            .send()
            .await;
        ensure!(
            result.is_err(),
            "listener at {address} completed HTTP before activation"
        );
    }
    gate_socket
        .write_all(&[1])
        .await
        .context("release settingsonly listener activation")?;

    let (_ready_socket, _peer) = tokio::time::timeout(TEST_TIMEOUT, ready.accept())
        .await
        .context("settingsonly child did not report ready within five seconds")?
        .context("accept settingsonly ready notification")?;

    let client = reqwest::Client::builder()
        .timeout(TEST_TIMEOUT)
        .build()
        .context("build settingsonly journey HTTP client")?;
    assert_health_contract(&client, health).await?;
    assert_primary_fails_closed(&client, primary).await?;

    send_sigterm(child)?;
    let status = wait_for_child(child).await?;
    ensure!(status.success(), "settingsonly child exited with {status}");
    assert_port_released(primary, "Primary").await?;
    assert_port_released(health, "Health").await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() -> TestResult {
    let (primary, health) = reserve_listener_addresses().await?;
    let ready = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind parent ready notification listener")?;
    let ready_notify = ready
        .local_addr()
        .context("read ready notification address")?;
    let activation_gate = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind parent activation gate")?;
    let activation_gate_addr = activation_gate
        .local_addr()
        .context("read activation gate address")?;
    let logs = ChildLogs::create(primary.port())?;
    let mut child = spawn_child(primary, health, ready_notify, activation_gate_addr, &logs)?;

    let outcome = exercise_child(&mut child, &ready, &activation_gate, primary, health).await;
    if let Err(error) = outcome {
        let cleanup = cleanup_failed_child(&mut child);
        let diagnostics = logs.diagnostics();
        let _remove_result = logs.remove();
        cleanup?;
        return Err(error.context(diagnostics));
    }

    logs.remove()?;
    Ok(())
}

fn child_address(name: &str) -> TestResult<SocketAddr> {
    std::env::var(name)
        .with_context(|| format!("missing child environment {name}"))?
        .parse()
        .with_context(|| format!("parse child environment {name}"))
}

/// Derive a libtest `--exact` selector from `module_path!` + crate name, without hand-writing
/// a second full test path beside the child `$name`.
fn ignored_subprocess_selector(fn_name: &str) -> String {
    let module = module_path!();
    let crate_name = env!("CARGO_CRATE_NAME");
    if module == crate_name {
        return fn_name.to_owned();
    }
    if let Some(rest) = module
        .strip_prefix(crate_name)
        .and_then(|suffix| suffix.strip_prefix("::"))
    {
        return format!("{rest}::{fn_name}");
    }
    format!("{module}::{fn_name}")
}

/// One `$name` expands both the `#[ignore]` child and the parent `--exact` selector.
macro_rules! settingsonly_lifecycle_subprocess {
    ($name:ident) => {
        fn settingsonly_lifecycle_subprocess_exact_name() -> String {
            ignored_subprocess_selector(stringify!($name))
        }

        #[tokio::test(flavor = "multi_thread")]
        #[ignore = "subprocess target for the settingsonly runtime journey"]
        async fn $name() -> TestResult {
            if std::env::var_os(CHILD_ENV).is_none() {
                return Ok(());
            }
            let config = settingsonly::test_support::FixtureConfig::new(
                child_address(PRIMARY_ADDR_ENV)?,
                child_address(HEALTH_ADDR_ENV)?,
                child_address(READY_NOTIFY_ADDR_ENV)?,
                child_address(ACTIVATION_GATE_ADDR_ENV)?,
            );
            settingsonly::test_support::run_fixture(config).await
        }
    };
}

settingsonly_lifecycle_subprocess!(settingsonly_lifecycle_fixture_child);
