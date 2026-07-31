#![allow(
    clippy::disallowed_methods,
    reason = "real Docker process and HTTP deadlines require host monotonic time; a fake Clock would make the external acceptance harness unbounded"
)]

use std::{
    fmt::Write as _,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use testkit::{
    ContainerService, await_condition_async_every, await_delay, integration_container_labels,
};

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const OUTAGE_TIMEOUT: Duration = Duration::from_secs(45);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_IDEMPOTENCY_KEYS_JSON: &str =
    r#"{"current":{"id":"journey-v1","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;
const CRITICAL_WORKER_PROBES: &[&str] = &[
    "auth_grant_sweeper",
    "service_token_replay_sweeper",
    "outbox_relay_identity",
    "outbox_relay_settings",
    "outbox_sampler",
    "outbox_sweeper",
    "inbox_sweeper",
    "dlx_lifecycle",
];

/// Eventually with custom poll interval for docker-heavy probes.
async fn await_pred_every<F, Fut>(
    timeout: Duration,
    interval: Duration,
    mut pred: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    let fatal = std::sync::Arc::new(std::sync::Mutex::new(None::<anyhow::Error>));
    match await_condition_async_every(timeout, interval, || {
        let fut = pred();
        let fatal = std::sync::Arc::clone(&fatal);
        async move {
            match fut.await {
                Ok(ready) => ready,
                Err(error) => {
                    *fatal
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                    true
                }
            }
        }
    })
    .await
    {
        Ok(()) => match fatal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            Some(error) => Err(error),
            None => Ok(()),
        },
        Err(_) => bail!("condition wait timed out after {timeout:?}"),
    }
}

/// Drive an async wait from sync Drop / std-thread contexts without bare sleep.
fn block_on_delay(duration: Duration) {
    block_on_async(async {
        await_delay(duration).await;
    })
}

fn block_on_async<T>(fut: impl std::future::Future<Output = T>) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test async bridge runtime")
            .block_on(fut),
    }
}

pub(crate) async fn run_two_replica_acceptance() -> Result<()> {
    let mut fixture = RuntimeComposeFixture::start().await?;
    let (replica_a, replica_b) = fixture.start_replica_pair().await?;

    let ready_a = fixture.wait_ready(&replica_a, READY_TIMEOUT).await?;
    assert_critical_probes(&ready_a)?;
    let ready_b = fixture.wait_ready(&replica_b, READY_TIMEOUT).await?;
    assert_critical_probes(&ready_b)?;
    fixture.assert_entered_migrator(&replica_a).await?;
    fixture.assert_entered_migrator(&replica_b).await?;
    fixture.assert_migration_ledger().await?;

    fixture.pause_vault().await?;
    fixture.wait_not_ready(&replica_a, OUTAGE_TIMEOUT).await?;
    fixture.wait_not_ready(&replica_b, OUTAGE_TIMEOUT).await?;
    fixture.unpause_vault().await?;
    assert_critical_probes(&fixture.wait_ready(&replica_a, READY_TIMEOUT).await?)?;
    assert_critical_probes(&fixture.wait_ready(&replica_b, READY_TIMEOUT).await?)?;

    fixture
        .terminate_while_peer_stays_ready(&replica_a, &replica_b)
        .await?;
    let replacement = fixture.start_replica("runtime-replacement").await?;
    assert_critical_probes(&fixture.wait_ready(&replacement, READY_TIMEOUT).await?)?;
    assert_critical_probes(&fixture.wait_ready(&replica_b, READY_TIMEOUT).await?)?;
    fixture.assert_migration_ledger().await?;
    fixture.close().await
}

struct RuntimeComposeFixture {
    repo_root: PathBuf,
    compose_file: PathBuf,
    override_file: PathBuf,
    project: String,
    containers: Vec<String>,
    vault_container: String,
    postgres_password: String,
    vault_paused: bool,
    closed: bool,
}

#[derive(Clone)]
struct Replica {
    container: String,
    ready_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationLedgerRow {
    version: i64,
    success: bool,
    checksum_hex: String,
}

impl MigrationLedgerRow {
    fn parse(line: &str) -> Result<Self> {
        let columns = line.split('|').collect::<Vec<_>>();
        let [version, success, checksum_hex] = columns.as_slice() else {
            bail!("invalid migration ledger row: {line:?}");
        };
        Ok(Self {
            version: version
                .parse()
                .with_context(|| format!("invalid migration version {version:?}"))?,
            success: match *success {
                "t" => true,
                "f" => false,
                other => bail!("invalid migration success flag {other:?}"),
            },
            checksum_hex: (*checksum_hex).to_owned(),
        })
    }
}

fn embedded_migration_ledger() -> Vec<MigrationLedgerRow> {
    use std::fmt::Write as _;

    let migrator = sqlx::migrate!("../adapters/postgres/migrations");
    migrator
        .iter()
        .map(|migration| {
            let mut checksum_hex = String::with_capacity(migration.checksum.len() * 2);
            for byte in migration.checksum.iter() {
                write!(&mut checksum_hex, "{byte:02x}")
                    .unwrap_or_else(|_| unreachable!("writing to String is infallible"));
            }
            MigrationLedgerRow {
                version: migration.version,
                success: true,
                checksum_hex,
            }
        })
        .collect()
}

fn require_exact_migration_ledger(
    actual: &[MigrationLedgerRow],
    expected: &[MigrationLedgerRow],
) -> Result<()> {
    ensure!(
        actual == expected,
        "database migration ledger differs from SQLx embedded migrations; actual={actual:?}; expected={expected:?}"
    );
    Ok(())
}

impl RuntimeComposeFixture {
    async fn start() -> Result<Self> {
        command_ok(
            Command::new("docker").arg("info"),
            "connect to Docker daemon",
        )
        .await?;
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("journeys must have a repository parent")?
            .to_path_buf();
        let compose_file = repo_root.join("deploy/docker-compose.yml");
        let postgres_password =
            read_env_file_value(&repo_root.join("deploy/.env.example"), "POSTGRES_PASSWORD")?;
        let project = format!(
            "rss1801-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );
        let override_file = std::env::temp_dir().join(format!("{project}-compose.override.yml"));
        let override_source = render_compose_override()?;
        std::fs::write(&override_file, override_source)
            .with_context(|| format!("write compose override {}", override_file.display()))?;
        let vault_container = format!("{project}-vault");
        let mut fixture = Self {
            repo_root,
            compose_file,
            override_file,
            project,
            containers: Vec::new(),
            vault_container,
            postgres_password,
            vault_paused: false,
            closed: false,
        };

        eprintln!("two-replica: building the exact compose runtime image");
        fixture
            .compose_ok(&["build", "server"], "build runtime image")
            .await?;
        for service in ["postgres", "redis", "rabbitmq", "minio", "vault"] {
            fixture.start_infra(service).await?;
        }
        for service in ["postgres", "redis", "rabbitmq", "minio", "vault"] {
            fixture
                .wait_container_healthy(service, READY_TIMEOUT)
                .await?;
        }
        for init in ["minio-init", "vault-init", "rss-access-jwks-init"] {
            eprintln!("two-replica: running {init}");
            fixture
                .compose_ok(
                    &["run", "--rm", "--no-deps", "--use-aliases", init],
                    &format!("run {init}"),
                )
                .await?;
        }
        Ok(fixture)
    }

    fn compose_command(&self) -> Command {
        let mut command = Command::new("docker");
        command
            .current_dir(self.repo_root.join("deploy"))
            .args(["compose", "--env-file"])
            .arg(self.repo_root.join("deploy/.env.example"))
            .args(["--project-name", &self.project, "--file"])
            .arg(&self.compose_file)
            .arg("--file")
            .arg(&self.override_file);
        command
    }

    async fn compose_ok(&self, args: &[&str], purpose: &str) -> Result<String> {
        let mut command = self.compose_command();
        command.args(args);
        command_stdout(&mut command, purpose).await
    }

    async fn start_infra(&mut self, service: &str) -> Result<()> {
        let container = if service == "vault" {
            self.vault_container.clone()
        } else {
            format!("{}-{service}", self.project)
        };
        eprintln!("two-replica: starting isolated {service}");
        self.compose_ok(
            &[
                "run",
                "--detach",
                "--name",
                &container,
                "--no-deps",
                "--use-aliases",
                service,
            ],
            &format!("start {service}"),
        )
        .await?;
        self.containers.push(container);
        Ok(())
    }

    async fn wait_container_healthy(&self, service: &str, timeout: Duration) -> Result<()> {
        let container = if service == "vault" {
            &self.vault_container
        } else {
            self.containers
                .iter()
                .find(|name| name.ends_with(&format!("-{service}")))
                .with_context(|| format!("missing tracked {service} container"))?
        };
        let last = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        await_pred_every(timeout, Duration::from_secs(1), || {
            let last = std::sync::Arc::clone(&last);
            let container = container.to_owned();
            let service = service.to_owned();
            async move {
                let status = docker_stdout(&[
                    "inspect",
                    "--format",
                    "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                    &container,
                ])
                .await?;
                match status.trim() {
                    "healthy" => Ok(true),
                    "exited" | "dead" => bail!("{service} exited before becoming healthy"),
                    other => {
                        *last.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                            other.to_owned();
                        Ok(false)
                    }
                }
            }
        })
        .await
        .map_err(|error| {
            let other = last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if other.is_empty() {
                error
            } else {
                anyhow::anyhow!(
                    "{service} did not become healthy within {timeout:?}; last={other}; {error:#}"
                )
            }
        })?;
        Ok(())
    }

    async fn start_replica_pair(&mut self) -> Result<(Replica, Replica)> {
        self.compose_ok(
            &["create", "--scale", "server=2", "server"],
            "create both runtime replicas before either starts",
        )
        .await?;
        let ids = self
            .compose_ok(
                &["ps", "--all", "--quiet", "server"],
                "list created runtime replicas",
            )
            .await?;
        let mut containers = Vec::new();
        for id in ids.lines() {
            let name = docker_stdout(&["inspect", "--format", "{{.Name}}", id]).await?;
            containers.push(name.trim_start_matches('/').to_owned());
        }
        containers.sort();
        let [container_a, container_b] = containers.as_slice() else {
            bail!("compose must create exactly two runtime replicas; found {containers:?}");
        };
        self.containers.extend(containers.iter().cloned());

        let postgres = self.postgres_container()?.to_owned();
        let mut barrier = MigrationLockBarrier::acquire(&postgres, &self.postgres_password).await?;
        docker_ok(&["start", container_a, container_b]).await?;
        barrier
            .wait_for_two_migrators(&postgres, READY_TIMEOUT)
            .await?;
        barrier.release().await?;

        let replica_a = replica_from_started_container(container_a).await?;
        let replica_b = replica_from_started_container(container_b).await?;
        Ok((replica_a, replica_b))
    }

    async fn start_replica(&mut self, suffix: &str) -> Result<Replica> {
        let container = format!("{}-{suffix}", self.project);
        self.compose_ok(
            &[
                "run",
                "--detach",
                "--name",
                &container,
                "--no-deps",
                "--use-aliases",
                "--publish",
                "127.0.0.1::8083/tcp",
                "server",
            ],
            &format!("start {suffix}"),
        )
        .await?;
        let replica = replica_from_started_container(&container).await?;
        self.containers.push(replica.container.clone());
        Ok(replica)
    }

    fn postgres_container(&self) -> Result<&str> {
        self.containers
            .iter()
            .find(|name| name.ends_with("-postgres"))
            .map(String::as_str)
            .context("postgres container is not tracked")
    }

    async fn wait_ready(&self, replica: &Replica, timeout: Duration) -> Result<Value> {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None::<Result<Value>>));
        let last = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let finished = await_condition_async_every(timeout, Duration::from_secs(1), || {
            let captured = std::sync::Arc::clone(&captured);
            let last = std::sync::Arc::clone(&last);
            let ready_url = replica.ready_url.clone();
            let container = replica.container.clone();
            async move {
                match http_get(&ready_url) {
                    Ok((200, body)) => {
                        let parsed = serde_json::from_str(&body)
                            .with_context(|| format!("parse {container} readyz response"));
                        *captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(parsed);
                        true
                    }
                    Ok((status, body)) => {
                        *last.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                            format!("HTTP {status}: {body}");
                        false
                    }
                    Err(error) => {
                        *last.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                            format!("request error: {error:#}");
                        false
                    }
                }
            }
        })
        .await;
        if finished.is_ok()
            && let Some(value) = captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        {
            return value;
        }
        let last = last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let logs = docker_combined(&["logs", "--tail", "100", &replica.container])
            .await
            .unwrap_or_else(|error| format!("unable to collect logs: {error:#}"));
        if !container_is_running(&replica.container).await? {
            bail!(
                "{} exited before becoming ready; last={last}\nlogs:\n{logs}",
                replica.container
            );
        }
        bail!(
            "{} did not become ready within {timeout:?}; last={last}\nlogs:\n{logs}",
            replica.container
        );
    }

    async fn wait_not_ready(&self, replica: &Replica, timeout: Duration) -> Result<()> {
        await_pred_every(timeout, Duration::from_millis(500), || {
            let ready_url = replica.ready_url.clone();
            let container = replica.container.clone();
            async move {
                if let Ok((503, body)) = http_get(&ready_url) {
                    let report: Value = serde_json::from_str(&body).with_context(|| {
                        format!("parse {container} fail-closed report")
                    })?;
                    ensure!(
                        has_unhealthy_probe(&report, "keyprovider_ready")
                            || has_unhealthy_probe(&report, "vault_secret_resolver_ready"),
                        "{container} returned 503 without an unhealthy Vault-owned probe: {body}"
                    );
                    return Ok(true);
                }
                if !container_is_running(&container).await? {
                    let logs = docker_combined(&["logs", "--tail", "100", &container])
                        .await
                        .unwrap_or_else(|error| format!("unable to collect logs: {error:#}"));
                    bail!(
                        "{container} exited instead of reporting fail-closed readiness:\n{logs}"
                    );
                }
                Ok(false)
            }
        })
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "{} remained ready while Vault was paused; {error:#}",
                replica.container
            )
        })?;
        Ok(())
    }

    async fn pause_vault(&mut self) -> Result<()> {
        docker_ok(&["pause", &self.vault_container]).await?;
        self.vault_paused = true;
        Ok(())
    }

    async fn unpause_vault(&mut self) -> Result<()> {
        docker_ok(&["unpause", &self.vault_container]).await?;
        self.vault_paused = false;
        Ok(())
    }

    async fn assert_migration_ledger(&self) -> Result<()> {
        let postgres = self.postgres_container()?;
        let password = format!("PGPASSWORD={}", self.postgres_password);
        let rows = docker_stdout(&[
            "exec",
            "-e",
            &password,
            postgres,
            "psql",
            "-U",
            "postgres",
            "-d",
            "rss",
            "-At",
            "-F",
            "|",
            "-c",
            "SELECT version, success, encode(checksum, 'hex') FROM _sqlx_migrations ORDER BY version",
        ]).await?;
        let actual = rows
            .lines()
            .map(MigrationLedgerRow::parse)
            .collect::<Result<Vec<_>>>()?;
        require_exact_migration_ledger(&actual, &embedded_migration_ledger())
    }

    async fn assert_entered_migrator(&self, replica: &Replica) -> Result<()> {
        let logs = docker_combined(&["logs", &replica.container]).await?;
        ensure!(
            logs.contains("postgres migrations applied"),
            "{} never emitted the exact Postgres migrator completion marker:\n{logs}",
            replica.container
        );
        Ok(())
    }

    async fn terminate_while_peer_stays_ready(
        &self,
        target: &Replica,
        peer: &Replica,
    ) -> Result<()> {
        let stop = Arc::new(AtomicBool::new(false));
        let first_error = Arc::new(Mutex::new(None::<String>));
        let samples = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let peer_clone = peer.clone();
        let monitor_stop = Arc::clone(&stop);
        let monitor_error = Arc::clone(&first_error);
        let monitor_samples = Arc::clone(&samples);
        let monitor = thread::spawn(move || {
            while !monitor_stop.load(Ordering::SeqCst) {
                let observation = match http_get(&peer_clone.ready_url) {
                    Ok((200, body)) => serde_json::from_str::<Value>(&body)
                        .map_err(|error| format!("invalid readyz JSON: {error}; body={body}"))
                        .and_then(|report| {
                            assert_critical_probes(&report).map_err(|error| {
                                format!("critical probe failure: {error:#}; body={body}")
                            })
                        }),
                    Ok((status, body)) => Err(format!("HTTP {status}; body={body}")),
                    Err(error) => Err(format!("readyz request failed: {error:#}")),
                };
                match observation {
                    Ok(()) => {
                        monitor_samples.fetch_add(1, Ordering::SeqCst);
                        let _ = started_tx.try_send(());
                    }
                    Err(error) => record_first_monitor_error(&monitor_error, error),
                }
                block_on_delay(Duration::from_millis(100));
            }
        });
        if started_rx.recv_timeout(Duration::from_secs(5)).is_err() {
            stop.store(true, Ordering::SeqCst);
            monitor
                .join()
                .map_err(|_| anyhow::anyhow!("peer monitor panicked"))?;
            bail!("peer never produced an initial ready sample");
        }
        let pre_term_samples = samples.load(Ordering::SeqCst);

        let signal_result = docker_ok(&["kill", "--signal", "TERM", &target.container]).await;
        let wait_result = docker_stdout(&["wait", &target.container]).await;
        stop.store(true, Ordering::SeqCst);
        monitor
            .join()
            .map_err(|_| anyhow::anyhow!("peer monitor panicked"))?;
        signal_result?;
        let exit = wait_result?;
        ensure!(
            exit.trim() == "0",
            "{} exited with {exit}",
            target.container
        );
        let post_term_samples = samples.load(Ordering::SeqCst);
        let error = first_error
            .lock()
            .map_err(|_| anyhow::anyhow!("peer monitor error slot was poisoned"))?
            .clone();
        let logs = docker_combined(&["logs", &target.container]).await?;
        require_drain_evidence(
            pre_term_samples,
            post_term_samples,
            error.as_deref(),
            &logs,
            &peer.container,
            &target.container,
        )
    }

    async fn close(mut self) -> Result<()> {
        self.cleanup().await?;
        self.closed = true;
        Ok(())
    }

    async fn cleanup(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if self.vault_paused {
            let mut unpause = Command::new("docker");
            unpause.args(["unpause", &self.vault_container]);
            if let Err(error) = command_output_with_timeout(
                &mut unpause,
                "unpause Vault during fixture cleanup",
                CLEANUP_TIMEOUT,
            )
            .await
            {
                errors.push(format!("unpause Vault: {error:#}"));
            } else {
                self.vault_paused = false;
            }
        }
        if !self.containers.is_empty() {
            let mut remove = Command::new("docker");
            remove.args(["rm", "--force"]);
            remove.args(&self.containers);
            if let Err(error) = command_output_with_timeout(
                &mut remove,
                "remove tracked fixture containers",
                CLEANUP_TIMEOUT,
            )
            .await
            {
                errors.push(format!("remove containers: {error:#}"));
            } else {
                self.containers.clear();
            }
        }
        let mut down = self.compose_command();
        down.args(["down", "--volumes", "--remove-orphans", "--timeout", "5"]);
        if let Err(error) = command_output_with_timeout(
            &mut down,
            "remove fixture project and fresh volumes",
            CLEANUP_TIMEOUT,
        )
        .await
        {
            errors.push(format!("compose down: {error:#}"));
        }
        if errors.is_empty()
            && let Err(error) = std::fs::remove_file(&self.override_file)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            errors.push(format!(
                "remove compose override {}: {error}",
                self.override_file.display()
            ));
        }
        ensure!(
            errors.is_empty(),
            "two-replica fixture cleanup failed: {}",
            errors.join("; ")
        );
        Ok(())
    }
}

fn render_compose_override() -> Result<String> {
    let mut source = format!(
        "services:\n  server:\n    depends_on: !reset []\n    restart: \"no\"\n    ports: !override\n      - \"127.0.0.1::8083/tcp\"\n    environment:\n      RSS_COMMAND_IDEMPOTENCY_KEYS_JSON: '{COMMAND_IDEMPOTENCY_KEYS_JSON}'\n"
    );
    if let Some(labels) = integration_container_labels(ContainerService::Server)? {
        writeln!(&mut source, "    labels:")?;
        for (key, value) in labels {
            writeln!(&mut source, "      {key}: \"{value}\"")?;
        }
    }
    for service in [
        ContainerService::Postgres,
        ContainerService::Redis,
        ContainerService::RabbitMq,
        ContainerService::Minio,
        ContainerService::Vault,
    ] {
        let Some(labels) = integration_container_labels(service)? else {
            continue;
        };
        writeln!(&mut source, "  {}:", service.name())?;
        writeln!(&mut source, "    labels:")?;
        for (key, value) in labels {
            writeln!(&mut source, "      {key}: \"{value}\"")?;
        }
    }
    Ok(source)
}

const MIGRATION_BARRIER_APP: &str = "rss-two-replica-migration-barrier";

struct MigrationLockBarrier {
    child: Option<std::process::Child>,
    postgres: String,
    password: String,
}

impl MigrationLockBarrier {
    async fn acquire(postgres: &str, password: &str) -> Result<Self> {
        let lock_id = sqlx_migration_lock_id("rss");
        let mut command = Command::new("docker");
        let password_env = format!("PGPASSWORD={password}");
        command.args([
            "exec",
            "-e",
            &password_env,
            "-e",
            &format!("PGAPPNAME={MIGRATION_BARRIER_APP}"),
            postgres,
            "psql",
            "-U",
            "postgres",
            "-d",
            "rss",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &format!("SELECT pg_advisory_lock({lock_id}); SELECT pg_sleep(600)"),
        ]);
        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("start SQLx migration advisory-lock barrier")?;
        let mut barrier = Self {
            child: Some(child),
            postgres: postgres.to_owned(),
            password: password.to_owned(),
        };
        barrier.wait_until_owner(Duration::from_secs(10)).await?;
        Ok(barrier)
    }

    async fn wait_until_owner(&mut self, timeout: Duration) -> Result<()> {
        await_pred_every(timeout, Duration::from_millis(100), || async {
            if self
                .child
                .as_mut()
                .context("migration barrier child missing")?
                .try_wait()
                .context("poll migration barrier process")?
                .is_some()
            {
                bail!("migration advisory-lock barrier exited before acquiring the lock");
            }
            let count = psql_scalar(
                &self.postgres,
                &self.password,
                &format!(
                    "SELECT COUNT(*) FROM pg_stat_activity a JOIN pg_locks l USING (pid) WHERE a.application_name = '{MIGRATION_BARRIER_APP}' AND l.locktype = 'advisory' AND l.granted"
                ),
            )
            .await?;
            Ok(count.trim() == "1")
        })
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "migration advisory-lock barrier was not acquired within {timeout:?}; {error:#}"
            )
        })?;
        Ok(())
    }

    async fn wait_for_two_migrators(&self, postgres: &str, timeout: Duration) -> Result<()> {
        let last = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        await_pred_every(timeout, Duration::from_millis(100), || {
            let last = std::sync::Arc::clone(&last);
            let postgres = postgres.to_owned();
            let password = self.password.clone();
            async move {
                let observed = psql_scalar(
                    &postgres,
                    &password,
                    "SELECT COUNT(*) || '|' || COUNT(*) FILTER (WHERE granted) FROM pg_locks WHERE locktype = 'advisory'",
                )
                .await?;
                *last.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                    observed.clone();
                Ok(observed.trim() == "3|1")
            }
        })
        .await
        .map_err(|error| {
            let last = last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            anyhow::anyhow!(
                "both runtime processes did not block behind the held SQLx migration lock; expected total|granted=3|1, last={last:?}; {error:#}"
            )
        })?;
        Ok(())
    }

    async fn release(&mut self) -> Result<()> {
        let terminated = psql_scalar(
            &self.postgres,
            &self.password,
            &format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = '{MIGRATION_BARRIER_APP}'"
            ),
        ).await?;
        ensure!(
            terminated.lines().all(|line| line.trim() == "t") && !terminated.trim().is_empty(),
            "failed to terminate migration barrier backend: {terminated:?}"
        );
        if let Some(mut child) = self.child.take() {
            wait_child_exit(
                &mut child,
                Duration::from_secs(10),
                "migration barrier docker exec",
            )
            .await?;
        }
        Ok(())
    }
}

impl Drop for MigrationLockBarrier {
    fn drop(&mut self) {
        if self.child.is_none() {
            return;
        }
        if let Err(error) = block_on_async(self.release()) {
            eprintln!("two-replica cleanup: migration barrier release failed: {error:#}");
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

// Pinned SQLx 0.8.6 `sqlx-postgres/src/migrate.rs::generate_lock_id`: CRC-32/ISO-HDLC of the
// database name multiplied by its migration namespace. Keeping this in the test harness lets us
// hold the exact same advisory lock before either pre-created runtime process starts.
fn sqlx_migration_lock_id(database_name: &str) -> i64 {
    let mut crc = u32::MAX;
    for byte in database_name.bytes() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    i64::from(!crc) * 0x3d32_ad9e
}

async fn psql_scalar(postgres: &str, password: &str, query: &str) -> Result<String> {
    let password_env = format!("PGPASSWORD={password}");
    docker_stdout(&[
        "exec",
        "-e",
        &password_env,
        postgres,
        "psql",
        "-U",
        "postgres",
        "-d",
        "rss",
        "-At",
        "-c",
        query,
    ])
    .await
}

fn read_env_file_value(path: &Path, key: &str) -> Result<String> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("read canonical compose env {}", path.display()))?;
    let prefix = format!("{key}=");
    let values = source
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    let [value] = values.as_slice() else {
        bail!("canonical compose env must define {key} exactly once");
    };
    ensure!(
        !value.is_empty(),
        "canonical compose env {key} must be non-empty"
    );
    Ok((*value).to_owned())
}

async fn wait_child_exit(
    child: &mut std::process::Child,
    timeout: Duration,
    purpose: &str,
) -> Result<()> {
    await_pred_every(timeout, Duration::from_millis(100), || async {
        Ok(child
            .try_wait()
            .with_context(|| format!("poll {purpose}"))?
            .is_some())
    })
    .await
    .map_err(|error| {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::anyhow!("{purpose} did not exit within {timeout:?}; {error:#}")
    })?;
    Ok(())
}

impl Drop for RuntimeComposeFixture {
    fn drop(&mut self) {
        if !self.closed
            && let Err(error) = block_on_async(self.cleanup())
        {
            eprintln!("two-replica cleanup fallback failed: {error:#}");
        }
    }
}

async fn replica_from_started_container(container: &str) -> Result<Replica> {
    let address = wait_published_health_port(container, Duration::from_secs(10)).await?;
    Ok(Replica {
        container: container.to_owned(),
        ready_url: format!("http://{address}/health/v1/readyz"),
    })
}

async fn wait_published_health_port(container: &str, timeout: Duration) -> Result<String> {
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let fatal = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    match await_condition_async_every(timeout, Duration::from_millis(100), || {
        let captured = std::sync::Arc::clone(&captured);
        let fatal = std::sync::Arc::clone(&fatal);
        let container = container.to_owned();
        async move {
            if let Ok(published) = docker_stdout(&["port", &container, "8083/tcp"]).await
                && let Some(address) = published
                    .lines()
                    .find(|line| line.starts_with("127.0.0.1:"))
            {
                *captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(address.to_owned());
                return true;
            }
            match container_is_running(&container).await {
                Ok(true) => false,
                Ok(false) => {
                    *fatal.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(format!("{container} exited before publishing its health port"));
                    true
                }
                Err(error) => {
                    *fatal.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(error.to_string());
                    true
                }
            }
        }
    })
    .await
    {
        Ok(()) => {
            if let Some(error) = fatal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let state = docker_stdout(&["inspect", "--format", "{{json .State}}", container])
                    .await
                    .unwrap_or_else(|error| format!("unable to inspect state: {error:#}"));
                let logs = docker_combined(&["logs", "--tail", "100", container])
                    .await
                    .unwrap_or_else(|error| format!("unable to collect logs: {error:#}"));
                bail!("{error}; state={state}\nlogs:\n{logs}");
            }
            captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .ok_or_else(|| anyhow::anyhow!("{container} published port wait succeeded without value"))
        }
        Err(_) => bail!("{container} did not publish a health port within {timeout:?}"),
    }
}

fn assert_critical_probes(report: &Value) -> Result<()> {
    ensure!(
        report["overall"] == "healthy",
        "readyz overall is not healthy: {report}"
    );
    for expected in CRITICAL_WORKER_PROBES {
        ensure!(
            report["checks"].as_array().is_some_and(|checks| checks
                .iter()
                .any(|check| { check["name"] == *expected && check["status"] == "healthy" })),
            "readyz is missing healthy critical worker {expected}: {report}"
        );
    }
    Ok(())
}

fn has_unhealthy_probe(report: &Value, name: &str) -> bool {
    report["checks"].as_array().is_some_and(|checks| {
        checks
            .iter()
            .any(|check| check["name"] == name && check["status"] == "unhealthy")
    })
}

fn record_first_monitor_error(slot: &Mutex<Option<String>>, error: String) {
    if let Ok(mut first) = slot.lock()
        && first.is_none()
    {
        *first = Some(error);
    }
}

fn require_drain_evidence(
    pre_term_samples: usize,
    post_term_samples: usize,
    first_error: Option<&str>,
    logs: &str,
    peer: &str,
    target: &str,
) -> Result<()> {
    ensure!(
        post_term_samples > pre_term_samples,
        "peer produced no new successful readiness sample while {target} drained; pre={pre_term_samples}, post={post_term_samples}"
    );
    ensure!(
        first_error.is_none(),
        "{peer} lost readiness or a critical worker while {target} drained; first_error={first_error:?}"
    );
    ensure!(
        logs.contains("all runtime resources drained; exiting"),
        "{target} exited without the exact runtimeexec drain-completion marker:\n{logs}"
    );
    Ok(())
}

fn http_get(url: &str) -> Result<(u16, String)> {
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "3",
            "--output",
            "-",
            "--write-out",
            "\n%{http_code}",
            url,
        ])
        .output()
        .with_context(|| format!("execute curl for {url}"))?;
    let rendered = String::from_utf8_lossy(&output.stdout);
    let (body, status) = rendered
        .rsplit_once('\n')
        .with_context(|| format!("curl response lacks status delimiter: {rendered}"))?;
    let status = status
        .trim()
        .parse::<u16>()
        .with_context(|| format!("parse curl status {status:?}"))?;
    Ok((status, body.to_owned()))
}

async fn docker_ok(args: &[&str]) -> Result<()> {
    let mut command = Command::new("docker");
    command.args(args);
    command_ok(&mut command, &format!("docker {}", args.join(" "))).await
}

async fn docker_stdout(args: &[&str]) -> Result<String> {
    let mut command = Command::new("docker");
    command.args(args);
    command_stdout(&mut command, &format!("docker {}", args.join(" "))).await
}

async fn docker_combined(args: &[&str]) -> Result<String> {
    let mut command = Command::new("docker");
    command.args(args);
    let output = command_output(&mut command, &format!("docker {}", args.join(" "))).await?;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(combined)
}

async fn container_is_running(container: &str) -> Result<bool> {
    Ok(
        docker_stdout(&["inspect", "--format", "{{.State.Running}}", container])
            .await?
            .trim()
            == "true",
    )
}

async fn command_ok(command: &mut Command, purpose: &str) -> Result<()> {
    command_output(command, purpose).await.map(|_| ())
}

async fn command_stdout(command: &mut Command, purpose: &str) -> Result<String> {
    let output = command_output(command, purpose).await?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

async fn command_output(command: &mut Command, purpose: &str) -> Result<Output> {
    command_output_with_timeout(command, purpose, COMMAND_TIMEOUT).await
}

async fn command_output_with_timeout(
    command: &mut Command,
    purpose: &str,
    timeout: Duration,
) -> Result<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("execute command to {purpose}"))?;
    let mut stdout = child.stdout.take().context("capture command stdout")?;
    let mut stderr = child.stderr.take().context("capture command stderr")?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None::<std::process::ExitStatus>));
        match await_pred_every(timeout, Duration::from_millis(100), || {
            let captured = std::sync::Arc::clone(&captured);
            async {
                if let Some(status) = child
                    .try_wait()
                    .with_context(|| format!("poll command to {purpose}"))?
                {
                    *captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(status);
                    return Ok(true);
                }
                Ok(false)
            }
        })
        .await
        {
            Ok(()) => captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .ok_or_else(|| anyhow::anyhow!("command wait succeeded without status"))?,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("command to {purpose} exceeded {timeout:?}");
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader panicked while trying to {purpose}"))?
        .with_context(|| format!("read stdout while trying to {purpose}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader panicked while trying to {purpose}"))?
        .with_context(|| format!("read stderr while trying to {purpose}"))?;
    let output = Output {
        status,
        stdout,
        stderr,
    };
    ensure!(
        output.status.success(),
        "failed to {purpose} (status={}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_migration_ledger_rejects_missing_extra_checksum_and_success_drift() {
        let expected = embedded_migration_ledger();
        assert!(!expected.is_empty());
        assert!(require_exact_migration_ledger(&expected, &expected).is_ok());

        let mut missing = expected.clone();
        missing.pop();
        assert!(require_exact_migration_ledger(&missing, &expected).is_err());

        let mut extra = expected.clone();
        extra.push(expected[0].clone());
        assert!(require_exact_migration_ledger(&extra, &expected).is_err());

        let mut checksum_drift = expected.clone();
        checksum_drift[0].checksum_hex.push('0');
        assert!(require_exact_migration_ledger(&checksum_drift, &expected).is_err());

        let mut failed = expected.clone();
        failed[0].success = false;
        assert!(require_exact_migration_ledger(&failed, &expected).is_err());
    }

    #[test]
    fn migration_barrier_uses_the_pinned_sqlx_database_lock() {
        assert_eq!(sqlx_migration_lock_id("rss"), 1_742_650_608_339_212_066);
    }

    #[test]
    fn compose_fixture_consumes_the_canonical_postgres_password_once() {
        let source = include_str!("runtime_compose_fixture.rs");
        let env_key = ["POSTGRES", "PASSWORD"].join("_");
        let copied_assignment = ["PGPASSWORD=", "postgres_demo_pw"].concat();
        assert_eq!(source.matches(&env_key).count(), 1);
        assert!(!source.contains(&copied_assignment));
    }

    #[test]
    fn drain_evidence_requires_post_term_sample_exact_marker_and_preserves_first_error() {
        const MARKER: &str = "all runtime resources drained; exiting";
        assert!(require_drain_evidence(2, 3, None, MARKER, "peer", "target").is_ok());
        assert!(require_drain_evidence(2, 2, None, MARKER, "peer", "target").is_err());
        assert!(
            require_drain_evidence(2, 3, Some("HTTP 503; body=down"), MARKER, "peer", "target")
                .is_err()
        );
        assert!(
            require_drain_evidence(2, 3, None, "shutdown sequence complete", "peer", "target")
                .is_err()
        );
    }
}
