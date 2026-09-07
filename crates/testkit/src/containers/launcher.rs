//! A short-lived owner for shared fixtures and one nextest child; no service protocol.
use super::{Result, exclusive_kafka_tls, exclusive_mqtt_tls, exclusive_rabbitmq};
use std::{
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn unique_name(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}
async fn docker(args: &[&str]) -> Result<std::process::Output> {
    let output = tokio::process::Command::new("docker")
        .args(args)
        .kill_on_drop(true)
        .output()
        .await?;
    // Docker may include endpoint credentials in raw errors; emit only closed diagnostic classes.
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    let reason = if stderr.contains("permission denied") || stderr.contains("access denied") {
        "permission-denied"
    } else if stderr.contains("conflict") || stderr.contains("active endpoints") {
        "resource-in-use"
    } else if stderr.contains("no such") || stderr.contains("not found") {
        "not-found"
    } else if stderr.contains("cannot connect") || stderr.contains("connection refused") {
        "daemon-unavailable"
    } else {
        "command-failed"
    };
    anyhow::ensure!(
        output.status.success(),
        "fixture Docker {} {} failed (reason={reason}, exit={:?}, stderr_bytes={})",
        args[0],
        args[1],
        output.status.code(),
        output.stderr.len()
    );
    Ok(output)
}
async fn cleanup(run: &str) -> Result<()> {
    let mut failed = false;
    for resource in ["container", "network"] {
        let filter = format!("label=rss.test-run={run}");
        let flags = if resource == "container" { "-aq" } else { "-q" };
        let listed = docker(&[resource, "ls", flags, "--filter", &filter]).await;
        match listed.and_then(|output| String::from_utf8(output.stdout).map_err(Into::into)) {
            Ok(ids) => {
                for id in ids.split_whitespace() {
                    if let Err(error) = docker(&[resource, "rm", "-f", id]).await {
                        eprintln!("testkit: cleanup remove resource={resource} id={id}: {error}");
                        failed = true;
                    }
                }
            }
            Err(error) => {
                eprintln!("testkit: cleanup list resource={resource}: {error}");
                failed = true;
            }
        }
    }
    anyhow::ensure!(
        !failed,
        "fixture cleanup failed; all enumerable resources were attempted"
    );
    Ok(())
}
struct Fixtures {
    _rabbit: Option<super::RabbitFixture>,
    _kafka: Option<super::KafkaTlsFixture>,
    _mqtt: Option<super::MqttTlsFixture>,
}
async fn prepare(providers: &[String], path: &Path) -> Result<Fixtures> {
    // Guards outlive nextest and every test process it owns, including failure paths.
    let rabbit = if providers.iter().any(|p| p == "amqp") {
        Some(exclusive_rabbitmq().await?)
    } else {
        None
    };
    let kafka = if providers.iter().any(|p| p == "kafka") {
        Some(exclusive_kafka_tls(super::KafkaTlsServerIdentity::MatchingHost).await?)
    } else {
        None
    };
    let mqtt = if providers.iter().any(|p| p == "mqtt") {
        Some(exclusive_mqtt_tls(true).await?)
    } else {
        None
    };
    let d = super::descriptor::Descriptor {
        version: 1,
        amqp: rabbit.as_ref().map(|r| r.descriptor()),
        kafka: kafka.as_ref().map(|k| k.descriptor()),
        mqtt: mqtt.as_ref().map(|m| m.descriptor()),
    };
    std::fs::write(path, serde_json::to_vec(&d)?)?;
    Ok(Fixtures {
        _rabbit: rabbit,
        _kafka: kafka,
        _mqtt: mqtt,
    })
}
async fn execute(
    command: &[String],
    path: &Path,
    terminate: &mut tokio::signal::unix::Signal,
    interrupt: &mut tokio::signal::unix::Signal,
) -> Result<i32> {
    let mut child = tokio::process::Command::new(&command[0])
        .args(&command[1..])
        .env("RSS_TEST_FIXTURES", path)
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    let group = ProcessGroup(
        child
            .id()
            .ok_or_else(|| anyhow::anyhow!("missing nextest PID"))?,
    );
    let result = tokio::select! {
        status = child.wait() => Some(status?),
        _ = terminate.recv() => None,
        _ = interrupt.recv() => None,
    };
    if let Some(status) = result {
        return Ok(status.code().unwrap_or(1));
    }
    // nextest owns per-test process groups: let it forward termination and reap those first.
    group.signal("-TERM");
    if tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .is_err()
    {
        group.signal("-KILL");
        child.kill().await?;
        child.wait().await?;
    }
    anyhow::bail!("fixture launcher cancelled")
}

// Drop runs on startup/test cancellation too; terminate the entire nextest descendant group.
struct ProcessGroup(u32);
impl ProcessGroup {
    fn signal(&self, signal: &str) {
        let _ = std::process::Command::new("/bin/kill")
            .args([signal, "--", &format!("-{}", self.0)])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.signal("-KILL");
    }
}

/// Run selected provider fixtures around one nextest command. SIGTERM/INT cancel startup or tests.
#[allow(clippy::disallowed_methods)]
// reason: this executable owns timing and cancellation for development resources.
pub async fn launch(arguments: Vec<String>) -> Result<i32> {
    let separator = arguments.iter().position(|a| a == "--").ok_or_else(|| {
        anyhow::anyhow!("usage: rss-test-launcher [amqp kafka mqtt] -- command args")
    })?;
    let (providers, tail) = arguments.split_at(separator);
    let command = &tail[1..];
    anyhow::ensure!(!command.is_empty(), "missing nextest command");
    anyhow::ensure!(
        providers
            .iter()
            .all(|p| matches!(p.as_str(), "amqp" | "kafka" | "mqtt")),
        "unknown shared provider"
    );
    let run = std::env::var("RSS_TEST_RUN_ID")?;
    anyhow::ensure!(super::is_safe_label_token(&run), "invalid fixture run ID");
    let file = tempfile::NamedTempFile::new()?; // private 0600; never included in CI artifacts
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let prepared = tokio::select! {
        result = prepare(providers, file.path()) => result,
        _ = terminate.recv() => Err(anyhow::anyhow!("fixture startup terminated")),
        _ = interrupt.recv() => Err(anyhow::anyhow!("fixture startup interrupted")),
    };
    let result = match prepared {
        Ok(_fixtures) => execute(command, file.path(), &mut terminate, &mut interrupt).await,
        Err(error) => Err(error),
    };
    let mut stage = super::runtime::Stage::new("cleanup", "all", 0);
    // One owner deadline bounds the entire sweep, irrespective of resource count.
    let cleaned = tokio::time::timeout(Duration::from_secs(30), cleanup(&run)).await;
    stage.finish(matches!(&cleaned, Ok(Ok(()))));
    cleaned??;
    result
}
