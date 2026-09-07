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
pub(super) fn text(d: &serde_json::Value, key: &str) -> Result<String> {
    d.get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("invalid fixture field: {key}"))
}
pub(super) fn port(d: &serde_json::Value, key: &str) -> Result<u16> {
    d.get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
        .filter(|v| *v != 0)
        .ok_or_else(|| anyhow::anyhow!("invalid fixture port: {key}"))
}
pub(super) fn descriptor(provider: &str) -> Result<serde_json::Value> {
    let path = std::env::var("RSS_TEST_FIXTURES")
        .map_err(|_| anyhow::anyhow!("shared fixture requires the Make test launcher"))?;
    let file = std::fs::File::open(path)?;
    let d: serde_json::Value = serde_json::from_reader(file)?;
    anyhow::ensure!(d["version"] == 1, "unsupported fixture descriptor");
    let provider = d
        .get(provider)
        .filter(|v| v.is_object())
        .ok_or_else(|| anyhow::anyhow!("selected provider absent from fixture descriptor"))?;
    let id = text(provider, "container")?;
    anyhow::ensure!(
        id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid fixture container endpoint"
    );
    Ok(provider.clone())
}

async fn docker(args: &[&str]) -> Result<std::process::Output> {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("docker")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    anyhow::ensure!(
        output.status.success(),
        "fixture Docker resource operation failed"
    );
    Ok(output)
}
async fn cleanup(run: &str) -> Result<()> {
    for resource in ["container", "network"] {
        let filter = format!("label=rss.test-run={run}");
        let args = if resource == "container" {
            vec![resource, "ls", "-aq", "--filter", &filter]
        } else {
            vec![resource, "ls", "-q", "--filter", &filter]
        };
        let ids = docker(&args).await?;
        for id in String::from_utf8(ids.stdout)?.split_whitespace() {
            docker(&[resource, "rm", "-f", id]).await?;
        }
    }
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
    let mut d = serde_json::json!({"version": 1});
    if let Some(r) = &rabbit {
        d["amqp"] = r.descriptor();
    }
    if let Some(k) = &kafka {
        d["kafka"] = k.descriptor();
    }
    if let Some(m) = &mqtt {
        d["mqtt"] = m.descriptor();
    }
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
    let started = std::time::Instant::now();
    let cleaned = cleanup(&run).await;
    super::runtime::metric("cleanup", "all", started.elapsed().as_secs_f64(), 0)?;
    cleaned?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_connection_fields_fail_closed() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"port": 0}),
            serde_json::json!({"port": 65536}),
            serde_json::json!({"port": "5672"}),
        ] {
            assert!(port(&value, "port").is_err());
        }
        assert_eq!(
            port(&serde_json::json!({"port": 5672}), "port").ok(),
            Some(5672)
        );
        assert!(text(&serde_json::json!({"host": ""}), "host").is_err());
        assert_ne!(unique_name("topic"), unique_name("topic"));
    }
}
