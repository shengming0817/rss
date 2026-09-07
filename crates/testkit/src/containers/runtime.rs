use super::{ContainerAsync, Result};
use testcontainers::ImageExt as _;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerRequest, Image};
use tokio::io::AsyncReadExt as _;

use super::CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES;

#[allow(clippy::disallowed_methods)]
// reason: fixture owner measures bounded resource operations.
pub(super) async fn start<I, T>(image: T) -> Result<ContainerAsync<I>>
where
    I: Image,
    T: Into<ContainerRequest<I>> + Send,
{
    let mut request = image.into();
    if let Ok(run) = std::env::var("RSS_TEST_RUN_ID") {
        anyhow::ensure!(super::is_safe_label_token(&run), "invalid fixture run ID");
        request = request.with_label("rss.test-run", run);
    }
    let image = format!("{}:{}", request.image().name(), request.image().tag());
    let started = std::time::Instant::now();
    let present = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::process::Command::new("docker")
            .args(["image", "inspect", &image])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await??;
    if !present.success() {
        let pulled = tokio::time::timeout(
            std::time::Duration::from_secs(110),
            tokio::process::Command::new("docker")
                .args(["pull", &image])
                .kill_on_drop(true)
                .status(),
        )
        .await??;
        anyhow::ensure!(pulled.success(), "fixture image preparation failed");
    }
    metric(
        "image",
        request.image().name(),
        started.elapsed().as_secs_f64(),
        0,
    )?;
    let started = std::time::Instant::now();
    let container =
        tokio::time::timeout(std::time::Duration::from_secs(110), request.start()).await??;
    metric(
        "start-ready",
        container.image().name(),
        started.elapsed().as_secs_f64(),
        1,
    )?;
    Ok(container)
}

pub(super) async fn run_container_command(
    container: &impl ContainerId,
    operation: &'static str,
    command: &[&str],
) -> Result<()> {
    let output = run_container_command_output(container, operation, command).await?;
    if output.exit_code == Some(0) {
        Ok(())
    } else {
        Err(output.failure(operation))
    }
}

pub(super) struct ContainerCommandOutput {
    pub(super) exit_code: Option<i64>,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

impl ContainerCommandOutput {
    pub(super) fn failure(&self, operation: &'static str) -> anyhow::Error {
        anyhow::anyhow!(
            "container fixture '{operation}' initialization command failed (exit={:?}, stdout_bytes={}, stderr_bytes={})",
            self.exit_code,
            self.stdout.len(),
            self.stderr.len()
        )
    }
}

/// The launcher owns shared containers; children retain only a management endpoint.
pub(super) enum Container<I: Image> {
    Owned(Box<ContainerAsync<I>>),
    Shared(String),
}
pub(super) trait ContainerId {
    fn container_id(&self) -> &str;
}
impl<I: Image> ContainerId for ContainerAsync<I> {
    fn container_id(&self) -> &str {
        self.id()
    }
}
impl<I: Image> ContainerId for Container<I> {
    fn container_id(&self) -> &str {
        match self {
            Self::Owned(c) => c.id(),
            Self::Shared(id) => id,
        }
    }
}
impl<T: ContainerId> ContainerId for Box<T> {
    fn container_id(&self) -> &str {
        (**self).container_id()
    }
}

pub(super) async fn run_container_command_output(
    container: &impl ContainerId,
    operation: &'static str,
    command: &[&str],
) -> Result<ContainerCommandOutput> {
    let mut child = tokio::process::Command::new("docker")
        .args(["exec", container.container_id()])
        .args(command)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let collect = async {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let out = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing command stdout"))?;
        let err = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing command stderr"))?;
        let (a, b) = tokio::join!(
            read_bounded(out, &mut stdout),
            read_bounded(err, &mut stderr)
        );
        a?;
        b?;
        let status = child.wait().await?;
        Ok::<_, anyhow::Error>(ContainerCommandOutput {
            exit_code: status.code().map(i64::from),
            stdout: bounded_command_output(stdout),
            stderr: bounded_command_output(stderr),
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(15), collect)
        .await
        .map_err(|_| anyhow::anyhow!("container fixture '{operation}' command deadline elapsed"))?
}

pub(super) fn bounded_command_output(mut bytes: Vec<u8>) -> String {
    let truncated = bytes.len() > CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES;
    bytes.truncate(CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES);
    let mut output = String::from_utf8_lossy(&bytes).into_owned();
    output.retain(|character| character == '\n' || character == '\t' || !character.is_control());
    if truncated {
        output.push_str("\n[rss-testkit: command output truncated]");
    }
    output
}

pub(super) fn metric(phase: &str, provider: &str, seconds: f64, starts: u32) -> Result<()> {
    use std::io::Write as _;
    if let Ok(path) = std::env::var("RSS_TEST_METRICS") {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(
            file,
            "{}",
            serde_json::json!({"phase": phase, "provider": provider, "seconds": seconds, "starts": starts})
        )?;
    }
    eprintln!("testkit: phase={phase} provider={provider} seconds={seconds:.3} starts={starts}");
    Ok(())
}

async fn read_bounded(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut buffer = [0; 4096];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        let retain =
            count.min((CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES + 1).saturating_sub(output.len()));
        output.extend_from_slice(&buffer[..retain]);
    }
}
