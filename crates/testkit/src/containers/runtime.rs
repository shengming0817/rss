use super::{
    BoundedFileLogConsumer, CiContainerContext, ContainerAsync, ContainerService, ImageExt, Result,
};
use testcontainers::core::{CmdWaitFor, ExecCommand};
use testcontainers::runners::AsyncBuilder;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerRequest, GenericBuildableImage, GenericImage, Image};
use tokio::io::AsyncReadExt as _;

use super::{CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES, MINIO_ROOT_PASSWORD, MINIO_WORKLOAD_PASSWORD};

pub(super) async fn build_mosquitto_mtls_image() -> Result<GenericImage> {
    Ok(
        GenericBuildableImage::new("rss-mosquitto-mtls-fixture", "2.0.22-v4")
            .with_dockerfile_string(include_str!("../../fixtures/mqtt/Dockerfile"))
            .with_data(include_str!("../../fixtures/mqtt/plugin.c"), "plugin.c")
            .build_image()
            .await?,
    )
}

pub(super) async fn start<I, T>(image: T, service: ContainerService) -> Result<ContainerAsync<I>>
where
    I: Image,
    T: Into<ContainerRequest<I>> + Send,
{
    start_with_context(image, service, CiContainerContext::from_env()?).await
}

pub(super) async fn start_with_context<I, T>(
    image: T,
    service: ContainerService,
    context: Option<CiContainerContext>,
) -> Result<ContainerAsync<I>>
where
    I: Image,
    T: Into<ContainerRequest<I>> + Send,
{
    let Some(context) = context else {
        return Ok(image.start().await?);
    };
    let consumer = BoundedFileLogConsumer::new(&context.log_dir, service)?;
    let request = image
        .into()
        .with_labels(service.labels(&context))
        .with_log_consumer(move |frame: &testcontainers::core::logs::LogFrame| {
            if let Err(error) = consumer.write_frame(frame) {
                eprintln!("failed to persist integration container log: {error}");
            }
        });
    Ok(request.start().await?)
}

pub(super) async fn run_container_command<I: Image>(
    container: &ContainerAsync<I>,
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
            "container fixture '{operation}' initialization command failed (exit={:?}, stdout={:?}, stderr={:?})",
            self.exit_code,
            self.stdout,
            self.stderr
        )
    }
}

pub(super) async fn run_container_command_output<I: Image>(
    container: &ContainerAsync<I>,
    operation: &'static str,
    command: &[&str],
) -> Result<ContainerCommandOutput> {
    let mut result = container
        .exec(
            ExecCommand::new(
                command
                    .iter()
                    .map(|part| (*part).to_owned())
                    .collect::<Vec<_>>(),
            )
            .with_cmd_ready_condition(CmdWaitFor::exit()),
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "container fixture '{operation}' initialization failed (exit=unavailable): {error}"
            )
        })?;
    let exit_code = result.exit_code().await.map_err(|error| {
        anyhow::anyhow!(
            "container fixture '{operation}' exit inspection failed (exit=unavailable): {error}"
        )
    })?;
    let mut stdout = Vec::new();
    result.stdout().take((CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES + 1) as u64)
        .read_to_end(&mut stdout).await.map_err(|error| anyhow::anyhow!(
            "container fixture '{operation}' stdout collection failed (exit={exit_code:?}): {error}"
        ))?;
    let mut stderr = Vec::new();
    result.stderr().take((CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES + 1) as u64)
        .read_to_end(&mut stderr).await.map_err(|error| anyhow::anyhow!(
            "container fixture '{operation}' stderr collection failed (exit={exit_code:?}): {error}"
        ))?;
    Ok(ContainerCommandOutput {
        exit_code,
        stdout: bounded_redacted_command_output(stdout),
        stderr: bounded_redacted_command_output(stderr),
    })
}

pub(super) fn bounded_redacted_command_output(mut bytes: Vec<u8>) -> String {
    let truncated = bytes.len() > CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES;
    bytes.truncate(CONTAINER_COMMAND_OUTPUT_LIMIT_BYTES);
    let mut output = String::from_utf8_lossy(&bytes)
        .replace(MINIO_ROOT_PASSWORD, "<redacted>")
        .replace(MINIO_WORKLOAD_PASSWORD, "<redacted>");
    output.retain(|character| character == '\n' || character == '\t' || !character.is_control());
    if truncated {
        output.push_str("\n[rss-testkit: command output truncated]");
    }
    output
}
