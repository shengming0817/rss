//! Failure-only Docker state projection. Never collect environment, credentials or raw errors.
use super::{ContainerAsync, Duration};
use testcontainers::Image;

#[derive(Debug, serde::Deserialize)]
struct State {
    running: bool,
    exit_code: i64,
    oom_killed: bool,
    restarting: bool,
    configured: usize,
    published: usize,
}

fn render(bytes: &[u8]) -> Result<String, serde_json::Error> {
    let state: State = serde_json::from_slice(bytes)?;
    Ok(format!(
        "running={} exit_code={} oom_killed={} restarting={} configured={} published={}",
        state.running,
        state.exit_code,
        state.oom_killed,
        state.restarting,
        state.configured,
        state.published,
    ))
}

pub(super) async fn snapshot<I: Image>(container: &ContainerAsync<I>, port: u16) -> String {
    // The template projects only booleans, an exit code and binding counts. Docker
    // Config/Env, State.Error, host addresses and logs never enter this diagnostic.
    let template = r#"{"running":{{json .State.Running}},"exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}},"restarting":{{json .State.Restarting}},"configured":{{with index .HostConfig.PortBindings "PORT/tcp"}}{{len .}}{{else}}0{{end}},"published":{{with index .NetworkSettings.Ports "PORT/tcp"}}{{len .}}{{else}}0{{end}}}"#
        .replace("PORT", &port.to_string());
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("docker")
            .args(["inspect", "--format", &template, container.id()])
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    match result {
        Ok(Ok(output)) if output.status.success() => {
            render(&output.stdout).unwrap_or_else(|_| "diagnostic=invalid-state".into())
        }
        Ok(Ok(_)) => "diagnostic=inspect-failed".into(),
        Ok(Err(_)) => "diagnostic=inspect-unavailable".into(),
        Err(_) => "diagnostic=inspect-timeout".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn state_distinguishes_unpublished_running_and_exited_containers() -> anyhow::Result<()> {
        for (running, exit_code, oom) in [(true, 0, false), (false, 137, true)] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "running": running, "exit_code": exit_code, "oom_killed": oom,
                "restarting": false, "configured": 1, "published": 0,
                "Env": ["PASSWORD=secret"], "Error": "token=secret",
            }))?;
            let rendered = render(&bytes)?;
            assert!(rendered.contains(&format!("running={running} exit_code={exit_code}")));
            assert!(rendered.contains("configured=1 published=0"));
            assert!(!rendered.contains("secret"));
        }
        assert!(render(br#"{"running":"secret"}"#).is_err());
        Ok(())
    }
}
