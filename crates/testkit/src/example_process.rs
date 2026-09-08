//! Bounded child-process I/O for public-API example consumers.
//! ref: tokio tokio/src/process/mod.rs@tokio-1.50.0
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Default)]
struct OutputSummary {
    bytes: u64,
}

impl OutputSummary {
    async fn drain(&mut self, mut pipe: impl AsyncRead + Unpin) -> std::io::Result<()> {
        let mut block = [0; 4096];
        loop {
            let count = pipe.read(&mut block).await?;
            if count == 0 {
                return Ok(());
            }
            self.bytes = self.bytes.saturating_add(count as u64);
        }
    }
}

pub async fn run_binary(
    binary: &str,
    input: &serde_json::Value,
    deadline: Duration,
) -> anyhow::Result<()> {
    let mut child = tokio::process::Command::new(binary)
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing piped stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing piped stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("missing piped stderr"))?;
    let bytes = serde_json::to_vec(input)?;
    let (mut out, mut err) = (OutputSummary::default(), OutputSummary::default());
    let operation = tokio::time::timeout(deadline, async {
        let write = async {
            stdin.write_all(&bytes).await?;
            drop(stdin);
            Ok::<_, std::io::Error>(())
        };
        let (_, (), (), status) =
            tokio::try_join!(write, out.drain(stdout), err.drain(stderr), child.wait())?;
        Ok::<_, std::io::Error>(status)
    })
    .await;
    let outcome = match operation {
        Ok(Ok(status)) if status.success() => return Ok(()),
        Ok(Ok(status)) => status.to_string(),
        Ok(Err(error)) => format!(
            "process-io-error kind={:?} os={:?}",
            error.kind(),
            error.raw_os_error()
        ),
        Err(_) => "timeout".to_owned(),
    };
    let _ = child.start_kill();
    let reaped = matches!(
        tokio::time::timeout(Duration::from_secs(5), child.wait()).await,
        Ok(Ok(_))
    );
    anyhow::bail!(
        "external provider example {binary}: {outcome}, reaped={reaped}; stdout_bytes={} stderr_bytes={}",
        out.bytes,
        err.bytes
    )
}

/// Connection data for a fixture-owned non-owner role; never logged by this helper.
pub fn pg_input(pg: &crate::PgTlsFixture, username: &str, tenant: &str) -> serde_json::Value {
    let p = pg.params();
    serde_json::json!({"host":p.host,"port":p.port,"database":p.database,
        "username":username,"password":"fixture-only","pg_ca":pg.ca_pem(),"tenant":tenant})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn consumer_timeout_reaps_child() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir()?;
        let binary = directory.path().join("consumer");
        std::fs::write(
            &binary,
            "#!/bin/sh\necho timeout-marker >&2\nexec /bin/sleep 30\n",
        )?;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))?;
        let error = run_binary(
            binary
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("fixture path"))?,
            &serde_json::json!({}),
            Duration::from_secs(1),
        )
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("consumer did not time out"))?
        .to_string();
        assert!(error.contains("timeout"), "{error}");
        assert!(error.contains("reaped=true"), "{error}");
        assert!(
            error.contains(
                binary
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("fixture path"))?
            ),
            "{error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn encoded_child_credentials_never_enter_failure_diagnostics() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir()?;
        let binary = directory.path().join("consumer");
        std::fs::write(
            &binary,
            "#!/bin/sh\nprintf '%s\\n' 'ab\\ncd' 'ab%0Acd' 'YWIKY2Q=' 'ab' 'cd' >&2\nexit 7\n",
        )?;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))?;
        let error = run_binary(
            binary
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("fixture path"))?,
            &serde_json::json!({"password": "ab\ncd"}),
            Duration::from_secs(10),
        )
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("consumer unexpectedly succeeded"))?
        .to_string();
        for encoded in ["ab\\ncd", "ab%0Acd", "YWIKY2Q="] {
            assert!(
                !error.contains(encoded),
                "encoded credential escaped: {error}"
            );
        }
        assert!(error.contains("stderr_bytes="), "{error}");
        Ok(())
    }

    #[tokio::test]
    async fn consumer_output_is_bounded_drained_and_redacted() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir()?;
        let binary = directory.path().join("consumer");
        std::fs::write(
            &binary,
            "#!/bin/sh\ni=0; while [ $i -lt 5000 ]; do echo noisy-output; echo noisy-error >&2; i=$((i+1)); done\necho fixture-password >&2\necho tail-marker >&2\nexit 7\n",
        )?;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))?;
        let error = run_binary(
            binary
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("fixture path"))?,
            &serde_json::json!({"password":"fixture-password"}),
            Duration::from_secs(30),
        )
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("consumer unexpectedly succeeded"))?
        .to_string();
        assert!(error.contains("stdout_bytes=65000"), "{error}");
        assert!(error.contains("stderr_bytes="), "{error}");
        assert!(!error.contains("tail-marker"));
        assert!(!error.contains("fixture-password"));
        assert!(error.len() < 1000);
        Ok(())
    }
}
