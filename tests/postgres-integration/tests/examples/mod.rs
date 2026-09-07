//! Fixture owner for both in-workspace and isolated, artifact-only example processes.
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Default)]
struct OutputTail {
    bytes: Vec<u8>,
    truncated: bool,
}

impl OutputTail {
    async fn drain(&mut self, mut pipe: impl AsyncRead + Unpin) -> std::io::Result<()> {
        const LIMIT: usize = 16 * 1024;
        let mut block = [0; 4096];
        loop {
            let count = pipe.read(&mut block).await?;
            if count == 0 {
                return Ok(());
            }
            let excess = (self.bytes.len() + count).saturating_sub(LIMIT);
            self.bytes.drain(..excess);
            self.truncated |= excess != 0;
            self.bytes.extend_from_slice(&block[..count]);
        }
    }

    fn diagnostic(&self, input: &serde_json::Value) -> String {
        let mut output = String::from_utf8_lossy(&self.bytes).into_owned();
        if self.truncated {
            // Omit the partial first line, including any cut credential fragment.
            output = output
                .split_once('\n')
                .map_or("", |(_, tail)| tail)
                .to_owned();
        }
        for key in [
            "password",
            "publisher_url",
            "subscriber_url",
            "pg_ca",
            "amqp_ca",
        ] {
            if let Some(secret) = input[key].as_str().filter(|value| !value.is_empty()) {
                output = output.replace(secret, "[redacted]");
                if let Some((_, rest)) = secret.split_once("://")
                    && let Some((credentials, _)) = rest.split_once('@')
                    && let Some((_, password)) = credentials.split_once(':')
                    && !password.is_empty()
                {
                    output = output.replace(password, "[redacted]");
                }
            }
        }
        output
            .retain(|character| character == '\n' || character == '\t' || !character.is_control());
        if self.truncated {
            output.insert_str(0, "[truncated]\n");
        }
        output
    }
}

async fn run_binary(
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
    let mut stdin = child.stdin.take().expect("configured piped stdin");
    let stdout = child.stdout.take().expect("configured piped stdout");
    let stderr = child.stderr.take().expect("configured piped stderr");
    let bytes = serde_json::to_vec(input)?;
    let (mut out, mut err) = (OutputTail::default(), OutputTail::default());
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
        Ok(Err(_)) => "process-io-error".to_owned(),
        Err(_) => "timeout".to_owned(),
    };
    let _ = child.start_kill();
    let reaped = matches!(
        tokio::time::timeout(Duration::from_secs(5), child.wait()).await,
        Ok(Ok(_))
    );
    anyhow::bail!(
        "external provider example {binary}: {outcome}, reaped={reaped}; stdout={} stderr={}",
        out.diagnostic(input),
        err.diagnostic(input)
    )
}

pub(super) async fn run(
    pg: &testkit::PgTlsFixture,
    network: &testkit::BridgeNetwork,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let route = "rss.example";
    let broker = testkit::rabbitmq_tls(
        route,
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "example-broker",
        },
    )
    .await?;
    let params = pg.params();
    let binaries: Vec<String> = match std::env::var("RSS_EXAMPLE_CONSUMERS") {
        Ok(value) => {
            let values: Vec<String> = serde_json::from_str(&value)?;
            anyhow::ensure!(!values.is_empty(), "empty external example selection");
            values
        }
        Err(std::env::VarError::NotPresent) => vec![String::new()],
        Err(error) => return Err(error.into()),
    };
    for (index, binary) in binaries.iter().enumerate() {
        let id = format!("external-example-{index}");
        let input = serde_json::json!({
            "host": params.host, "port": params.port, "database": params.database,
            "username": "tmsg_runtime", "password": "fixture-only", "pg_ca": pg.ca_pem(),
            "tenant": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "target": ([1; 16]), "lineage": ([2; 16]), "epoch": 1,
            "id": id, "route": route, "publisher_url": broker.publisher_url(), "subscriber_url": broker.subscriber_url(), "amqp_ca": broker.ca_pem(),
        });
        if binary.is_empty() {
            rss_examples::providers::run(serde_json::from_value(input)?).await?;
        } else {
            run_binary(binary, &input, Duration::from_secs(60)).await?;
        }
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.business_effects WHERE id=$1")
                .bind(id)
                .fetch_one(owner)
                .await?;
        assert_eq!(count, 1, "real business effect committed once");
        if !binary.is_empty() {
            eprintln!("external-provider-consumer PASS {binary}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn consumer_timeout_reaps_child_and_retains_bounded_diagnostics() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir()?;
    let binary = directory.path().join("consumer");
    std::fs::write(
        &binary,
        "#!/bin/sh\necho timeout-marker >&2\nexec /bin/sleep 30\n",
    )?;
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))?;
    let error = run_binary(
        binary.to_str().expect("UTF-8 fixture path"),
        &serde_json::json!({}),
        Duration::from_secs(15),
    )
    .await
    .expect_err("sleeping consumer must time out")
    .to_string();
    assert!(error.contains("timeout"), "{error}");
    assert!(error.contains("reaped=true"), "{error}");
    assert!(error.contains("timeout-marker"), "{error}");
    assert!(
        error.contains(binary.to_str().expect("UTF-8 fixture path")),
        "{error}"
    );
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
        binary.to_str().expect("UTF-8 fixture path"),
        &serde_json::json!({"password":"fixture-password"}),
        Duration::from_secs(30),
    )
    .await
    .expect_err("consumer exits with failure")
    .to_string();
    assert!(error.contains("truncated"), "{error}");
    assert!(error.contains("tail-marker"), "{error}");
    assert!(!error.contains("fixture-password"));
    assert!(error.len() < 40_000);
    Ok(())
}
