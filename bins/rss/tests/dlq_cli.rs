use std::process::Command;

fn rss(args: &[&str]) -> anyhow::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_rss"))
        .env_clear()
        .args(args)
        .output()
        .map_err(anyhow::Error::from)
}

fn assert_no_leaks(args: &[&str], stdout: &str, stderr: &str) {
    for leak in ["SECRET_BAIT", "Clap surface", "clap-rs"] {
        assert!(
            !stdout.contains(leak),
            "args={args:?} help leaked implementer text {leak}: {stdout}"
        );
    }
    for runtime_leak in [
        "RSS_PG_",
        "DATABASE",
        "configuration",
        "postgres://",
        "secret bundle",
    ] {
        assert!(
            !stdout.contains(runtime_leak),
            "args={args:?} stdout leaked runtime: {stdout}"
        );
        assert!(
            !stderr.contains(runtime_leak),
            "args={args:?} stderr leaked runtime: {stderr}"
        );
    }
}

#[test]
fn dlq_help_is_local_and_does_not_open_runtime_configuration() -> anyhow::Result<()> {
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["dlq", "--help"],
            &[
                "dlq",
                "list",
                "inspect",
                "replay-dead-letter",
                "redrive-outbox",
                "resolve-expired-outbox",
            ],
        ),
        (
            &["dlq", "list", "--help"],
            &["dlq", "list", "operator-service-token-stdin", "limit"],
        ),
        (
            &["dlq", "inspect", "--help"],
            &["dlq", "inspect", "kind", "id"],
        ),
        (
            &["dlq", "replay-dead-letter", "--help"],
            &["dlq", "replay-dead-letter", "dead-letter-id", "replay-id"],
        ),
        (
            &["dlq", "redrive-outbox", "--help"],
            &["dlq", "redrive-outbox", "event-id"],
        ),
        (
            &["dlq", "resolve-expired-outbox", "--help"],
            &[
                "dlq",
                "resolve-expired-outbox",
                "change-ticket",
                "resolution-kind",
                "evidence-event-id",
            ],
        ),
    ];
    for &(args, tokens) in cases {
        let output = rss(args)?;
        assert!(
            output.status.success(),
            "args={args:?} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        for token in tokens {
            assert!(
                stdout.contains(token),
                "args={args:?} missing help token {token}: {stdout}"
            );
        }
        assert_no_leaks(args, &stdout, &stderr);
    }
    Ok(())
}

#[test]
#[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
fn dlq_SECRET_BAIT_assignment_fails_before_runtime() -> anyhow::Result<()> {
    let output = rss(&[
        "dlq",
        "list",
        "--operator-service-token-stdin=SECRET_BAIT",
        "--operator-tenant",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ab",
        "--tenant",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ab",
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("dlq: invalid value; see --help"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("SECRET_BAIT"),
        "diagnostic leaked SECRET_BAIT: {stderr}"
    );
    for runtime_leak in ["RSS_PG_", "DATABASE", "postgres://"] {
        assert!(!stderr.contains(runtime_leak), "stderr={stderr}");
    }
    Ok(())
}
