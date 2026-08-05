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
fn l2_dr_recovery_help_is_local_and_does_not_open_runtime_configuration() -> anyhow::Result<()> {
    let cases: &[(&[&str], &[&str])] = &[
        (&["l2-dr-recovery", "--help"], &["l2-dr-recovery", "apply"]),
        (
            &["l2-dr-recovery", "apply", "--help"],
            &[
                "l2-dr-recovery",
                "apply",
                "operator-service-token-stdin",
                "epoch-id",
                "event-id",
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
fn l2_dr_recovery_SECRET_BAIT_assignment_fails_before_runtime() -> anyhow::Result<()> {
    let output = rss(&[
        "l2-dr-recovery",
        "apply",
        "--operator-service-token-stdin=SECRET_BAIT",
        "--operator-tenant",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890aa",
        "--tenant",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ab",
        "--epoch-id",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ac",
        "--change-ticket",
        "CHG-1837",
        "--pg-restore-point-micros",
        "1700000000000200",
        "--rabbitmq-restore-point-micros",
        "1700000000000100",
        "--event-id",
        "event-a",
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("l2-dr-recovery: invalid value; see --help"),
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
