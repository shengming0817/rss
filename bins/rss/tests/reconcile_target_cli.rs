use std::process::Command;

fn rss(args: &[&str]) -> anyhow::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_rss"))
        .env_clear()
        .args(args)
        .output()
        .map_err(anyhow::Error::from)
}

#[test]
fn reconcile_target_help_is_local_and_does_not_open_runtime_configuration() -> anyhow::Result<()> {
    for args in [
        ["reconcile-target", "--help"].as_slice(),
        ["reconcile-target", "inspect", "--help"].as_slice(),
        ["reconcile-target", "resume", "--help"].as_slice(),
    ] {
        let output = rss(args)?;
        assert!(
            output.status.success(),
            "args={args:?} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            stdout.contains("reconcile-target")
                || stdout.contains("Inspect")
                || stdout.contains("Resume"),
            "args={args:?} stdout={stdout}"
        );
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
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains(runtime_leak),
                "args={args:?} stderr leaked runtime: {stderr}"
            );
        }
    }
    Ok(())
}

#[test]
#[allow(non_snake_case)] // 验收过滤名含 SECRET_BAIT
fn reconcile_target_SECRET_BAIT_assignment_fails_before_runtime() -> anyhow::Result<()> {
    let output = rss(&[
        "reconcile-target",
        "resume",
        "--operator-service-token-stdin=SECRET_BAIT",
        "--operator-tenant",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ab",
        "--tenant",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ab",
        "--target-id",
        "018f5d8a-7b6c-7d2e-8a1b-1234567890ac",
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("invalid reconcile-target arguments"),
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
