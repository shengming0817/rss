use std::process::Command;

fn rss(args: &[&str]) -> anyhow::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_rss"))
        .env_clear()
        .args(args)
        .output()
        .map_err(anyhow::Error::from)
}

#[test]
fn device_latent_help_is_local_and_does_not_open_runtime_configuration() -> anyhow::Result<()> {
    for args in [
        ["device-latent", "--help"].as_slice(),
        ["device-latent", "inspect", "--help"].as_slice(),
    ] {
        let output = rss(args)?;
        assert!(
            output.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.starts_with("usage: rss device-latent inspect "));
        assert!(stdout.contains("--output json|prometheus"));
        assert!(!stdout.contains("operator-tenant"));
        assert!(output.stderr.is_empty());
    }
    Ok(())
}

#[test]
fn unknown_device_latent_action_fails_before_runtime_configuration() -> anyhow::Result<()> {
    let output = rss(&["device-latent", "resume"])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("unknown rss command"), "stderr={stderr}");
    for runtime_leak in ["RSS_PG_", "DATABASE", "configuration", "postgres://"] {
        assert!(!stderr.contains(runtime_leak), "stderr={stderr}");
    }
    Ok(())
}
