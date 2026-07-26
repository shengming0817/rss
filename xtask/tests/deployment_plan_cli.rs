use std::process::{Command, Output};

fn run(args: &[&str]) -> anyhow::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .map_err(Into::into)
}

#[test]
fn deployment_plan_check_accepts_the_committed_exact_set() -> anyhow::Result<()> {
    let output = run(&["deployment", "plan", "check"])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn deployment_plan_cli_rejects_every_compatibility_shape_without_echoing_bait() -> anyhow::Result<()>
{
    for args in [
        vec!["deployment", "plan"],
        vec!["deployment", "plan", "--check"],
        vec!["deployment", "plan", "check", "runtime"],
        vec!["deployment", "plan", "render", "--output", "SECRET_BAIT"],
        vec!["deployment-plan", "check"],
    ] {
        let output = run(&args)?;
        assert!(!output.status.success(), "unexpectedly accepted {args:?}");
        assert!(output.stdout.is_empty(), "partial stdout for {args:?}");
        assert!(!String::from_utf8(output.stderr)?.contains("SECRET_BAIT"));
    }
    Ok(())
}
