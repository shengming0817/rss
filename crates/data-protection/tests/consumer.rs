//! F1.3: Unix-only process carrier for the independent allocator probe.
#![cfg(unix)]
use std::{path::Path, time::Duration};

#[path = "support/process.rs"]
mod process;

#[test]
fn public_paths_clear_owned_allocations_before_release() -> Result<(), Box<dyn std::error::Error>> {
    let owner = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = owner.join("tests/zeroize-probe");
    let output = owner.join("../../rss-external-check/zeroize-probe");
    std::fs::create_dir_all(&output)?;
    let log_path = output.join(format!("{}.log", std::process::id()));
    let log = std::fs::File::create(&log_path)?;
    let mut command = process::command(env!("CARGO"), Duration::from_secs(600));
    command
        .args(["run", "--locked", "--offline", "--manifest-path"])
        .arg(fixture.join("Cargo.toml"))
        .current_dir(&fixture)
        .env("CARGO_TARGET_DIR", output.join("target"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .stdout(log.try_clone()?)
        .stderr(log);
    let status = process::run(&mut command)?;
    let evidence = std::fs::read_to_string(&log_path)?;
    assert!(status.success(), "zeroize probe failed: {evidence}");
    assert!(
        evidence.contains("zeroize probe passed"),
        "missing execution evidence: {evidence}"
    );
    Ok(())
}
