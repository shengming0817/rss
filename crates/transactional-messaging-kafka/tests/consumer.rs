//! Independent resolution: no workspace consumer can provide a missing dependency/feature.
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
#[test]
fn independent_tokio_host() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("src"))?;
    let owner = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::copy(
        owner.join("../../Cargo.lock"),
        root.path().join("Cargo.lock"),
    )?;
    fs::write(
        root.path().join("Cargo.toml"),
        format!(
            r#"[package]
name = "kafka-independent-host"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
kafka = {{ package = "rss-transactional-messaging-kafka", path = {owner:?}, default-features = false }}
"#
        ),
    )?;
    fs::write(
        root.path().join("src/lib.rs"),
        r#"
use kafka::{KafkaConfig, KafkaPublisher, KafkaError};
pub async fn host(config: KafkaConfig) -> Result<(), KafkaError> {
    let (_publisher, resource) = KafkaPublisher::create(config, std::time::Duration::from_secs(5)).await?;
    resource.shutdown(std::time::Duration::from_secs(5)).await
}
"#,
    )?;
    let log = root.path().join("cargo.log");
    let output = fs::File::create(&log)?;
    let mut child = Command::new(env!("CARGO"))
        .args(["check", "--offline"])
        .current_dir(root.path())
        .env("CARGO_TARGET_DIR", root.path().join("target"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output))
        .spawn()?;
    let mut status = None;
    for _ in 0..1200 {
        if let Some(done) = child.try_wait()? {
            status = Some(done);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let Some(status) = status else {
        child.kill()?;
        child.wait()?;
        anyhow::bail!(
            "independent compilation exceeded 120s:\n{}",
            fs::read_to_string(&log)?
        );
    };
    assert!(status.success(), "{}", fs::read_to_string(log)?);
    let graph = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--offline",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
        ])
        .current_dir(root.path())
        .output()?;
    assert!(graph.status.success());
    let graph = String::from_utf8(graph.stdout)?;
    for absent in [
        "rss-runtime ",
        "rss-transactional-messaging-postgres ",
        "rss-transactional-messaging-amqp ",
    ] {
        assert!(!graph.lines().any(|line| line.starts_with(absent)));
    }
    assert!(graph.lines().any(|line| line.starts_with("rdkafka ")));
    Ok(())
}
