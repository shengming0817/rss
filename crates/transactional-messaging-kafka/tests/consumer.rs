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
    let mut command = Command::new(env!("CARGO"));
    command
        .args(["check", "--offline"])
        .current_dir(root.path())
        .env("CARGO_TARGET_DIR", root.path().join("target"))
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let mut status = None;
    for _ in 0..1200 {
        if let Some(done) = child.try_wait()? {
            status = Some(done);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let Some(status) = status else {
        terminate_compilation(&mut child)?;
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

fn terminate_compilation(child: &mut std::process::Child) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // Keep the leader unreaped until its whole group has been signalled: its PID cannot
        // be reused as another process group's identity while native compiler children exit.
        let killed = Command::new("/bin/kill")
            .args(["-KILL", &format!("-{}", child.id())])
            .stderr(Stdio::null())
            .status();
        if !killed.is_ok_and(|status| status.success()) {
            // The leader may finish between the deadline poll and kill. Always reap it;
            // if it is still alive, retire it before reporting a group-cleanup failure.
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            child.kill()?;
            child.wait()?;
            return Err(std::io::Error::other(
                "failed to terminate compiler process group",
            ));
        }
    }
    #[cfg(not(unix))]
    child.kill()?;
    child.wait()?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn timeout_cleanup_closes_descendant_output() -> anyhow::Result<()> {
    use std::io::{BufRead, Read};
    use std::os::unix::process::CommandExt as _;
    let mut child = Command::new("/bin/sh")
        .args(["-c", "sleep 60 & echo ready; wait"])
        .process_group(0)
        .stdout(Stdio::piped())
        .spawn()?;
    let group = child.id();
    let mut output = std::io::BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("missing child output"))?,
    );
    let mut ready = String::new();
    output.read_line(&mut ready)?;
    assert_eq!(ready.trim(), "ready");
    terminate_compilation(&mut child)?;
    let (send, receive) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut rest = Vec::new();
        let _ = send.send(output.read_to_end(&mut rest));
    });
    let ended = receive.recv_timeout(Duration::from_secs(2));
    if ended.is_err() {
        // Cleanup the deliberately leaked descendant when running the red regression.
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &format!("-{group}")])
            .status();
    }
    assert!(
        ended.is_ok(),
        "compiler descendant retained its output after timeout"
    );
    ended??;
    reader
        .join()
        .map_err(|_| std::io::Error::other("output reader panicked"))?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn timeout_cleanup_reaps_a_naturally_exited_leader() -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt as _;
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .process_group(0)
        .spawn()?;
    // Observe exit without wait/try_wait: keep the leader's identity reserved for cleanup.
    for _ in 0..100 {
        let status = Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &child.id().to_string()])
            .output()?;
        if String::from_utf8_lossy(&status.stdout)
            .trim()
            .starts_with('Z')
        {
            terminate_compilation(&mut child)?;
            assert_eq!(child.wait()?.code(), Some(0));
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    terminate_compilation(&mut child)?;
    anyhow::bail!("fixture leader did not exit");
}
