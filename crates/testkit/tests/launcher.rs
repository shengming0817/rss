#![cfg(feature = "containers")]

use std::os::unix::fs::PermissionsExt as _;

// Includes cold startup of relocated archive binaries (notably on macOS), the
// launcher's 20-second cancellation and 30-second cleanup budgets, plus exit.
const LAUNCHER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

#[tokio::test]
async fn cleanup_attempts_remaining_resources_after_docker_failure() -> anyhow::Result<()> {
    for fail in ["remove", "list"] {
        let directory = tempfile::tempdir()?;
        let docker = directory.path().join("docker");
        std::fs::write(
            &docker,
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$FIXTURE_CALLS"
case "$1 $2" in
  'container ls')
    [ "$FIXTURE_FAIL" = list ] && { echo "permission denied token=secret" >&2; exit 1; }
    printf 'c1\nc2\n' ;;
  'container rm') [ "$4" = c1 ] && { echo "conflict token=secret" >&2; exit 1; } ;;
  'network ls') printf 'n1\n' ;;
esac
exit 0
"#,
        )?;
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755))?;
        let log = directory.path().join("calls");
        // Rust 1.96 and nextest 0.9.137 both supply the relocated binary path at runtime.
        let launcher = std::env::var("CARGO_BIN_EXE_rss-test-launcher")?;
        let output = tokio::time::timeout(
            LAUNCHER_DEADLINE,
            tokio::process::Command::new(launcher)
                .args(["--", "/usr/bin/true"])
                .env("PATH", directory.path())
                .env("RSS_TEST_RUN_ID", "cleanup-fault-proof")
                .env("FIXTURE_CALLS", &log)
                .env("FIXTURE_FAIL", fail)
                .kill_on_drop(true)
                .output(),
        )
        .await??;
        assert!(!output.status.success());
        let diagnostic = String::from_utf8(output.stderr)?;
        assert!(
            diagnostic.contains(if fail == "list" {
                "permission-denied"
            } else {
                "resource-in-use"
            }),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains("token=secret"));
        let calls = std::fs::read_to_string(log)?;
        assert!(calls.contains("network rm -f n1"), "{calls}");
        if fail == "remove" {
            assert!(calls.contains("container rm -f c2"), "{calls}");
        }
        assert!(
            calls
                .lines()
                .filter(|line| line.contains(" ls "))
                .all(|line| line.contains("label=rss.test-run=cleanup-fault-proof"))
        );
    }
    Ok(())
}

#[tokio::test]
async fn child_and_cleanup_outcomes_are_both_preserved() -> anyhow::Result<()> {
    for cleanup_fails in [false, true] {
        let directory = tempfile::tempdir()?;
        let docker = directory.path().join("docker");
        std::fs::write(
            &docker,
            if cleanup_fails {
                "#!/bin/sh\necho 'token=secret' >&2\nexit 1\n"
            } else {
                "#!/bin/sh\nexit 0\n"
            },
        )?;
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755))?;
        for code in [9, 0] {
            let output = tokio::time::timeout(
                LAUNCHER_DEADLINE,
                tokio::process::Command::new(std::env::var("CARGO_BIN_EXE_rss-test-launcher")?)
                    .args(["--", "/bin/sh", "-c", &format!("exit {code}")])
                    .env("PATH", directory.path())
                    .env("RSS_TEST_RUN_ID", "dual-outcome-proof")
                    .kill_on_drop(true)
                    .output(),
            )
            .await??;
            if cleanup_fails {
                assert!(!output.status.success());
                let diagnostic = String::from_utf8(output.stderr)?;
                assert!(
                    diagnostic.contains(&format!("child_exit={code}")),
                    "{diagnostic}"
                );
                assert!(diagnostic.contains("cleanup=failed"), "{diagnostic}");
                assert!(!diagnostic.contains("token=secret"));
            } else {
                assert_eq!(output.status.code(), Some(code));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_launcher_metrics_remain_complete_json_lines() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let docker = directory.path().join("docker");
    std::fs::write(&docker, "#!/bin/sh\nexit 0\n")?;
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755))?;
    let metrics = directory.path().join("fixture-metrics");
    let mut children = Vec::new();
    for _ in 0..16 {
        children.push(
            tokio::process::Command::new(std::env::var("CARGO_BIN_EXE_rss-test-launcher")?)
                .args(["--", "/usr/bin/true"])
                .env("PATH", directory.path())
                .env("RSS_TEST_RUN_ID", "parallel-metrics-proof")
                .env("RSS_TEST_METRICS_DIR", &metrics)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()?,
        );
    }
    tokio::time::timeout(LAUNCHER_DEADLINE, async {
        for child in &mut children {
            assert!(child.wait().await?.success());
        }
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    let files = std::fs::read_dir(metrics)?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(files.len(), 16);
    let mut lines = String::new();
    for file in files {
        let record = std::fs::read_to_string(file.path())?;
        assert_eq!(record.lines().count(), 1);
        lines.push_str(&record);
    }
    assert_eq!(lines.lines().count(), 16);
    for line in lines.lines() {
        let metric: serde_json::Value = serde_json::from_str(line)?;
        assert_eq!(metric["phase"], "cleanup");
        assert_eq!(metric["outcome"], "success");
    }
    Ok(())
}

#[tokio::test]
async fn metric_write_failure_preserves_child_exit_and_marks_incomplete() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let docker = directory.path().join("docker");
    std::fs::write(&docker, "#!/bin/sh\nexit 0\n")?;
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755))?;
    let metrics = directory.path().join("fixture-metrics");
    std::fs::write(&metrics, "not a directory")?;
    for code in [0, 9] {
        let output = tokio::time::timeout(
            LAUNCHER_DEADLINE,
            tokio::process::Command::new(std::env::var("CARGO_BIN_EXE_rss-test-launcher")?)
                .args(["--", "/bin/sh", "-c", &format!("exit {code}")])
                .env("PATH", directory.path())
                .env("RSS_TEST_RUN_ID", "metrics-failure-proof")
                .env("RSS_TEST_METRICS_DIR", &metrics)
                .kill_on_drop(true)
                .output(),
        )
        .await??;
        assert_eq!(output.status.code(), Some(code));
        assert!(metrics.with_extension("incomplete").exists());
        assert!(String::from_utf8(output.stderr)?.contains("fixture metrics incomplete"));
    }
    Ok(())
}
