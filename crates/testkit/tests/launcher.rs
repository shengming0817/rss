#![cfg(feature = "containers")]

use std::os::unix::fs::PermissionsExt as _;

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
            std::time::Duration::from_secs(10),
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
