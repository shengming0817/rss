use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Consumer(PathBuf);
impl Consumer {
    fn new(name: &str) -> Result<Self> {
        let root = std::env::temp_dir().join(format!("rss-{name}-{}", std::process::id()));
        fs::create_dir(&root)?;
        fs::create_dir(root.join("src"))?;
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock"),
            root.join("Cargo.lock"),
        )?;
        Ok(Self(root))
    }

    fn cargo(&self, args: &[&str], success: bool) -> Result<String> {
        let log = self.0.join("cargo.log");
        let output = fs::File::create(&log)?;
        let mut child = Command::new(env!("CARGO"))
            .args(args)
            .arg("--offline")
            .current_dir(&self.0)
            .env("CARGO_TARGET_DIR", self.0.join("target"))
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn()?;
        // Bound each Cargo invocation, including a compiler or package-cache lock stall.
        for _ in 0..1200 {
            if let Some(status) = child.try_wait()? {
                let text = fs::read_to_string(&log)?;
                assert_eq!(status.success(), success, "cargo {args:?}: {text}");
                return Ok(text);
            }
            thread::sleep(Duration::from_millis(100));
        }
        child.kill()?;
        child.wait()?;
        Err("independent consumer Cargo command exceeded 120 seconds".into())
    }
}
impl Drop for Consumer {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn base_consumer_has_no_optional_integration() -> Result {
    let owner = Path::new(env!("CARGO_MANIFEST_DIR"));
    let consumer = Consumer::new("redact-base")?;
    fs::write(consumer.0.join("src/main.rs"), "fn main() {}")?;
    for default in ["", ", default-features = false"] {
        fs::write(
            consumer.0.join("Cargo.toml"),
            format!(
                r#"[package]
name = "redact-base-consumer"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
privacy = {{ package = "rss-redact", path = {owner:?}{default} }}
"#
            ),
        )?;
        let graph = consumer.cargo(
            &["tree", "--edges", "normal,build", "--prefix", "none"],
            true,
        )?;
        assert!(graph.lines().any(|line| line.starts_with("rss-redact ")));
        assert!(
            !graph
                .lines()
                .any(|line| line.starts_with("rss-redact-derive ")),
            "{graph}"
        );
        fs::write(
            consumer.0.join("src/main.rs"),
            r#"
use privacy::{Redact, RedactScope, SecretText, RedactionHashKey, RedactedBytes, RedactedSource};
fn main() {
    let secret = SecretText::from_string("do-not-log".into());
    let key = RedactionHashKey::from_bytes(vec![42; 32]).unwrap();
    for scope in [RedactScope::ServerLog, RedactScope::Wire] {
        assert_eq!(secret.redact_scoped(scope), "SecretText(<redacted>)");
        assert_eq!(key.redact_scoped(scope), "RedactionHashKey(<redacted>)");
    }
    assert_eq!(format!("{secret:?}"), "SecretText(<redacted>)");
    assert_eq!(format!("{key:?}"), "RedactionHashKey(<redacted>)");
    assert_eq!(format!("{:?}", RedactedBytes::new(vec![42])), "<redacted>");
    let source = RedactedSource::new(std::io::Error::other("do-not-log"));
    assert_eq!(format!("{source:?}"), "RedactedSource(<redacted>)");
    assert!(std::error::Error::source(&source).is_none());
}
"#,
        )?;
        consumer.cargo(&["run", "--quiet"], true)?;
        fs::write(
            consumer.0.join("src/main.rs"),
            "#[derive(privacy::Redact)] struct Secret; fn main() {}",
        )?;
        let error = consumer.cargo(&["check", "--quiet"], false)?;
        assert!(error.contains("could not find `Redact`"), "{error}");
    }
    Ok(())
}
