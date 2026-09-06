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
fn postgres_hosts_have_independent_feature_closures() -> Result {
    let owner = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = owner.join("../transactional-messaging");
    let context = owner.join("../request-context");
    let runtime = owner.join("../runtime");
    let consumer = Consumer::new("postgres-host-features")?;
    fs::write(
        consumer.0.join("src/lib.rs"),
        include_str!("fixtures/host_api.rs"),
    )?;
    for default in ["", ", default-features = false"] {
        fs::write(
            consumer.0.join("Cargo.toml"),
            format!(
                r#"[package]
name = "postgres-host-consumer"
version = "0.0.0"
edition = "2024"
[workspace]
[features]
rss-runtime = ["adapter/rss-runtime", "dep:rss-runtime"]
trait-probe = ["dep:rss-runtime"]
integration = ["adapter/integration"]
[dependencies]
adapter = {{ package = "rss-transactional-messaging-postgres", path = {owner:?}{default} }}
message_core = {{ package = "rss-transactional-messaging", path = {core:?} }}
rss-request-context = {{ path = {context:?} }}
rss-runtime = {{ path = {runtime:?}, optional = true }}
"#
            ),
        )?;
        for features in ["", "integration"] {
            let graph = consumer.cargo(
                &[
                    "tree",
                    "--edges",
                    "normal,build",
                    "--prefix",
                    "none",
                    "--features",
                    features,
                ],
                true,
            )?;
            assert!(
                !graph.lines().any(|line| line.starts_with("rss-runtime ")),
                "{graph}"
            );
            consumer.cargo(&["check", "--quiet", "--features", features], true)?;
        }
        let error = consumer.cargo(&["check", "--quiet", "--features", "trait-probe"], false)?;
        assert!(
            error.contains("ManagedResource") && error.contains("not satisfied"),
            "{error}"
        );
        consumer.cargo(&["check", "--quiet", "--features", "rss-runtime"], true)?;
        consumer.cargo(&["check", "--quiet", "--all-features"], true)?;
    }
    Ok(())
}
