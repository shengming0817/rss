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
fn resource_hosts_have_independent_feature_closures() -> Result {
    let owner = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runtime = owner.join("../runtime");
    let consumer = Consumer::new("amqp-host-features")?;
    fs::write(
        consumer.0.join("src/lib.rs"),
        include_str!("fixtures/host_api.rs"),
    )?;
    for (features, defaults) in [
        ("", true),
        ("", false),
        ("managed-runtime", false),
        ("test-support", false),
        ("managed-runtime,test-support", false),
    ] {
        let default = if defaults {
            ""
        } else {
            ", default-features = false"
        };
        fs::write(
            consumer.0.join("Cargo.toml"),
            format!(
                r#"[package]
name = "amqp-host-consumer"
version = "0.0.0"
edition = "2024"
[workspace]
[features]
managed-runtime = ["amqp/managed-runtime"]
test-support = ["amqp/test-support"]
bridge-probe = ["dep:rss-runtime"]
reuse-probe = []
handle-probe = ["dep:rss-runtime"]
[dependencies]
amqp = {{ package = "rss-transactional-messaging-amqp", path = {owner:?}{default} }}
rss-runtime = {{ path = {runtime:?}, optional = true }}
"#
            ),
        )?;
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
            graph
                .lines()
                .any(|line| line.starts_with("rss-transactional-messaging-amqp "))
        );
        let managed = features.contains("managed-runtime");
        assert_eq!(
            graph.lines().any(|line| line.starts_with("rss-runtime ")),
            managed,
            "{features}: {graph}"
        );
        consumer.cargo(&["check", "--quiet", "--features", features], true)?;
        let bridge = consumer.cargo(
            &[
                "check",
                "--quiet",
                "--features",
                &format!("{features},bridge-probe"),
            ],
            managed,
        )?;
        if !managed {
            assert!(
                bridge.contains("ManagedResource") && bridge.contains("not satisfied"),
                "{bridge}"
            );
        }
        let reuse = consumer.cargo(
            &[
                "check",
                "--quiet",
                "--features",
                &format!("{features},reuse-probe"),
            ],
            false,
        )?;
        assert!(reuse.contains("use of moved value"), "{reuse}");
        let handle = consumer.cargo(
            &[
                "check",
                "--quiet",
                "--features",
                &format!("{features},handle-probe"),
            ],
            false,
        )?;
        assert!(
            handle.contains("ManagedResource") && handle.contains("not satisfied"),
            "{handle}"
        );
    }
    Ok(())
}
