const IMAGE_ENV: &str = "RSS_DEVICEIDENTITY_ACCEPTANCE_IMAGE";

fn content_address(value: &str) -> anyhow::Result<&str> {
    if value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Ok(value);
    }
    let Some((name, digest)) = value.rsplit_once("@sha256:") else {
        anyhow::bail!("{IMAGE_ENV} must be sha256:<64 lowercase hex> or name@sha256:<digest>")
    };
    anyhow::ensure!(
        !name.is_empty()
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{IMAGE_ENV} must be content addressed"
    );
    Ok(value)
}

#[test]
fn deviceidentity_runtime_image_is_a_content_addressed_candidate() -> anyhow::Result<()> {
    let image = std::env::var(IMAGE_ENV).map_err(|_| anyhow::anyhow!("{IMAGE_ENV} must be set"))?;
    let image = content_address(&image)?;
    let output = std::process::Command::new("docker")
        .args(["image", "inspect", image, "--format", "{{json .Config}}"])
        .output()?;
    anyhow::ensure!(output.status.success(), "docker image inspect failed");
    let config: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    anyhow::ensure!(
        config["User"] == "65532" || config["User"] == "nonroot",
        "image must be nonroot"
    );
    anyhow::ensure!(
        config["Entrypoint"] == serde_json::json!(["/usr/local/bin/deviceidentity-server"]),
        "fixed ENTRYPOINT required"
    );
    let container = std::process::Command::new("docker")
        .args(["create", image])
        .output()?;
    anyhow::ensure!(container.status.success(), "docker create failed");
    let container = String::from_utf8(container.stdout)?.trim().to_owned();
    let schema_path = std::env::temp_dir().join(format!(
        "rss-deviceidentity-schema-{}-{}.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("acceptance")
    ));
    let copied = std::process::Command::new("docker")
        .args([
            "cp",
            &format!("{container}:/usr/share/rss/deviceidentity/config.schema.json"),
            schema_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid temp path"))?,
        ])
        .status()?;
    let removed = std::process::Command::new("docker")
        .args(["rm", &container])
        .status()?;
    anyhow::ensure!(
        copied.success() && removed.success(),
        "schema inventory check failed"
    );
    let schema: serde_json::Value = serde_json::from_slice(&std::fs::read(&schema_path)?)?;
    std::fs::remove_file(&schema_path)?;
    anyhow::ensure!(
        schema["properties"]["schemaVersion"]["const"] == 2,
        "schema v2 missing"
    );
    let tree = std::process::Command::new("cargo")
        .args([
            "tree",
            "-e",
            "normal",
            "-p",
            "deviceidentity",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .output()?;
    anyhow::ensure!(tree.status.success(), "cargo tree failed");
    let tree = String::from_utf8(tree.stdout)?;
    for forbidden in ["softca ", "memory "] {
        anyhow::ensure!(
            !tree.lines().any(|line| line.starts_with(forbidden)),
            "forbidden production package: {forbidden}"
        );
    }
    let features = std::process::Command::new("cargo")
        .args([
            "tree",
            "-e",
            "features",
            "-p",
            "deviceidentity",
            "--prefix",
            "none",
            "--format",
            "{p} {f}",
        ])
        .output()?;
    anyhow::ensure!(features.status.success(), "cargo feature tree failed");
    let features = String::from_utf8(features.stdout)?;
    for forbidden in ["test-support", "allow-http"] {
        anyhow::ensure!(
            !features
                .split([',', ' ', '\n'])
                .any(|value| value == forbidden),
            "forbidden production feature: {forbidden}"
        );
    }
    let status = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "--entrypoint",
            "/usr/local/bin/deviceidentity-server",
            image,
            "--help",
        ])
        .status()?;
    anyhow::ensure!(status.success(), "candidate --help failed");
    Ok(())
}

#[test]
fn tag_only_and_uppercase_digest_are_rejected() {
    assert!(content_address("rss/deviceidentity:latest").is_err());
    assert!(content_address(&format!("rss/deviceidentity@sha256:{}", "A".repeat(64))).is_err());
    assert!(content_address(&format!("sha256:{}", "a".repeat(64))).is_ok());
}
