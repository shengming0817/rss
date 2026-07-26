//! Production runtime declaration and smoke-policy acceptance.
//!
//! The shell behavior matrix stops before Docker by intentionally supplying an incomplete Remote
//! SPIFFE fixture. This proves the evidence/skip boundary without turning the static journey into a
//! host-Docker prerequisite; the full release execution remains `RSS_SMOKE_MODE=release
//! ./deploy/smoke.sh`.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use anyhow::{Context as _, Result, ensure};

const SMOKE: &str = include_str!("../../deploy/smoke.sh");
const RUNTIME_MANIFEST: &str = include_str!("../../assemblies/runtime/assembly.toml");
const NOT_PRODUCTION_EVIDENCE: &str = "NOT PRODUCTION EVIDENCE";
const RELEASE_DEMO_EVIDENCE: &str = "RELEASE IMAGE ON DEMO INFRA EVIDENCE";

struct SmokeFixture {
    root: PathBuf,
    script: PathBuf,
}

impl SmokeFixture {
    fn create() -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "rss-production-runtime-smoke-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root).context("remove stale smoke fixture")?;
        }
        fs::create_dir_all(root.join("deploy")).context("create deploy fixture")?;
        fs::create_dir_all(root.join("assemblies/runtime")).context("create assembly fixture")?;
        let script = root.join("deploy/smoke.sh");
        fs::write(&script, SMOKE).context("write smoke fixture")?;
        fs::write(
            root.join("deploy/.env.example"),
            concat!(
                "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD=remote-runtime\n",
                "RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD=runtime\n",
                "RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD=runtime\n",
                "SPIFFE_ENDPOINT_SOCKET=\n",
                "RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID=\n",
                "RSS_S3_CANARY_INTERVAL_SECS=60\n",
                "RSS_S3_CANARY_TIMEOUT_SECS=5\n",
            ),
        )
        .context("write incomplete Remote/SPIFFE fixture")?;
        fs::write(
            root.join("assemblies/runtime/assembly.lock.json"),
            r#"{"identity":{"name":"runtime"}}"#,
        )
        .context("write assembly identity fixture")?;
        Ok(Self { root, script })
    }

    fn run(
        &self,
        mode: Option<&str>,
        allow_skip: Option<&str>,
        keep_up: Option<&str>,
    ) -> Result<Output> {
        let mut command = Command::new("/bin/bash");
        command
            .arg(&self.script)
            .current_dir(&self.root)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        if let Some(mode) = mode {
            command.env("RSS_SMOKE_MODE", mode);
        }
        if let Some(allow_skip) = allow_skip {
            command.env("RSS_SMOKE_ALLOW_SKIP", allow_skip);
        }
        if let Some(keep_up) = keep_up {
            command.env("KEEP_UP", keep_up);
        }
        command.output().context("execute smoke policy fixture")
    }
}

impl Drop for SmokeFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_failed_with(output: &Output, needle: &str) -> Result<()> {
    ensure!(
        !output.status.success(),
        "smoke unexpectedly succeeded: stdout={} stderr={}",
        text(&output.stdout),
        text(&output.stderr)
    );
    ensure!(
        text(&output.stderr).contains(needle),
        "missing `{needle}` classification: stderr={}",
        text(&output.stderr)
    );
    ensure!(
        !text(&output.stdout)
            .lines()
            .any(|line| line == NOT_PRODUCTION_EVIDENCE),
        "failed smoke must not mint a skip receipt"
    );
    Ok(())
}

#[test]
fn production_runtime_manifest_is_production() -> Result<()> {
    let manifest: toml::Value = toml::from_str(RUNTIME_MANIFEST)?;
    ensure!(
        manifest.get("profile").and_then(toml::Value::as_str) == Some("production"),
        "full runtime manifest must use the production profile"
    );
    let providers = manifest
        .get("diportProviders")
        .and_then(toml::Value::as_array)
        .context("runtime manifest lacks diportProviders")?;
    ensure!(
        providers.iter().any(|provider| {
            provider.get("provider").and_then(toml::Value::as_str)
                == Some("vault::VaultSecretResolver")
                && provider.get("lifecycle").and_then(toml::Value::as_str) == Some("active")
        }),
        "production runtime must actively bind VaultSecretResolver"
    );
    Ok(())
}

#[test]
fn production_runtime_smoke_policy_is_fail_closed() -> Result<()> {
    let fixture = SmokeFixture::create()?;
    assert_failed_with(&fixture.run(None, None, None)?, "RSS_SMOKE_MODE 必填")?;
    assert_failed_with(
        &fixture.run(Some("compat"), None, None)?,
        "RSS_SMOKE_MODE 非法",
    )?;
    assert_failed_with(
        &fixture.run(Some("developer"), Some("true"), None)?,
        "RSS_SMOKE_ALLOW_SKIP 非法",
    )?;
    assert_failed_with(
        &fixture.run(Some("developer"), Some(""), None)?,
        "RSS_SMOKE_ALLOW_SKIP 非法",
    )?;
    assert_failed_with(
        &fixture.run(Some("release"), Some("1"), None)?,
        "release smoke 禁止",
    )?;
    assert_failed_with(
        &fixture.run(Some("release"), Some("0"), None)?,
        "Remote/SPIFFE fixture 不完整",
    )?;
    assert_failed_with(
        &fixture.run(Some("developer"), None, None)?,
        "Remote/SPIFFE fixture 不完整",
    )?;

    assert_failed_with(
        &fixture.run(Some("release"), Some("0"), Some("1"))?,
        "release smoke 禁止 KEEP_UP=1",
    )?;

    let explicit_skip = fixture.run(Some("developer"), Some("1"), None)?;
    ensure!(
        explicit_skip.status.success(),
        "explicit developer skip failed: stderr={}",
        text(&explicit_skip.stderr)
    );
    let receipts = text(&explicit_skip.stdout)
        .lines()
        .filter(|line| *line == NOT_PRODUCTION_EVIDENCE)
        .count();
    ensure!(
        receipts == 1,
        "expected one non-production receipt, got {receipts}"
    );
    let skip_stdout = text(&explicit_skip.stdout);
    ensure!(
        skip_stdout.contains("SPIFFE_ENDPOINT_SOCKET")
            && skip_stdout.contains("RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID"),
        "developer skip must name every missing fixture variable: {skip_stdout}"
    );
    ensure!(
        !skip_stdout
            .lines()
            .any(|line| line == RELEASE_DEMO_EVIDENCE),
        "developer skip must not mint a release-image receipt"
    );
    ensure!(
        SMOKE.contains(&format!("printf '%s\\n' '{RELEASE_DEMO_EVIDENCE}'")),
        "release success must emit its exact machine classification"
    );
    Ok(())
}
