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
const RUNTIME_PLAN: &[u8] = include_bytes!("../../assemblies/runtime/runtime-plan.json");
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
        fs::write(
            root.join("assemblies/runtime/runtime-plan.json"),
            RUNTIME_PLAN,
        )
        .context("write governed RuntimePlan fixture")?;
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
    ensure!(
        SMOKE.contains(r#"source "${SCRIPT_DIR}/server-version-identity.sh""#),
        "smoke must source the shared server version identity seam"
    );
    ensure!(
        SMOKE.contains("rss_require_build_identity"),
        "smoke must fail-closed on illegal GIT_SHA/BUILD_DATE before compose build"
    );
    ensure!(
        SMOKE.contains("rss_assert_version_matches"),
        "smoke must assert server version output via the shared identity seam"
    );
    ensure!(
        SMOKE.contains(r#"GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)""#),
        "smoke must bake GIT_SHA from repository HEAD before compose build"
    );
    ensure!(
        SMOKE.contains(r#"BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)""#),
        "smoke must bake BUILD_DATE as UTC before compose build"
    );
    ensure!(
        SMOKE
            .contains("docker run --rm --entrypoint /usr/local/bin/server rss-runtime:dev version"),
        "smoke must offline-verify server version bake-in"
    );
    Ok(())
}

fn identity_helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../deploy/server-version-identity.sh")
}

fn run_identity_helper(env: &[(&str, Option<&str>)], script: &str) -> Result<Output> {
    let helper = identity_helper_path();
    ensure!(
        helper.is_file(),
        "missing identity helper {}",
        helper.display()
    );
    let mut command = Command::new("/bin/bash");
    command
        .arg("-c")
        .arg(format!("source \"{}\"; {}", helper.display(), script))
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    for (key, value) in env {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {}
        }
    }
    command
        .output()
        .context("execute server-version-identity helper")
}

#[test]
fn server_version_identity_helper_rejects_illegal_inputs_and_accepts_exact_match() -> Result<()> {
    let good_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let good_date = "2026-08-01T00:00:00Z";

    let missing = run_identity_helper(&[], "rss_require_build_identity")?;
    ensure!(!missing.status.success(), "missing identity must fail");
    ensure!(
        text(&missing.stderr).contains("GIT_SHA missing or unknown"),
        "missing identity classification: {}",
        text(&missing.stderr)
    );

    let bad_sha = run_identity_helper(
        &[
            ("GIT_SHA", Some("deadbeef")),
            ("BUILD_DATE", Some(good_date)),
        ],
        "rss_require_build_identity",
    )?;
    ensure!(!bad_sha.status.success(), "short GIT_SHA must fail");
    ensure!(
        text(&bad_sha.stderr).contains("GIT_SHA illegal"),
        "bad sha classification: {}",
        text(&bad_sha.stderr)
    );

    let bad_date = run_identity_helper(
        &[
            ("GIT_SHA", Some(good_sha)),
            ("BUILD_DATE", Some("not-a-date")),
        ],
        "rss_require_build_identity",
    )?;
    ensure!(!bad_date.status.success(), "illegal BUILD_DATE must fail");
    ensure!(
        text(&bad_date.stderr).contains("BUILD_DATE illegal"),
        "bad date classification: {}",
        text(&bad_date.stderr)
    );

    let unknown = run_identity_helper(
        &[
            ("GIT_SHA", Some("unknown")),
            ("BUILD_DATE", Some(good_date)),
        ],
        "rss_require_build_identity",
    )?;
    ensure!(!unknown.status.success(), "unknown GIT_SHA must fail");

    let good = run_identity_helper(
        &[("GIT_SHA", Some(good_sha)), ("BUILD_DATE", Some(good_date))],
        "rss_require_build_identity",
    )?;
    ensure!(
        good.status.success(),
        "canonical identity must pass: {}",
        text(&good.stderr)
    );

    let mismatch = run_identity_helper(
        &[("GIT_SHA", Some(good_sha)), ("BUILD_DATE", Some(good_date))],
        r#"rss_assert_version_matches $'GIT_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nBUILD_DATE=2026-08-01T00:00:00Z\n'"#,
    )?;
    ensure!(!mismatch.status.success(), "mismatched bake-in must fail");
    ensure!(
        text(&mismatch.stderr).contains("GIT_SHA mismatch"),
        "mismatch classification: {}",
        text(&mismatch.stderr)
    );

    let matched = run_identity_helper(
        &[("GIT_SHA", Some(good_sha)), ("BUILD_DATE", Some(good_date))],
        &format!("rss_assert_version_matches $'GIT_SHA={good_sha}\\nBUILD_DATE={good_date}\\n'"),
    )?;
    ensure!(
        matched.status.success(),
        "exact bake-in match must pass: {}",
        text(&matched.stderr)
    );
    Ok(())
}
