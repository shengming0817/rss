//! RuntimePlan-bound DeploymentPlan generation and raw-byte drift checking.
//!
//! INVARIANT: DEPLOYMENT-PLAN-ARTIFACT-CLOSURE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "deployment_plan::tests::output_closure_rejects_missing_extra_crlf_and_symlink + deployment_plan::tests::render_preflight_failure_is_zero_write", anti_vacuity = "deployment_plan::tests::three_repository_profiles_compile_and_match_committed_bytes + deployment_plan::tests::render_publishes_exact_set_repairs_drift_and_is_idempotent" } — the verified assembly artifact matrix is compiled in full before render, and the generated directory is an exact regular-file LF set.

use anyhow::{Context, Result, ensure};
use assembly_schema::{DeploymentPlan, ParsedDeploymentPlan};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const GENERATED_DIR: &str = "deploy/generated";
const LF_RULE: &str = "deploy/generated/*.deployment-plan.json text eol=lf";
const MAX_PLAN_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Render,
    Check,
}

pub(crate) fn run(action: Action) -> Result<()> {
    run_root(&crate::workspace_root()?, action)
}

fn run_root(root: &Path, action: Action) -> Result<()> {
    run_with_planner(root, action, || plan_all(root))
}

fn run_with_planner(
    root: &Path,
    action: Action,
    planner: impl FnOnce() -> Result<Vec<PlannedOutput>>,
) -> Result<()> {
    let planned = planner()?;
    validate_output_closure(root, &planned)?;
    match action {
        Action::Render => render(root, &planned).map(|_| ()),
        Action::Check => check(&planned),
    }
}

struct PlannedOutput {
    path: PathBuf,
    expected: Vec<u8>,
    actual: Option<Vec<u8>>,
}

fn plan_all(root: &Path) -> Result<Vec<PlannedOutput>> {
    let matrix = crate::assembly_artifacts::load_verified(root)
        .context("deployment plan preflight: artifact matrix rejected")?;
    ensure!(
        !matrix.supported_rows().is_empty(),
        "deployment plan preflight: empty supported assembly universe"
    );

    let mut planned = Vec::with_capacity(matrix.supported_rows().len());
    for row in matrix.supported_rows() {
        let profile = row.deployment();
        let runtime = profile.runtime_plan();
        let plan =
            DeploymentPlan::compile_v1(runtime, profile.plan_input()).with_context(|| {
                format!(
                    "deployment plan preflight: invalid {} deployment facts",
                    row.name()
                )
            })?;
        let mut expected = serde_json::to_vec_pretty(&plan).with_context(|| {
            format!("deployment plan preflight: cannot serialize {}", row.name())
        })?;
        expected.push(b'\n');
        ParsedDeploymentPlan::from_json_slice(runtime, &expected).with_context(|| {
            format!(
                "deployment plan preflight: generated {} bytes rejected",
                row.name()
            )
        })?;

        let path = root
            .join(GENERATED_DIR)
            .join(format!("{}.deployment-plan.json", row.name()));
        let actual = read_existing_output(&path)?;
        planned.push(PlannedOutput {
            path,
            expected,
            actual,
        });
    }
    planned.sort_by(|left, right| left.path.cmp(&right.path));
    let paths = planned
        .iter()
        .map(|item| item.path.clone())
        .collect::<Vec<_>>();
    crate::generated_file::verify_lf_checkout(root, LF_RULE, &paths)
        .map_err(|_| anyhow::anyhow!("deployment plan preflight: LF checkout policy rejected"))?;
    Ok(planned)
}

fn read_existing_output(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => crate::generated_file::read_stable_utf8_file(
            path,
            MAX_PLAN_BYTES,
            "deployment plan output",
        )
        .map(String::into_bytes)
        .map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("deployment plan output metadata failed"),
    }
}

fn validate_output_closure(root: &Path, planned: &[PlannedOutput]) -> Result<()> {
    let expected = planned
        .iter()
        .filter_map(|item| item.path.file_name().map(ToOwned::to_owned))
        .collect::<std::collections::BTreeSet<_>>();
    let directory = root.join(GENERATED_DIR);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).context("deployment plan output directory inspection failed");
        }
    };
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "deployment plan output directory is not a real directory"
    );
    let observed = crate::generated_file::list_stable_regular_files(&directory)?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let extras = observed.difference(&expected).count();
    ensure!(
        extras == 0,
        "deployment plan output: {extras} orphan entries in deploy/generated"
    );
    Ok(())
}

fn check(planned: &[PlannedOutput]) -> Result<()> {
    let missing = planned
        .iter()
        .filter(|item| item.actual.is_none())
        .map(safe_output_name)
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty(),
        "deployment plan check: missing {}",
        missing.join(",")
    );
    let drift = planned
        .iter()
        .filter(|item| {
            item.actual
                .as_deref()
                .is_some_and(|actual| actual != item.expected)
        })
        .map(safe_output_name)
        .collect::<Vec<_>>();
    ensure!(
        drift.is_empty(),
        "deployment plan check: drift {}",
        drift.join(",")
    );
    eprintln!("deployment plan check: {} profiles clean", planned.len());
    Ok(())
}

fn safe_output_name(item: &PlannedOutput) -> String {
    item.path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
            })
        })
        .unwrap_or("<invalid-output>")
        .to_owned()
}

fn render(root: &Path, planned: &[PlannedOutput]) -> Result<usize> {
    let mut changed = 0usize;
    for item in planned {
        if item.actual.as_deref() == Some(item.expected.as_slice()) {
            continue;
        }
        crate::generated_file::atomic_replace(&item.path, &item.expected)
            .context("deployment plan render: atomic publication failed")?;
        changed += 1;
    }
    validate_output_closure(root, planned)?;
    for item in planned {
        let actual = read_existing_output(&item.path)?;
        ensure!(
            actual.as_deref() == Some(item.expected.as_slice()),
            "deployment plan render: post-publication drift {}",
            safe_output_name(item)
        );
    }
    eprintln!("deployment plan render: {changed} profiles updated");
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(path: PathBuf, bytes: &[u8]) -> PlannedOutput {
        PlannedOutput {
            path,
            expected: bytes.to_vec(),
            actual: Some(bytes.to_vec()),
        }
    }

    fn planned_output(path: PathBuf, bytes: &[u8]) -> Result<PlannedOutput> {
        let actual = read_existing_output(&path)?;
        Ok(PlannedOutput {
            path,
            expected: bytes.to_vec(),
            actual,
        })
    }

    #[test]
    fn output_closure_rejects_missing_extra_crlf_and_symlink() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-output-red");
        let generated = root.join(GENERATED_DIR);
        fs::create_dir_all(&generated)?;
        let path = generated.join("runtime.deployment-plan.json");
        fs::write(&path, b"{}\r\n")?;
        let mut planned = vec![output(path.clone(), b"{}\n")];
        planned[0].actual = Some(b"{}\r\n".to_vec());
        let drift = check(&planned).err().context("CRLF/raw-byte red escaped")?;
        assert!(
            drift
                .to_string()
                .contains("drift runtime.deployment-plan.json")
        );

        planned[0].actual = None;
        let missing = check(&planned).err().context("missing red escaped")?;
        assert!(
            missing
                .to_string()
                .contains("missing runtime.deployment-plan.json")
        );
        fs::write(generated.join("orphan.json"), b"{}\n")?;
        let orphan = validate_output_closure(&root, &planned)
            .err()
            .context("orphan red escaped")?;
        assert!(orphan.to_string().contains("1 orphan entries"));
        fs::remove_file(generated.join("orphan.json"))?;

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&path, generated.join("orphan-link"))?;
            assert!(validate_output_closure(&root, &planned).is_err());
            fs::remove_file(generated.join("orphan-link"))?;
            fs::remove_file(&path)?;
            let target = generated.join("target.json");
            fs::write(&target, b"{}\n")?;
            std::os::unix::fs::symlink(&target, &path)?;
            let error = read_existing_output(&path)
                .err()
                .context("expected symlink was accepted")?;
            assert!(error.to_string().contains("symlink"));
        }
        Ok(())
    }

    #[test]
    fn three_repository_profiles_compile_and_match_committed_bytes() -> Result<()> {
        let root = crate::workspace_root()?;
        let planned = plan_all(&root)?;
        ensure!(planned.len() == 3, "expected three supported profiles");
        validate_output_closure(&root, &planned)?;
        check(&planned)
    }

    #[test]
    fn render_preflight_failure_is_zero_write() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-zero-write");
        let generated = root.join(GENERATED_DIR);
        fs::create_dir_all(&generated)?;
        let first = generated.join("identityaudit.deployment-plan.json");
        fs::write(&first, b"drift must remain\n")?;
        let before = fs::read(&first)?;
        let error = run_with_planner(&root, Action::Render, || {
            Err(anyhow::anyhow!("later profile preflight rejected"))
        })
        .err()
        .context("preflight failure was accepted")?;
        assert!(error.to_string().contains("later profile"));
        assert_eq!(fs::read(&first)?, before);
        assert_eq!(fs::read_dir(&generated)?.count(), 1);
        Ok(())
    }

    #[test]
    fn render_publishes_exact_set_repairs_drift_and_is_idempotent() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-render-green");
        let generated = root.join(GENERATED_DIR);
        let expected = [
            (
                "identityaudit.deployment-plan.json",
                b"{\"profile\":\"identityaudit\"}\n".as_slice(),
            ),
            (
                "runtime.deployment-plan.json",
                b"{\"profile\":\"runtime\"}\n".as_slice(),
            ),
        ];
        let plan = |name: &str, bytes: &[u8]| planned_output(generated.join(name), bytes);

        let first = expected
            .iter()
            .map(|(name, bytes)| plan(name, bytes))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(render(&root, &first)?, 2);
        validate_output_closure(&root, &first)?;
        for (name, bytes) in expected {
            assert_eq!(fs::read(generated.join(name))?, bytes);
        }
        assert_eq!(
            crate::generated_file::list_stable_regular_files(&generated)?,
            expected
                .iter()
                .map(|(name, _)| std::ffi::OsString::from(name))
                .collect::<Vec<_>>()
        );

        let unchanged = expected
            .iter()
            .map(|(name, bytes)| plan(name, bytes))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(render(&root, &unchanged)?, 0);

        fs::write(generated.join(expected[0].0), b"tampered\n")?;
        let drifted = expected
            .iter()
            .map(|(name, bytes)| plan(name, bytes))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(render(&root, &drifted)?, 1);
        validate_output_closure(&root, &drifted)?;
        for (name, bytes) in expected {
            assert_eq!(fs::read(generated.join(name))?, bytes);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn directory_replacement_during_closure_is_rejected() -> Result<()> {
        let root = crate::testutil::unique_tmp("deployment-plan-directory-swap");
        let generated = root.join(GENERATED_DIR);
        let displaced = root.join("deploy/generated-old");
        fs::create_dir_all(&generated)?;
        fs::write(generated.join("runtime.deployment-plan.json"), b"{}\n")?;
        let error = crate::generated_file::list_stable_regular_files_with_hook(&generated, || {
            fs::rename(&generated, &displaced)?;
            fs::create_dir(&generated)?;
            fs::write(generated.join("runtime.deployment-plan.json"), b"{}\n")?;
            Ok(())
        })
        .err()
        .context("directory replacement was accepted")?;
        assert!(error.to_string().contains("replaced"));
        Ok(())
    }
}
