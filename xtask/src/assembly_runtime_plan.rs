//! Deterministic committed RuntimePlan generation from the canonical assembly manifest and lock.
//!
//! INVARIANT: ASSEMBLY-RUNTIME-PLAN-VERIFY-GATE-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "assembly_runtime_plan_gate_is_release_owned_once_and_ordered", anti_vacuity = "assembly_runtime_plan::tests::committed_runtime_plans_are_check_clean" }—— committed runtime plans are checked by one typed in-process no-compile gate exactly once after AssemblyLock in final-HEAD release validation.

use anyhow::{Context, Result, bail, ensure};
use assembly_schema::{
    AssemblyListenerKind, ListenerAuth, ParsedAssemblyLock, RuntimePlan, RuntimePlanV3Input,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(test)]
const MANIFEST_NAME: &str = "assembly.toml";
const LOCK_NAME: &str = "assembly.lock.json";
const OUTPUT_NAME: &str = "runtime-plan.json";

struct Target {
    path: PathBuf,
    expected: Vec<u8>,
    actual: Option<Vec<u8>>,
}

pub(crate) fn run(check: bool) -> Result<()> {
    generate_root(&crate::workspace_root()?, check)
}

fn generate_root(root: &Path, check: bool) -> Result<()> {
    let targets = plan_targets(root)?;
    let drift = targets
        .iter()
        .filter(|target| target.actual.as_deref() != Some(target.expected.as_slice()))
        .collect::<Vec<_>>();
    if check {
        if drift.is_empty() {
            eprintln!("assembly generate-runtime-plans --check: 无漂移");
            return Ok(());
        }
        for target in &drift {
            eprintln!("  派生漂移: {}", relative_label(root, &target.path));
        }
        bail!(
            "assembly runtime-plan 派生漂移：{} 个目标不一致；运行 `cargo xtask assembly generate-runtime-plans`",
            drift.len()
        );
    }
    for target in drift {
        crate::generated_file::atomic_replace(&target.path, &target.expected)
            .with_context(|| format!("原子写入 {} 失败", target.path.display()))?;
        eprintln!("  generated {}", relative_label(root, &target.path));
    }
    Ok(())
}

fn plan_targets(root: &Path) -> Result<Vec<Target>> {
    let ir =
        crate::assembly_governance::AssemblyGovernanceIr::<crate::assembly_governance::Core>::load(
            root,
        )?;
    let mut targets = Vec::new();
    for assembly in ir.assemblies() {
        targets.push(plan_target(assembly)?);
    }
    ensure!(!targets.is_empty(), "runtime-plan assembly target 集合为空");
    Ok(targets)
}

fn plan_target(assembly: &crate::assembly_governance::GovernedAssembly) -> Result<Target> {
    let assembly_dir = &assembly.dir();
    let lock_path = assembly_dir.join(LOCK_NAME);
    let output_path = assembly_dir.join(OUTPUT_NAME);
    let manifest = assembly.manifest();
    let directory_name = assembly.manifest().name();
    let lock_source = read_plain_file(&lock_path)?;
    let lock = ParsedAssemblyLock::from_json_slice(&lock_source)
        .with_context(|| format!("解析 {} 失败", lock_path.display()))?
        .verify_repository_v2(assembly.source())
        .with_context(|| format!("repository 验证 {} 失败", lock_path.display()))?;
    let input = compiler_input(manifest)?;
    let plan = RuntimePlan::compile_v3(manifest, &lock, input)
        .with_context(|| format!("编译 {directory_name} RuntimePlan 失败"))?;
    let mut expected = serde_json::to_vec_pretty(&plan).context("序列化 RuntimePlan 失败")?;
    expected.push(b'\n');
    let actual =
        match fs::symlink_metadata(&output_path) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "RuntimePlan 输出必须是无符号链接的普通文件"
                );
                Some(fs::read(&output_path).with_context(|| {
                    format!("读取 RuntimePlan 输出 {} 失败", output_path.display())
                })?)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("读取 RuntimePlan 输出元数据失败"),
        };
    Ok(Target {
        path: output_path,
        expected,
        actual,
    })
}

#[cfg(test)]
fn generate_fixture_target(root: &Path, name: &str, check: bool) -> Result<()> {
    let ir = crate::assembly_governance::AssemblyGovernanceIr::<
        crate::assembly_governance::Core,
    >::load_target(root, name)?
    .with_context(|| format!("fixture assembly `{name}` missing"))?;
    let target = plan_target(
        ir.assembly(name)
            .with_context(|| format!("fixture assembly `{name}` missing manifest"))?,
    )?;
    let drift = target.actual.as_deref() != Some(target.expected.as_slice());
    if check {
        ensure!(!drift, "fixture runtime-plan drift");
    } else if drift {
        crate::generated_file::atomic_replace(&target.path, &target.expected)?;
    }
    Ok(())
}

fn compiler_input(
    manifest: &assembly_schema::CanonicalAssemblyManifestV2,
) -> Result<RuntimePlanV3Input> {
    let mut input = RuntimePlanV3Input::from_manifest(manifest);
    let mut listeners = manifest.listeners().iter().collect::<Vec<_>>();
    listeners.sort_by_key(|listener| listener.kind.as_str());
    for listener in listeners {
        let auth = listener_auth(manifest.name(), listener.kind)?;
        input.listener(listener.kind, auth, listener.domains.clone());
    }
    for domain in manifest.domains() {
        input.domain(*domain);
    }
    let mut placements = manifest.domains().to_vec();
    placements.sort_by_key(|domain| domain.as_str());
    for domain in placements {
        input.placement(domain, manifest.name());
    }
    Ok(input)
}

fn listener_auth(assembly: &str, kind: AssemblyListenerKind) -> Result<ListenerAuth> {
    match (assembly, kind) {
        (_, AssemblyListenerKind::Health) => Ok(ListenerAuth::NoAuth),
        ("runtime" | "deviceidentity", AssemblyListenerKind::Internal) => Ok(ListenerAuth::Mtls),
        (
            "runtime" | "identityaudit",
            AssemblyListenerKind::Primary | AssemblyListenerKind::Admin,
        ) => Ok(ListenerAuth::RssAccessToken),
        ("settingsonly", AssemblyListenerKind::Primary | AssemblyListenerKind::Admin) => {
            Ok(ListenerAuth::FederatedAccessToken)
        }
        ("deviceidentity", AssemblyListenerKind::Primary) => Ok(ListenerAuth::FederatedAccessToken),
        _ => bail!(
            "assembly `{assembly}` listener `{}` 没有闭合 RuntimePlan auth policy",
            kind.as_str()
        ),
    }
}

fn read_plain_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("读取 {} 元数据失败", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{} 必须是无符号链接的普通文件",
        path.display()
    );
    fs::read(path).with_context(|| format!("读取 {} 失败", path.display()))
}

fn relative_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy_tree(source: &Path, target: &Path) -> Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            ensure!(
                !file_type.is_symlink(),
                "fixture source must not contain symlinks"
            );
            let destination = target.join(entry.file_name());
            if file_type.is_dir() {
                copy_tree(&entry.path(), &destination)?;
            } else if file_type.is_file() {
                fs::copy(entry.path(), destination)?;
            }
        }
        Ok(())
    }

    fn fixture_root(name: &str) -> Result<PathBuf> {
        let root = crate::testutil::unique_tmp(name);
        let target = root.join("assemblies/settingsonly");
        fs::create_dir_all(&target)?;
        let workspace_root = crate::workspace_root()?;
        let workspace = workspace_root.join("assemblies/settingsonly");
        fs::copy(workspace.join(MANIFEST_NAME), target.join(MANIFEST_NAME))?;
        fs::copy(workspace.join("Cargo.toml"), target.join("Cargo.toml"))?;
        fs::copy(workspace.join(LOCK_NAME), target.join(LOCK_NAME))?;
        copy_tree(
            &workspace.join("src/generated"),
            &target.join("src/generated"),
        )?;
        copy_tree(&workspace_root.join("contracts"), &root.join("contracts"))?;
        Ok(root)
    }

    #[test]
    fn runtime_plan_codegen_detects_drift_without_repair_and_generate_is_check_clean() -> Result<()>
    {
        let root = fixture_root("assembly-runtime-plan-drift")?;
        let output = root.join("assemblies/settingsonly/runtime-plan.json");
        fs::write(&output, b"stale\n")?;

        assert!(generate_fixture_target(&root, "settingsonly", true).is_err());
        assert_eq!(fs::read(&output)?, b"stale\n");
        generate_fixture_target(&root, "settingsonly", false)?;
        generate_fixture_target(&root, "settingsonly", true)?;
        let generated = fs::read(&output)?;
        assert!(generated.ends_with(b"\n"));
        assert_eq!(generated.iter().filter(|byte| **byte == b'\r').count(), 0);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn committed_runtime_plans_are_check_clean() -> Result<()> {
        generate_root(&crate::workspace_root()?, true)
    }
}
