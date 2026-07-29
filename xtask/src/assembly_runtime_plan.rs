//! Deterministic committed RuntimePlan generation from the canonical assembly manifest and lock.

use anyhow::{Context, Result, bail, ensure};
use assembly_schema::{
    AssemblyListenerKind, AssemblyManifest, ListenerAuth, ParsedAssemblyLock, RuntimePlan,
    RuntimePlanV1Input,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
    let assemblies = root.join("assemblies");
    ensure_plain_directory(&assemblies)?;
    let mut entries = fs::read_dir(&assemblies)
        .with_context(|| format!("读取 {} 失败", assemblies.display()))?
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::path);
    let mut targets = Vec::new();
    for entry in entries {
        let file_type = entry
            .file_type()
            .with_context(|| format!("读取 {} 类型失败", entry.path().display()))?;
        ensure!(!file_type.is_symlink(), "assemblies 下禁止符号链接");
        if !file_type.is_dir() || !entry.path().join(MANIFEST_NAME).exists() {
            continue;
        }
        targets.push(plan_target(&entry.path())?);
    }
    ensure!(!targets.is_empty(), "runtime-plan assembly target 集合为空");
    Ok(targets)
}

fn plan_target(assembly_dir: &Path) -> Result<Target> {
    let manifest_path = assembly_dir.join(MANIFEST_NAME);
    let lock_path = assembly_dir.join(LOCK_NAME);
    let output_path = assembly_dir.join(OUTPUT_NAME);
    let manifest_source = read_plain_file(&manifest_path)?;
    let manifest = AssemblyManifest::from_toml_str(
        std::str::from_utf8(&manifest_source)
            .with_context(|| format!("{} 不是 UTF-8", manifest_path.display()))?,
    )
    .with_context(|| format!("解析 {} 失败", manifest_path.display()))?
    .canonicalize_v1()
    .with_context(|| format!("编译 {} canonical v1 失败", manifest_path.display()))?;
    let directory_name = assembly_dir
        .file_name()
        .and_then(|name| name.to_str())
        .context("assembly 目录名不是 UTF-8")?;
    ensure!(
        manifest.name() == directory_name,
        "assembly manifest name 与目录不一致"
    );
    let lock_source = read_plain_file(&lock_path)?;
    let lock = ParsedAssemblyLock::from_json_slice(&lock_source)
        .with_context(|| format!("解析 {} 失败", lock_path.display()))?;
    let input = compiler_input(&manifest)?;
    let plan = RuntimePlan::compile_v1(&manifest, &lock, input)
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

fn compiler_input(
    manifest: &assembly_schema::CanonicalAssemblyManifestV1,
) -> Result<RuntimePlanV1Input> {
    let mut input = RuntimePlanV1Input::from_manifest(manifest);
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
        ("runtime", AssemblyListenerKind::Internal) => Ok(ListenerAuth::Mtls),
        (
            "runtime" | "identityaudit",
            AssemblyListenerKind::Primary | AssemblyListenerKind::Admin,
        ) => Ok(ListenerAuth::RssAccessToken),
        ("settingsonly", AssemblyListenerKind::Primary | AssemblyListenerKind::Admin) => {
            Ok(ListenerAuth::FederatedAccessToken)
        }
        _ => bail!(
            "assembly `{assembly}` listener `{}` 没有闭合 RuntimePlan auth policy",
            kind.as_str()
        ),
    }
}

fn ensure_plain_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("读取 {} 元数据失败", path.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "{} 必须是无符号链接的目录",
        path.display()
    );
    Ok(())
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

    fn fixture_root(name: &str) -> Result<PathBuf> {
        let root = crate::testutil::unique_tmp(name);
        let target = root.join("assemblies/settingsonly");
        fs::create_dir_all(&target)?;
        let workspace = crate::workspace_root()?.join("assemblies/settingsonly");
        fs::copy(workspace.join(MANIFEST_NAME), target.join(MANIFEST_NAME))?;
        fs::copy(workspace.join(LOCK_NAME), target.join(LOCK_NAME))?;
        Ok(root)
    }

    #[test]
    fn runtime_plan_codegen_detects_drift_without_repair_and_generate_is_check_clean() -> Result<()>
    {
        let root = fixture_root("assembly-runtime-plan-drift")?;
        let output = root.join("assemblies/settingsonly/runtime-plan.json");
        fs::write(&output, b"stale\n")?;

        assert!(generate_root(&root, true).is_err());
        assert_eq!(fs::read(&output)?, b"stale\n");
        generate_root(&root, false)?;
        generate_root(&root, true)?;
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
