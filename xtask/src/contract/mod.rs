//! 契约声明源（`contracts/`）的发现 / 解析 / 校验。
pub mod manifest;
pub mod validate;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use manifest::ContractManifest;

/// 一个已发现并解析的契约：目录 + 元数据 + 磁盘路径派生的 kind/domain/version 段。
#[derive(Debug, Clone)]
pub struct DiscoveredContract {
    /// 契约目录（含 `contract.toml`）。
    pub dir: PathBuf,
    /// 磁盘段 `{kind}/{domain}/{version}`（相对 `contracts/` 根），供 R3 路径↔字段一致校验。
    pub path_kind: String,
    pub path_domain: String,
    pub path_version: String,
    pub manifest: ContractManifest,
}

/// 递归发现 `contracts_root` 下全部 `contract.toml`，解析为 `DiscoveredContract`，按目录排序（确定性）。
pub fn discover(contracts_root: &Path) -> Result<Vec<DiscoveredContract>> {
    let mut toml_paths = Vec::new();
    collect_contract_tomls(contracts_root, &mut toml_paths)?;
    toml_paths.sort();
    let mut out = Vec::with_capacity(toml_paths.len());
    for manifest_path in toml_paths {
        out.push(load_contract(contracts_root, &manifest_path)?);
    }
    Ok(out)
}

fn load_contract(contracts_root: &Path, manifest_path: &Path) -> Result<DiscoveredContract> {
    let dir = manifest_path
        .parent()
        .context("contract.toml 无父目录")?
        .to_path_buf();
    let text = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("读取 {}", manifest_path.display()))?;
    let manifest = ContractManifest::from_toml_str(&text)
        .with_context(|| format!("解析 {}", manifest_path.display()))?;
    let (path_kind, path_domain, path_version) =
        path_segments(contracts_root, &dir).with_context(|| {
            format!(
                "契约目录层级须为 contracts/{{kind}}/{{domain}}/{{version}}/: {}",
                dir.display()
            )
        })?;
    Ok(DiscoveredContract {
        dir,
        path_kind,
        path_domain,
        path_version,
        manifest,
    })
}

fn collect_contract_tomls(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("读目录 {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_contract_tomls(&path, out)?;
        } else if path.file_name().and_then(|n| n.to_str()) == Some("contract.toml") {
            out.push(path);
        }
    }
    Ok(())
}

/// 取 dir 相对 contracts_root 的末 3 段（kind/domain/version）。层级不符返回 `None`。
fn path_segments(contracts_root: &Path, dir: &Path) -> Option<(String, String, String)> {
    let rel = dir.strip_prefix(contracts_root).ok()?;
    let segs: Vec<&str> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    match segs.as_slice() {
        [kind, domain, version] => {
            Some((kind.to_string(), domain.to_string(), version.to_string()))
        }
        _ => None,
    }
}
