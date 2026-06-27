//! 契约声明源（`contracts/`）的发现 / 解析 / 校验。
pub(crate) mod breaking;
pub(crate) mod manifest;
pub(crate) mod protection;
pub(crate) mod redaction;
pub(crate) mod validate;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use manifest::ContractManifest;

/// 一个已发现并解析的契约：目录 + 元数据 + 磁盘路径派生的 kind/domain/version 段。
#[derive(Debug, Clone)]
pub(crate) struct DiscoveredContract {
    /// 契约目录（含 `contract.toml`）。
    pub(crate) dir: PathBuf,
    /// 磁盘段 `{kind}/{domain}/{version}`（相对 `contracts/` 根），供 R3 路径↔字段一致校验。
    pub(crate) path_kind: String,
    pub(crate) path_domain: String,
    pub(crate) path_version: String,
    pub(crate) manifest: ContractManifest,
}

/// 递归发现 `contracts_root` 下全部 `contract.toml`，解析为 `DiscoveredContract`，按目录排序（确定性）。
pub(crate) fn discover(contracts_root: &Path) -> Result<Vec<DiscoveredContract>> {
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
pub(crate) fn path_segments(contracts_root: &Path, dir: &Path) -> Option<(String, String, String)> {
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

/// JSON Schema 文档是否在任意 object schema 的 `properties` 中声明指定字段。
///
/// 仅检查 schema 的 property key，不扫描 `required` / description / enum 字符串，避免把普通文本误判为字段声明。
/// 下钻口径覆盖当前 contract schema 使用的 draft-07 承载关键字，与 codegen/validate 共用，避免治理门漂移。
pub(crate) fn schema_declares_property(value: &serde_json::Value, property: &str) -> bool {
    let serde_json::Value::Object(map) = value else {
        return false;
    };
    if map
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|props| props.contains_key(property))
    {
        return true;
    }
    for key in ["$defs", "definitions", "properties"] {
        if let Some(serde_json::Value::Object(children)) = map.get(key)
            && children
                .values()
                .any(|child| schema_declares_property(child, property))
        {
            return true;
        }
    }
    for key in ["items", "additionalProperties"] {
        if let Some(child) = map.get(key)
            && schema_declares_property(child, property)
        {
            return true;
        }
    }
    for key in ["allOf", "anyOf", "oneOf"] {
        if let Some(serde_json::Value::Array(children)) = map.get(key)
            && children
                .iter()
                .any(|child| schema_declares_property(child, property))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segments_three_segments_returns_some() {
        let root = std::path::Path::new("/contracts");
        let dir = std::path::Path::new("/contracts/http/_seed/v1");
        let result = path_segments(root, dir);
        assert_eq!(
            result,
            Some(("http".to_string(), "_seed".to_string(), "v1".to_string()))
        );
    }

    #[test]
    fn path_segments_two_segments_returns_none() {
        let root = std::path::Path::new("/contracts");
        let dir = std::path::Path::new("/contracts/http/_seed");
        assert!(path_segments(root, dir).is_none());
    }

    #[test]
    fn path_segments_four_segments_returns_none() {
        let root = std::path::Path::new("/contracts");
        let dir = std::path::Path::new("/contracts/http/_seed/v1/extra");
        assert!(path_segments(root, dir).is_none());
    }

    #[test]
    fn path_segments_root_equals_dir_returns_none() {
        let root = std::path::Path::new("/contracts");
        let dir = std::path::Path::new("/contracts");
        assert!(path_segments(root, dir).is_none());
    }
}
