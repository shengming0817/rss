//! 契约元数据声明（`contract.toml`）的冻结类型。
//!
//! INVARIANT: CONTRACT-FREEZE-01 — `ContractManifest` 字段集 + 枚举即 `contract.toml` 格式的
//! 单一事实源（Hard，类型层）：`#[serde(deny_unknown_fields)]` + 非 `Option` 枚举字段使「坏格式」
//! 解析即 `Err`，错误不可表达。新增/删字段须同步 `contracts/README.md` 与种子 golden。

use serde::Deserialize;

/// `contract.toml` 的解析目标。字段集冻结——见模块 INVARIANT。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractManifest {
    pub id: String,
    pub kind: ContractKind,
    pub domain: String,
    pub version: String,
    pub owner: ContractOwner,
    #[serde(rename = "consistencyLevel")]
    pub consistency_level: ConsistencyLevel,
    pub lifecycle: Lifecycle,
    #[serde(default)]
    pub schemas: Schemas,
}

impl ContractManifest {
    /// 解析 `contract.toml` 文本。坏枚举 / 未知字段 / 缺字段即 `Err`（CONTRACT-FREEZE-01）。
    pub fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

/// 契约种类。`kind` 决定 wire 形态与 codegen 走向；磁盘段 `contracts/{kind}/...` 与之同源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractKind {
    Http,
    Event,
    Command,
    Saga,
}

impl ContractKind {
    /// 磁盘目录段（与 `contracts/{kind}/...` 路径一致）。
    pub fn as_dir(self) -> &'static str {
        match self {
            ContractKind::Http => "http",
            ContractKind::Event => "event",
            ContractKind::Command => "command",
            ContractKind::Saga => "saga",
        }
    }
}

/// L0–L4 一致性等级（与 wire 语义同源，决策 #1）。拼写大小写敏感。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ConsistencyLevel {
    LocalOnly,
    LocalTx,
    OutboxFact,
    WorkflowEventual,
    DeviceLatent,
}

/// 契约生命周期。`active` 才需 assembly 接线（见 contract-fanout.md §契约归属）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    Draft,
    Active,
    Deprecated,
}

/// 契约归属。`_framework` sentinel = provider-agnostic 中立契约归框架；其余为域名。
///
/// reason: G0.3 仅需「是否框架归属」（R2 用）；owner→域名解析（`owner().domain()`）+ sealed 封闭
/// （`Framework` 类型层无法解析成域）收口到 `vocab::ContractOwner`，属后续单元
/// （见 .claude/rules/rss/contract-fanout.md §契约归属），本单元不预置未用 API。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractOwner {
    Domain(String),
    Framework,
}

impl<'de> Deserialize<'de> for ContractOwner {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(if raw == "_framework" {
            ContractOwner::Framework
        } else {
            ContractOwner::Domain(raw)
        })
    }
}

/// 契约声明的 schema 文件名（按 kind 取用子集；缺省全 `None`，由 validate R5 报形态错）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schemas {
    #[serde(default)]
    pub request: Option<String>,
    #[serde(default)]
    pub response: Option<String>,
    #[serde(default)]
    pub payload: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HTTP: &str = r#"
        id = "seed.echo"
        kind = "http"
        domain = "_seed"
        version = "v1"
        owner = "_framework"
        consistencyLevel = "LocalOnly"
        lifecycle = "draft"
        [schemas]
        request = "request.schema.json"
        response = "response.schema.json"
    "#;

    #[test]
    fn parses_valid_http_manifest() -> anyhow::Result<()> {
        let m = ContractManifest::from_toml_str(VALID_HTTP)?;
        assert_eq!(m.id, "seed.echo");
        assert_eq!(m.kind, ContractKind::Http);
        assert_eq!(m.kind.as_dir(), "http");
        assert_eq!(m.consistency_level, ConsistencyLevel::LocalOnly);
        assert_eq!(m.lifecycle, Lifecycle::Draft);
        assert_eq!(m.owner, ContractOwner::Framework);
        assert_eq!(m.schemas.request.as_deref(), Some("request.schema.json"));
        assert_eq!(m.schemas.payload, None);
        Ok(())
    }

    #[test]
    fn domain_owner_resolves_to_name() -> anyhow::Result<()> {
        let toml = VALID_HTTP.replace("\"_framework\"", "\"identity\"");
        let m = ContractManifest::from_toml_str(&toml)?;
        assert_eq!(m.owner, ContractOwner::Domain("identity".to_string()));
        Ok(())
    }

    #[test]
    fn all_kinds_have_distinct_dirs() {
        // anti-vacuity：四种 kind 的磁盘段两两不同且枚举可解析。
        for (text, want) in [
            ("http", ContractKind::Http),
            ("event", ContractKind::Event),
            ("command", ContractKind::Command),
            ("saga", ContractKind::Saga),
        ] {
            assert_eq!(want.as_dir(), text);
        }
    }

    #[test]
    fn rejects_unknown_kind() {
        let toml = VALID_HTTP.replace("\"http\"", "\"rpc\"");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_consistency_level() {
        let toml = VALID_HTTP.replace("\"LocalOnly\"", "\"Strong\"");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let toml = format!("{VALID_HTTP}\nbogus = 1\n");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_missing_required_field() {
        let toml = VALID_HTTP.replace("id = \"seed.echo\"", "");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_schema_key() {
        let toml = VALID_HTTP.replace("request = ", "bogus = \"x\"\nrequest = ");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }
}
