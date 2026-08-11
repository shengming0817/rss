//! 契约声明源（`contracts/`）的发现 / 解析 / 校验。
pub(crate) mod breaking;
pub(crate) mod governance;
pub(crate) mod manifest {
    pub(crate) use assembly_schema::contract_manifest::*;
}
pub(crate) mod protection;
pub(crate) mod redaction;
pub(crate) mod source_funnel;
pub(crate) mod validate;

#[cfg(test)]
use assembly_schema::repository_contract::path_segments;
pub(crate) use governance::GovernedContract;

/// Closed DeviceLatent device-certificate draft candidate identities.
///
/// This is the sole handwritten candidate set. Validation, deterministic code generation,
/// CI-impact projection, and evidence binding consume this typed catalog instead of repeating
/// contract IDs or repository paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DeviceCertificateCandidateId {
    PolicyPut,
    StatusGet,
    ApplyCommand,
    CommandAcked,
    CertificateReported,
    IngressReceipted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeviceCertificateCandidateSpec {
    pub(crate) id: &'static str,
    pub(crate) kind: manifest::ContractKind,
    pub(crate) consistency_level: manifest::ConsistencyLevel,
    pub(crate) lifecycle: manifest::Lifecycle,
    pub(crate) source_dir: &'static str,
}

macro_rules! device_certificate_candidate_catalog {
    ($( $variant:ident => ($id:literal, $kind:ident, $consistency:ident, $source:literal), )+) => {
        impl DeviceCertificateCandidateId {
            pub(crate) const ALL: [Self; [$(stringify!($variant)),+].len()] = [
                $(Self::$variant),+
            ];

            pub(crate) const fn spec(self) -> DeviceCertificateCandidateSpec {
                match self {
                    $(Self::$variant => DeviceCertificateCandidateSpec {
                        id: $id,
                        kind: manifest::ContractKind::$kind,
                        consistency_level: manifest::ConsistencyLevel::$consistency,
                        lifecycle: manifest::Lifecycle::Draft,
                        source_dir: $source,
                    }),+
                }
            }
        }
    };
}

device_certificate_candidate_catalog! {
    PolicyPut => (
        "identity.device-certificate-policy-put",
        Http,
        DeviceLatent,
        "contracts/http/identity/v2/device-certificate-policy-put"
    ),
    StatusGet => (
        "identity.device-certificate-status-get",
        Http,
        LocalOnly,
        "contracts/http/identity/v2/device-certificate-status-get"
    ),
    ApplyCommand => (
        "identity.apply-device-certificate",
        Command,
        OutboxFact,
        "contracts/command/identity/v1"
    ),
    CommandAcked => (
        "identity.device-command-acked",
        Event,
        OutboxFact,
        "contracts/event/identity/v1/device-command-acked"
    ),
    CertificateReported => (
        "identity.device-certificate-reported",
        Event,
        OutboxFact,
        "contracts/event/identity/v1/device-certificate-reported"
    ),
    IngressReceipted => (
        "identity.device-ingress-receipted",
        Event,
        OutboxFact,
        "contracts/event/identity/v1/device-ingress-receipted"
    ),
}

pub(crate) const TENANT_SCOPE_SOURCE_RULE: &str = "认证上下文、声明式 populate-only header 或 service-token exact-one header challenger（与 signed typed tenant claim equality）";

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
    fn path_segments_three_segments_flat_slug_none() {
        let root = std::path::Path::new("/contracts");
        let dir = std::path::Path::new("/contracts/http/_seed/v1");
        let result = path_segments(root, dir);
        assert_eq!(
            result,
            Some((
                "http".to_string(),
                "_seed".to_string(),
                "v1".to_string(),
                None
            ))
        );
    }

    #[test]
    fn path_segments_four_segments_nested_slug_some() {
        let root = std::path::Path::new("/contracts");
        let dir = std::path::Path::new("/contracts/event/identity/v1/role-assigned");
        let result = path_segments(root, dir);
        assert_eq!(
            result,
            Some((
                "event".to_string(),
                "identity".to_string(),
                "v1".to_string(),
                Some("role-assigned".to_string())
            ))
        );
    }

    #[test]
    fn path_segments_two_segments_returns_none() {
        let root = std::path::Path::new("/contracts");
        let dir = std::path::Path::new("/contracts/http/_seed");
        assert!(path_segments(root, dir).is_none());
    }

    #[test]
    fn path_segments_five_segments_returns_none() {
        let root = std::path::Path::new("/contracts");
        let dir = std::path::Path::new("/contracts/http/_seed/v1/a/b");
        assert!(path_segments(root, dir).is_none());
    }

    #[test]
    fn path_segments_root_equals_dir_returns_none() {
        let root = std::path::Path::new("/contracts");
        let dir = std::path::Path::new("/contracts");
        assert!(path_segments(root, dir).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn discovery_rejects_symlinked_directory_and_contract_file() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;
        let root = crate::testutil::unique_tmp("contract-discovery-symlink");
        let outside = crate::testutil::unique_tmp("contract-discovery-outside");
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&outside)?;
        symlink(&outside, root.join("event"))?;
        assert!(assembly_schema::repository_contract::inspect_contract_repository(&root).is_err());

        std::fs::remove_file(root.join("event"))?;

        let contract_dir = root.join("event/identity/v1/created");
        std::fs::create_dir_all(&contract_dir)?;
        let outside_manifest = outside.join("contract.toml");
        std::fs::write(&outside_manifest, "outside")?;
        symlink(&outside_manifest, contract_dir.join("contract.toml"))?;
        assert!(assembly_schema::repository_contract::inspect_contract_repository(&root).is_err());

        std::fs::remove_file(contract_dir.join("contract.toml"))?;
        std::fs::write(
            contract_dir.join("contract.toml"),
            r#"id="identity.created"
kind="event"
domain="identity"
version="v1"
owner="identity"
consistencyLevel="OutboxFact"
lifecycle="draft"
[schemas]
payload="payload.schema.json"
[capabilities.outbox]
role="fact"
"#,
        )?;
        let outside_schema = outside.join("payload.schema.json");
        std::fs::write(&outside_schema, "{}")?;
        symlink(&outside_schema, contract_dir.join("payload.schema.json"))?;
        assert!(assembly_schema::repository_contract::inspect_contract_repository(&root).is_err());

        std::fs::remove_dir_all(root)?;
        std::fs::remove_dir_all(outside)?;
        Ok(())
    }
}
