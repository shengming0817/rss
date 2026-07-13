use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;

pub const REGISTERED_DOMAIN_LABELS: &[&str] =
    &["identity", "settings", "audit", "contractreg", "syshealth"];

const REVOCATION_STORE_PORT: &str = "diport::RevocationStore";
const PUBLISHER_PORT: &str = "diport::Publisher";
const ACKABLE_SUBSCRIBER_PORT: &str = "diport::AckableSubscriber";
const SIGNER_PORT: &str = "diport::Signer";
const KEY_PROVIDER_PORT: &str = "diport::KeyProvider";
const PDP_PORT: &str = "diport::Pdp";
const AUDIT_SINK_PORT: &str = "diport::AuditSink";
const RATE_LIMITER_PORT: &str = "diport::RateLimiter";
const LOCK_STORE_PORT: &str = "diport::LockStore";
const CAS_STORE_PORT: &str = "diport::CasStore";
const OBJECT_STORE_PORT: &str = "diport::ObjectStore";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyManifest {
    pub name: String,
    pub profile: AssemblyProfile,
    pub domains: Vec<AssemblyDomain>,
    pub topology: AssemblyTopology,
    #[serde(rename = "frameworkContracts")]
    pub framework_contracts: Vec<String>,
    pub listeners: Vec<AssemblyListener>,
    #[serde(rename = "diportProviders")]
    pub diport_providers: Vec<DiportProvider>,
}

impl AssemblyManifest {
    pub fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn validate_basic(&self) -> Result<(), ManifestValidationErrors> {
        let errors = self.basic_validation_errors();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ManifestValidationErrors { errors })
        }
    }

    pub fn basic_validation_errors(&self) -> Vec<ManifestValidationError> {
        let mut errors = Vec::new();
        ensure_non_empty_string(&self.name, "name", &mut errors);
        ensure_non_empty_slice(&self.domains, "domains", &mut errors);
        ensure_non_empty_slice(&self.listeners, "listeners", &mut errors);
        ensure_non_empty_slice(&self.diport_providers, "diportProviders", &mut errors);

        ensure_unique(self.domains.iter().copied(), "domains", &mut errors);
        ensure_unique(
            self.framework_contracts.iter().map(String::as_str),
            "frameworkContracts",
            &mut errors,
        );
        for contract in &self.framework_contracts {
            ensure_non_empty_string(contract, "frameworkContracts", &mut errors);
        }
        ensure_unique(
            self.listeners.iter().map(|listener| listener.kind),
            "listeners",
            &mut errors,
        );
        ensure_unique_provider_keys(&self.diport_providers, &mut errors);

        for provider in &self.diport_providers {
            ensure_non_empty_string(&provider.provider, "diportProviders.provider", &mut errors);
            ensure_non_empty_string(
                &provider.provider_crate,
                "diportProviders.providerCrate",
                &mut errors,
            );
            ensure_non_empty_string(&provider.consumer, "diportProviders.consumer", &mut errors);
            ensure_non_empty_string(&provider.purpose, "diportProviders.purpose", &mut errors);
            for feature in &provider.required_features {
                ensure_non_empty_string(feature, "diportProviders.requiredFeatures", &mut errors);
            }
        }

        errors
    }

    pub fn validate_graph_evidence(&self) -> Result<(), GraphEvidenceValidationErrors> {
        let mut errors = Vec::new();
        let declared_domains: BTreeSet<_> = self.domains.iter().copied().collect();
        let mut bound_domains = BTreeSet::new();
        let mut bindings = BTreeSet::new();
        for listener in &self.listeners {
            for domain in &listener.domains {
                if !declared_domains.contains(domain) {
                    errors.push(GraphEvidenceValidationError::UnknownDomain { domain: *domain });
                }
                if !bindings.insert((*domain, listener.kind)) {
                    errors.push(GraphEvidenceValidationError::DuplicateDomainListener {
                        domain: *domain,
                        listener: listener.kind,
                    });
                }
                bound_domains.insert(*domain);
            }
        }
        for domain in declared_domains.difference(&bound_domains) {
            errors.push(GraphEvidenceValidationError::UnboundDomain { domain: *domain });
        }
        for provider in &self.diport_providers {
            let mut seen = BTreeSet::new();
            for channel in &provider.outputs {
                if !seen.insert(*channel) {
                    errors.push(GraphEvidenceValidationError::DuplicateProviderOutput {
                        channel: *channel,
                    });
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(GraphEvidenceValidationErrors { errors })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEvidenceValidationErrors {
    errors: Vec<GraphEvidenceValidationError>,
}

impl GraphEvidenceValidationErrors {
    pub fn as_slice(&self) -> &[GraphEvidenceValidationError] {
        &self.errors
    }
}

impl fmt::Display for GraphEvidenceValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} assembly graph evidence error(s)", self.errors.len())
    }
}

impl std::error::Error for GraphEvidenceValidationErrors {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphEvidenceValidationError {
    UnknownDomain {
        domain: AssemblyDomain,
    },
    UnboundDomain {
        domain: AssemblyDomain,
    },
    DuplicateDomainListener {
        domain: AssemblyDomain,
        listener: AssemblyListenerKind,
    },
    DuplicateProviderOutput {
        channel: LifecycleChannel,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestValidationErrors {
    errors: Vec<ManifestValidationError>,
}

impl ManifestValidationErrors {
    pub fn as_slice(&self) -> &[ManifestValidationError] {
        &self.errors
    }

    pub fn into_vec(self) -> Vec<ManifestValidationError> {
        self.errors
    }
}

impl fmt::Display for ManifestValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} assembly manifest validation error(s)",
            self.errors.len()
        )
    }
}

impl std::error::Error for ManifestValidationErrors {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestValidationError {
    Empty { field: &'static str },
    Duplicate { field: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssemblyProfile {
    Production,
    Demo,
    Test,
}

impl AssemblyProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Demo => "demo",
            Self::Test => "test",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssemblyDomain {
    Identity,
    Settings,
    Audit,
    Contractreg,
    Syshealth,
}

impl AssemblyDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Settings => "settings",
            Self::Audit => "audit",
            Self::Contractreg => "contractreg",
            Self::Syshealth => "syshealth",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssemblyTopology {
    Demo,
    DurableShared,
    DurableIsolated,
}

impl AssemblyTopology {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Demo => "demo",
            Self::DurableShared => "durable-shared",
            Self::DurableIsolated => "durable-isolated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyListener {
    pub kind: AssemblyListenerKind,
    pub domains: Vec<AssemblyDomain>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssemblyListenerKind {
    Primary,
    Internal,
    Admin,
    Health,
}

impl AssemblyListenerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Internal => "internal",
            Self::Admin => "admin",
            Self::Health => "health",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiportProvider {
    pub port: DiportPort,
    pub provider: String,
    #[serde(rename = "providerCrate")]
    pub provider_crate: String,
    #[serde(default, rename = "requiredFeatures")]
    pub required_features: Vec<String>,
    pub consumer: String,
    pub lifecycle: ProviderLifecycle,
    pub durability: ProviderDurability,
    pub purpose: String,
    pub outputs: Vec<LifecycleChannel>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleChannel {
    Probes,
    Resources,
    Workers,
}

impl LifecycleChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Probes => "probes",
            Self::Resources => "resources",
            Self::Workers => "workers",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum DiportPort {
    #[serde(rename = "diport::RevocationStore")]
    RevocationStore,
    #[serde(rename = "diport::Publisher")]
    Publisher,
    #[serde(rename = "diport::AckableSubscriber")]
    AckableSubscriber,
    #[serde(rename = "diport::Signer")]
    Signer,
    #[serde(rename = "diport::KeyProvider")]
    KeyProvider,
    #[serde(rename = "diport::Pdp")]
    Pdp,
    #[serde(rename = "diport::AuditSink")]
    AuditSink,
    #[serde(rename = "diport::RateLimiter")]
    RateLimiter,
    #[serde(rename = "diport::LockStore")]
    Lock,
    #[serde(rename = "diport::CasStore")]
    Cas,
    #[serde(rename = "diport::ObjectStore")]
    ObjectStore,
}

impl DiportPort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RevocationStore => REVOCATION_STORE_PORT,
            Self::Publisher => PUBLISHER_PORT,
            Self::AckableSubscriber => ACKABLE_SUBSCRIBER_PORT,
            Self::Signer => SIGNER_PORT,
            Self::KeyProvider => KEY_PROVIDER_PORT,
            Self::Pdp => PDP_PORT,
            Self::AuditSink => AUDIT_SINK_PORT,
            Self::RateLimiter => RATE_LIMITER_PORT,
            Self::Lock => LOCK_STORE_PORT,
            Self::Cas => CAS_STORE_PORT,
            Self::ObjectStore => OBJECT_STORE_PORT,
        }
    }
}

impl fmt::Display for DiportPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderLifecycle {
    Draft,
    Active,
    Deprecated,
}

impl ProviderLifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Deprecated => "deprecated",
        }
    }
}

impl fmt::Display for ProviderLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderDurability {
    EphemeralMemory,
    Persistent,
}

impl ProviderDurability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EphemeralMemory => "ephemeral-memory",
            Self::Persistent => "persistent",
        }
    }
}

impl fmt::Display for ProviderDurability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn ensure_non_empty_string(
    value: &str,
    field: &'static str,
    errors: &mut Vec<ManifestValidationError>,
) {
    if value.trim().is_empty() {
        errors.push(ManifestValidationError::Empty { field });
    }
}

fn ensure_non_empty_slice<T>(
    values: &[T],
    field: &'static str,
    errors: &mut Vec<ManifestValidationError>,
) {
    if values.is_empty() {
        errors.push(ManifestValidationError::Empty { field });
    }
}

fn ensure_unique<T>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
    errors: &mut Vec<ManifestValidationError>,
) where
    T: Ord,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            errors.push(ManifestValidationError::Duplicate { field });
            return;
        }
    }
}

fn ensure_unique_provider_keys(
    providers: &[DiportProvider],
    errors: &mut Vec<ManifestValidationError>,
) {
    let mut seen = BTreeSet::new();
    for provider in providers {
        let key = (
            provider.port.as_str(),
            provider.provider.as_str(),
            provider.provider_crate.as_str(),
            provider.consumer.as_str(),
        );
        if !seen.insert(key) {
            errors.push(ManifestValidationError::Duplicate {
                field: "diportProviders",
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    // reason: schema parser tests use direct fixture assertions; parse failures should panic with local context.

    use super::*;

    const MINIMAL: &str = r#"
name = "runtime"
profile = "demo"
domains = ["identity", "settings", "audit"]
topology = "durable-shared"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = ["identity", "settings", "audit"]

[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = ["resources", "workers"]
"#;

    #[test]
    fn parses_minimal_manifest() {
        let manifest = AssemblyManifest::from_toml_str(MINIMAL).expect("manifest");

        assert_eq!(manifest.name, "runtime");
        assert_eq!(
            manifest
                .domains
                .iter()
                .map(|domain| domain.as_str())
                .collect::<Vec<_>>(),
            ["identity", "settings", "audit"]
        );
        assert!(manifest.diport_providers[0].required_features.is_empty());
        assert!(manifest.framework_contracts.is_empty());
        assert_eq!(
            manifest.listeners[0].domains.as_slice(),
            [
                AssemblyDomain::Identity,
                AssemblyDomain::Settings,
                AssemblyDomain::Audit
            ]
        );
        assert_eq!(
            manifest.diport_providers[0].outputs.as_slice(),
            [LifecycleChannel::Resources, LifecycleChannel::Workers]
        );
        manifest.validate_basic().expect("valid manifest");
    }

    #[test]
    fn framework_contracts_are_required_non_empty_and_unique() {
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("frameworkContracts = []\n", ""))
                .is_err()
        );

        let invalid = AssemblyManifest::from_toml_str(&MINIMAL.replace(
            "frameworkContracts = []",
            "frameworkContracts = [\"\", \"seed.echo\", \"seed.echo\"]",
        ))
        .expect("closed framework contract declarations parse before semantic validation");
        let errors = invalid.basic_validation_errors();
        assert!(errors.contains(&ManifestValidationError::Empty {
            field: "frameworkContracts"
        }));
        assert!(errors.contains(&ManifestValidationError::Duplicate {
            field: "frameworkContracts"
        }));
    }

    #[test]
    fn rejects_unknown_fields_and_closed_values() {
        assert!(AssemblyManifest::from_toml_str(&format!("{MINIMAL}\nlegacy = true\n")).is_err());
        assert!(AssemblyManifest::from_toml_str(&MINIMAL.replace("identity", "billing")).is_err());
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("durable-shared", "global")).is_err()
        );
        assert!(AssemblyManifest::from_toml_str(&MINIMAL.replace("primary", "public")).is_err());
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("diport::Pdp", "diport::Unknown"))
                .is_err()
        );
        assert!(AssemblyManifest::from_toml_str(&MINIMAL.replace("active", "enabled")).is_err());
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("persistent", "durable")).is_err()
        );
    }

    #[test]
    fn reports_empty_and_duplicate_declarations() {
        let empty_domains = AssemblyManifest::from_toml_str(&MINIMAL.replace(
            r#"domains = ["identity", "settings", "audit"]"#,
            "domains = []",
        ))
        .expect("parse empty domains");
        assert!(
            empty_domains
                .basic_validation_errors()
                .contains(&ManifestValidationError::Empty { field: "domains" })
        );

        let duplicate_domains = AssemblyManifest::from_toml_str(&MINIMAL.replace(
            r#"domains = ["identity", "settings", "audit"]"#,
            r#"domains = ["identity", "identity"]"#,
        ))
        .expect("parse duplicate domains");
        assert!(
            duplicate_domains
                .basic_validation_errors()
                .contains(&ManifestValidationError::Duplicate { field: "domains" })
        );
    }

    #[test]
    fn graph_evidence_is_closed_and_non_vacuous() {
        let manifest = AssemblyManifest::from_toml_str(MINIMAL).expect("manifest");
        manifest
            .validate_graph_evidence()
            .expect("complete graph evidence");

        let missing_listener = MINIMAL.replace(
            "kind = \"primary\"\ndomains = [\"identity\", \"settings\", \"audit\"]",
            "kind = \"primary\"",
        );
        assert!(AssemblyManifest::from_toml_str(&missing_listener).is_err());
        let missing_provider = MINIMAL.replace("outputs = [\"resources\", \"workers\"]\n", "");
        assert!(AssemblyManifest::from_toml_str(&missing_provider).is_err());
    }
}
