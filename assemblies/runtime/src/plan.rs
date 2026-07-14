use assembly_schema::{
    AssemblyManifest, DiportProvider, ManifestValidationError, ProviderDurability,
    ProviderLifecycle,
};
use std::fmt;

const BUNDLED_ASSEMBLY_TOML: &str = include_str!("../assembly.toml");

pub const FACT_SOURCE_MATRIX: &[FactSourceEntry] = &[
    FactSourceEntry {
        source: "contracts",
        owns: "wire contracts",
    },
    FactSourceEntry {
        source: "Cargo.toml",
        owns: "physical dependencies",
    },
    FactSourceEntry {
        source: "assembly.toml",
        owns: "active assembly declaration",
    },
    FactSourceEntry {
        source: "modules_gen.rs",
        owns: "derived runtime module output",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactSourceEntry {
    pub source: &'static str,
    pub owns: &'static str,
}

#[derive(Clone)]
pub struct AssemblyPlan {
    manifest: AssemblyManifest,
}

impl fmt::Debug for AssemblyPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AssemblyPlan(<redacted-manifest>)")
    }
}

impl AssemblyPlan {
    pub fn from_toml_str(src: &str) -> Result<Self, AssemblyPlanError> {
        let manifest =
            AssemblyManifest::from_toml_str(src).map_err(|_| AssemblyPlanError::Parse)?;
        Ok(Self { manifest })
    }

    pub fn bundled() -> Result<Self, AssemblyPlanError> {
        Self::from_toml_str(BUNDLED_ASSEMBLY_TOML)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AssemblyPlanError {
    #[error("parse assembly manifest failed")]
    Parse,
}

#[derive(Debug, Clone)]
pub struct RuntimePlan {
    summary: RuntimePlanSummary,
    providers: Vec<RuntimeProviderSummary>,
}

impl RuntimePlan {
    pub fn from_assembly(plan: AssemblyPlan) -> Result<Self, RuntimePlanError> {
        validate_manifest(&plan.manifest)?;
        let summary = RuntimePlanSummary::from_manifest(&plan.manifest);
        let providers = plan
            .manifest
            .diport_providers
            .iter()
            .map(RuntimeProviderSummary::from_provider)
            .collect();
        Ok(Self { summary, providers })
    }

    pub fn bundled() -> Result<Self, RuntimePlanError> {
        Self::from_assembly(AssemblyPlan::bundled()?)
    }

    pub fn summary(&self) -> &RuntimePlanSummary {
        &self.summary
    }

    pub fn providers(&self) -> &[RuntimeProviderSummary] {
        &self.providers
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimePlanError {
    #[error(transparent)]
    Assembly(#[from] AssemblyPlanError),
    #[error("runtime assembly plan field `{field}` must not be empty")]
    Empty { field: &'static str },
    #[error("runtime assembly plan field `{field}` must not contain duplicates")]
    Duplicate { field: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePlanSummary {
    name: String,
    profile: &'static str,
    topology: &'static str,
    domains: Vec<&'static str>,
    listeners: Vec<&'static str>,
    provider_counts: ProviderCounts,
}

impl RuntimePlanSummary {
    fn from_manifest(manifest: &AssemblyManifest) -> Self {
        Self {
            name: manifest.name.clone(),
            profile: manifest.profile.as_str(),
            topology: manifest.topology.as_str(),
            domains: manifest
                .domains
                .iter()
                .map(|domain| domain.as_str())
                .collect(),
            listeners: manifest
                .listeners
                .iter()
                .map(|listener| listener.kind.as_str())
                .collect(),
            provider_counts: ProviderCounts::from_providers(&manifest.diport_providers),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn profile(&self) -> &'static str {
        self.profile
    }

    pub fn topology(&self) -> &'static str {
        self.topology
    }

    pub fn domains(&self) -> &[&'static str] {
        &self.domains
    }

    pub fn listeners(&self) -> &[&'static str] {
        &self.listeners
    }

    pub fn provider_counts(&self) -> ProviderCounts {
        self.provider_counts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderCounts {
    pub total: usize,
    pub active: usize,
    pub draft: usize,
    pub deprecated: usize,
    pub persistent: usize,
    pub ephemeral_memory: usize,
}

impl ProviderCounts {
    fn from_providers(providers: &[DiportProvider]) -> Self {
        let mut counts = Self {
            total: providers.len(),
            ..Self::default()
        };
        for provider in providers {
            match provider.lifecycle {
                ProviderLifecycle::Active => counts.active += 1,
                ProviderLifecycle::Draft => counts.draft += 1,
                ProviderLifecycle::Deprecated => counts.deprecated += 1,
            }
            match provider.durability {
                ProviderDurability::Persistent => counts.persistent += 1,
                ProviderDurability::EphemeralMemory => counts.ephemeral_memory += 1,
            }
        }
        counts
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProviderSummary {
    port: &'static str,
    lifecycle: &'static str,
    durability: &'static str,
    required_features: Vec<String>,
}

impl RuntimeProviderSummary {
    fn from_provider(provider: &DiportProvider) -> Self {
        Self {
            port: provider.port.as_str(),
            lifecycle: provider.lifecycle.as_str(),
            durability: provider.durability.as_str(),
            required_features: provider.required_features.clone(),
        }
    }

    pub fn port(&self) -> &'static str {
        self.port
    }

    pub fn lifecycle(&self) -> &'static str {
        self.lifecycle
    }

    pub fn durability(&self) -> &'static str {
        self.durability
    }

    pub fn required_features(&self) -> &[String] {
        &self.required_features
    }
}

fn validate_manifest(manifest: &AssemblyManifest) -> Result<(), RuntimePlanError> {
    if let Err(errors) = manifest.validate_basic()
        && let Some(error) = errors.as_slice().first()
    {
        return Err(runtime_validation_error(*error));
    }
    Ok(())
}

fn runtime_validation_error(error: ManifestValidationError) -> RuntimePlanError {
    match error {
        ManifestValidationError::Empty { field } => RuntimePlanError::Empty { field },
        ManifestValidationError::Duplicate { field } => RuntimePlanError::Duplicate { field },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    // reason: plan parser tests use direct fixture assertions; parse failures should panic with local context.

    use super::*;

    const MINIMAL_PROVIDER: &str = r#"
[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []
"#;

    fn manifest_with(body: &str) -> String {
        format!(
            r#"
name = "runtime"
profile = "demo"
domains = ["identity", "settings", "audit"]
topology = "durable-shared"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

{body}
"#
        )
    }

    #[test]
    fn runtime_plan_parses_bundled_runtime_assembly_manifest() {
        let plan = RuntimePlan::bundled().expect("bundled runtime plan");
        let summary = plan.summary();

        assert_eq!(summary.name(), "runtime");
        assert_eq!(summary.profile(), "demo");
        assert_eq!(summary.topology(), "durable-shared");
        assert_eq!(summary.domains(), ["settings", "identity", "audit"]);
        assert_eq!(
            summary.listeners(),
            ["primary", "internal", "admin", "health"]
        );
        assert_eq!(summary.provider_counts().total, 15);
        assert_eq!(summary.provider_counts().active, 13);
        assert_eq!(summary.provider_counts().draft, 2);
        assert_eq!(summary.provider_counts().persistent, 13);
        assert_eq!(summary.provider_counts().ephemeral_memory, 2);
    }

    #[test]
    fn runtime_plan_defaults_missing_required_features_to_empty() {
        let plan = RuntimePlan::from_assembly(
            AssemblyPlan::from_toml_str(&manifest_with(MINIMAL_PROVIDER)).expect("assembly plan"),
        )
        .expect("runtime plan");

        let provider = plan
            .providers()
            .iter()
            .find(|provider| provider.port() == "diport::Pdp")
            .expect("pdp provider");
        assert!(provider.required_features().is_empty());
    }

    #[test]
    fn runtime_plan_accepts_audit_sink_provider_declared_by_current_manifest() {
        let plan = RuntimePlan::bundled().expect("bundled runtime plan");

        assert!(
            plan.providers().iter().any(|provider| {
                provider.port() == "diport::AuditSink"
                    && provider.lifecycle() == "active"
                    && provider.durability() == "persistent"
            }),
            "current manifest must include active persistent AuditSink provider"
        );
    }

    #[test]
    fn runtime_plan_rejects_unknown_fields() {
        let top_level = format!("{}\nlegacy = true\n", manifest_with(MINIMAL_PROVIDER));
        assert!(AssemblyPlan::from_toml_str(&top_level).is_err());

        let listener_field = manifest_with(
            r#"
[[listeners]]
kind = "health"
domains = []
addr = "127.0.0.1:0"
"#,
        );
        assert!(AssemblyPlan::from_toml_str(&listener_field).is_err());

        let provider_field = manifest_with(
            r#"
[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []
secret = "super-secret-token"
"#,
        );
        assert!(AssemblyPlan::from_toml_str(&provider_field).is_err());
    }

    #[test]
    fn runtime_plan_rejects_unknown_closed_values() {
        for manifest in [
            manifest_with(MINIMAL_PROVIDER).replace("\"identity\"", "\"billing\""),
            manifest_with(MINIMAL_PROVIDER).replace("durable-shared", "durable-global"),
            manifest_with(MINIMAL_PROVIDER).replace("primary", "public"),
            manifest_with(MINIMAL_PROVIDER).replace("diport::Pdp", "diport::Unknown"),
            manifest_with(MINIMAL_PROVIDER).replace("active", "enabled"),
            manifest_with(MINIMAL_PROVIDER).replace("persistent", "durable"),
        ] {
            assert!(
                AssemblyPlan::from_toml_str(&manifest).is_err(),
                "manifest should reject unknown closed value: {manifest}"
            );
        }
    }

    #[test]
    fn runtime_plan_rejects_empty_or_duplicate_declarations() {
        let no_domains = manifest_with(MINIMAL_PROVIDER).replace(
            r#"domains = ["identity", "settings", "audit"]"#,
            "domains = []",
        );
        assert!(
            RuntimePlan::from_assembly(AssemblyPlan::from_toml_str(&no_domains).unwrap()).is_err()
        );

        let duplicate_domains = manifest_with(MINIMAL_PROVIDER).replace(
            r#"domains = ["identity", "settings", "audit"]"#,
            r#"domains = ["identity", "identity"]"#,
        );
        assert!(
            RuntimePlan::from_assembly(AssemblyPlan::from_toml_str(&duplicate_domains).unwrap())
                .is_err()
        );

        let no_listeners = r#"
name = "runtime"
profile = "demo"
domains = ["identity"]
topology = "demo"
frameworkContracts = []
listeners = []

[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []
"#;
        assert!(
            RuntimePlan::from_assembly(AssemblyPlan::from_toml_str(no_listeners).unwrap()).is_err()
        );

        let duplicate_listeners =
            manifest_with(MINIMAL_PROVIDER).replace(r#"kind = "internal""#, r#"kind = "primary""#);
        assert!(
            RuntimePlan::from_assembly(AssemblyPlan::from_toml_str(&duplicate_listeners).unwrap())
                .is_err()
        );

        let no_providers = r#"
name = "runtime"
profile = "demo"
domains = ["identity"]
topology = "demo"
frameworkContracts = []
diportProviders = []

[[listeners]]
kind = "primary"
domains = []
"#;
        assert!(
            RuntimePlan::from_assembly(AssemblyPlan::from_toml_str(no_providers).unwrap()).is_err()
        );
    }

    #[test]
    fn runtime_plan_summary_excludes_secret_bearing_manifest_values() {
        let manifest = manifest_with(
            r#"
[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "super-secret-token"
outputs = []
"#,
        );
        let assembly = AssemblyPlan::from_toml_str(&manifest).expect("assembly plan");
        assert!(!format!("{assembly:?}").contains("super-secret-token"));
        let plan = RuntimePlan::from_assembly(assembly).expect("runtime plan");
        let rendered = format!("{:?}", plan.summary());

        assert!(!rendered.contains("super-secret-token"));
        assert!(!rendered.contains("oidc::OidcProvider"));
    }

    #[test]
    fn runtime_plan_fact_source_matrix_is_stable() {
        assert_eq!(
            FACT_SOURCE_MATRIX
                .iter()
                .map(|entry| (entry.source, entry.owns))
                .collect::<Vec<_>>(),
            [
                ("contracts", "wire contracts"),
                ("Cargo.toml", "physical dependencies"),
                ("assembly.toml", "active assembly declaration"),
                ("modules_gen.rs", "derived runtime module output"),
            ]
        );
    }
}
