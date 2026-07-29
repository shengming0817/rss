#[doc(hidden)]
pub mod contract_manifest;
mod lock;
mod provider;
#[doc(hidden)]
pub mod repository_contract;
mod runtime_plan;

pub use lock::{
    AssemblyDigests, AssemblyFingerprint, AssemblyIdentity, AssemblyLock, AssemblyLockError,
    AssemblyLockErrorStage, GENERATED_MODULE_OWNERSHIP_MARKER, GENERATED_PROVIDER_OWNERSHIP_MARKER,
    ParsedAssemblyLock, RepositoryVerifiedAssemblyLock,
};
pub use provider::{
    DiportPort, DiportProvider, LifecycleChannel, ProviderCapabilityEvidence, ProviderCatalogEntry,
    ProviderConstructor, ProviderConsumer, ProviderDurability, ProviderFactorySymbol,
    ProviderFailurePosture, ProviderLifecycle, ProviderRole, ProviderScope,
};
pub use runtime_plan::{
    DomainLifecyclePhase, DomainPlan, ListenerAuth, ListenerPlan, ParsedRuntimePlan, PlacementPlan,
    ProviderPlan, RuntimePlan, RuntimePlanError, RuntimePlanErrorStage, RuntimePlanFingerprint,
    RuntimePlanJsonCategory, RuntimePlanJsonPath, RuntimePlanV1Input,
    validate_runtime_plan_json_slice,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const REGISTERED_DOMAIN_LABELS: &[&str] =
    &["identity", "settings", "audit", "contractreg", "syshealth"];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyManifest {
    pub name: String,
    pub profile: AssemblyProfile,
    pub domains: Vec<AssemblyDomain>,
    pub topology: AssemblyTopology,
    #[serde(rename = "frameworkContracts")]
    pub framework_contracts: Vec<FrameworkContractMount>,
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
            self.framework_contracts
                .iter()
                .map(|mount| mount.id.as_str()),
            "frameworkContracts",
            &mut errors,
        );
        for mount in &self.framework_contracts {
            ensure_non_empty_string(&mount.id, "frameworkContracts", &mut errors);
        }
        ensure_unique(
            self.listeners.iter().map(|listener| listener.kind),
            "listeners",
            &mut errors,
        );
        ensure_unique_provider_keys(&self.diport_providers, &mut errors);
        ensure_unique(
            self.diport_providers.iter().map(|provider| provider.id),
            "diportProviders.id",
            &mut errors,
        );

        for provider in &self.diport_providers {
            ensure_non_empty_string(
                &provider.provider_crate,
                "diportProviders.providerCrate",
                &mut errors,
            );
            ensure_non_empty_string(&provider.purpose, "diportProviders.purpose", &mut errors);
            for feature in &provider.required_features {
                ensure_non_empty_string(feature, "diportProviders.requiredFeatures", &mut errors);
            }
            ensure_unique(
                provider.required_features.iter().map(String::as_str),
                "diportProviders.requiredFeatures",
                &mut errors,
            );
            errors.extend(
                provider
                    .registry_mismatch_fields()
                    .into_iter()
                    .map(
                        |mismatch| ManifestValidationError::ProviderRegistryMismatch {
                            role: provider.id,
                            field: mismatch.field,
                            expected: mismatch.expected,
                            actual: mismatch.actual,
                        },
                    ),
            );
        }

        errors
    }

    pub fn validate_graph_evidence(&self) -> Result<(), GraphEvidenceValidationErrors> {
        let mut errors = Vec::new();
        let declared_domains: BTreeSet<_> = self.domains.iter().copied().collect();
        let mut bound_domains = BTreeSet::new();
        let mut bindings = BTreeSet::new();
        let listener_kinds = self
            .listeners
            .iter()
            .map(|listener| listener.kind)
            .collect::<BTreeSet<_>>();
        for mount in &self.framework_contracts {
            if !listener_kinds.contains(&mount.listener) {
                errors.push(GraphEvidenceValidationError::UnknownFrameworkListener {
                    contract_id: mount.id.clone(),
                    listener: mount.listener,
                });
            }
        }
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

    /// Validate and compile this manifest into the sole v1 semantic view.
    ///
    /// Code generation and manifest identity both consume this type, so set-like
    /// declarations cannot drift between their rendered and fingerprinted forms.
    pub fn canonicalize_v1(
        self,
    ) -> Result<CanonicalAssemblyManifestV1, AssemblyManifestCanonicalizationError> {
        self.validate_basic().map_err(|source| {
            AssemblyManifestCanonicalizationError(AssemblyManifestCanonicalizationErrorKind::Basic(
                source,
            ))
        })?;
        self.validate_graph_evidence().map_err(|source| {
            AssemblyManifestCanonicalizationError(AssemblyManifestCanonicalizationErrorKind::Graph(
                source,
            ))
        })?;

        // Intentionally exhaustive: a future source field must fail compilation until its
        // sequence/set semantics are reviewed for both codegen and fingerprinting.
        let AssemblyManifest {
            name,
            profile,
            domains,
            topology,
            framework_contracts,
            listeners,
            mut diport_providers,
        } = self;

        for provider in &mut diport_providers {
            provider.required_features.sort();
            provider.outputs.sort();
        }
        diport_providers.sort_by(|left, right| provider_key(left).cmp(&provider_key(right)));

        let value = CanonicalAssemblyManifestV1Value {
            name,
            profile,
            domains,
            topology,
            framework_contracts,
            listeners,
            diport_providers,
        };
        let manifest_digest = lock::canonical_manifest_digest(&value).map_err(|source| {
            AssemblyManifestCanonicalizationError(
                AssemblyManifestCanonicalizationErrorKind::Digest(source),
            )
        })?;
        Ok(CanonicalAssemblyManifestV1 {
            value,
            manifest_digest,
        })
    }
}

/// Read-only v1 semantic manifest shared by code generation and AssemblyLock identity.
pub struct CanonicalAssemblyManifestV1 {
    value: CanonicalAssemblyManifestV1Value,
    manifest_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalAssemblyManifestV1Value {
    name: String,
    profile: AssemblyProfile,
    domains: Vec<AssemblyDomain>,
    topology: AssemblyTopology,
    framework_contracts: Vec<FrameworkContractMount>,
    listeners: Vec<AssemblyListener>,
    diport_providers: Vec<DiportProvider>,
}

impl CanonicalAssemblyManifestV1 {
    pub fn name(&self) -> &str {
        &self.value.name
    }

    pub const fn profile(&self) -> AssemblyProfile {
        self.value.profile
    }

    pub fn domains(&self) -> &[AssemblyDomain] {
        &self.value.domains
    }

    pub const fn topology(&self) -> AssemblyTopology {
        self.value.topology
    }

    pub fn framework_contracts(&self) -> &[FrameworkContractMount] {
        &self.value.framework_contracts
    }

    pub fn listeners(&self) -> &[AssemblyListener] {
        &self.value.listeners
    }

    pub fn diport_providers(&self) -> &[DiportProvider] {
        &self.value.diport_providers
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
}

/// Closed error returned while compiling an AssemblyManifest into its v1 semantic form.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AssemblyManifestCanonicalizationError(AssemblyManifestCanonicalizationErrorKind);

#[derive(Debug, thiserror::Error)]
enum AssemblyManifestCanonicalizationErrorKind {
    #[error("invalid assembly declarations: {0}")]
    Basic(#[source] ManifestValidationErrors),
    #[error("invalid assembly graph evidence: {0}")]
    Graph(#[source] GraphEvidenceValidationErrors),
    #[error("canonical manifest digest failed: {0}")]
    Digest(#[source] AssemblyLockError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEvidenceValidationErrors {
    errors: Vec<GraphEvidenceValidationError>,
}

impl GraphEvidenceValidationErrors {
    pub fn as_slice(&self) -> &[GraphEvidenceValidationError] {
        &self.errors
    }

    pub fn into_vec(self) -> Vec<GraphEvidenceValidationError> {
        self.errors
    }
}

impl fmt::Display for GraphEvidenceValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_error_list(f, &self.errors)
    }
}

impl std::error::Error for GraphEvidenceValidationErrors {}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GraphEvidenceValidationError {
    #[error("framework contract `{contract_id}` references undeclared listener `{listener}")]
    UnknownFrameworkListener {
        contract_id: String,
        listener: AssemblyListenerKind,
    },
    #[error("listener references undeclared domain `{domain}`")]
    UnknownDomain { domain: AssemblyDomain },
    #[error("declared domain `{domain}` has no listener")]
    UnboundDomain { domain: AssemblyDomain },
    #[error("duplicate domain/listener binding `{domain}/{listener}`")]
    DuplicateDomainListener {
        domain: AssemblyDomain,
        listener: AssemblyListenerKind,
    },
    #[error("duplicate provider output `{channel}`")]
    DuplicateProviderOutput { channel: LifecycleChannel },
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
        write_error_list(f, &self.errors)
    }
}

impl std::error::Error for ManifestValidationErrors {}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestValidationError {
    #[error("field={field} empty declaration")]
    Empty { field: &'static str },
    #[error("field={field} duplicate declaration")]
    Duplicate { field: &'static str },
    #[error("field={field} invalid declaration")]
    Invalid { field: &'static str },
    #[error(
        "provider={role} field={field} does not match canonical registry: expected={expected} actual={actual}"
    )]
    ProviderRegistryMismatch {
        role: ProviderRole,
        field: &'static str,
        expected: String,
        actual: String,
    },
}

fn write_error_list<T: fmt::Display>(f: &mut fmt::Formatter<'_>, errors: &[T]) -> fmt::Result {
    for (index, error) in errors.iter().enumerate() {
        if index > 0 {
            f.write_str("; ")?;
        }
        write!(f, "{error}")?;
    }
    Ok(())
}

macro_rules! display_as_str {
    ($($ty:ty),+ $(,)?) => {$(
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    )+};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyListener {
    pub kind: AssemblyListenerKind,
    pub domains: Vec<AssemblyDomain>,
}

/// One explicit framework-owned contract mount in an assembly.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkContractMount {
    pub id: String,
    pub listener: AssemblyListenerKind,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
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

display_as_str!(AssemblyDomain, AssemblyListenerKind);

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
            provider.id.as_str(),
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

fn provider_key(provider: &DiportProvider) -> (&str, &str, &str, &str, &str) {
    (
        provider.id.as_str(),
        provider.port.as_str(),
        provider.provider.as_str(),
        provider.provider_crate.as_str(),
        provider.consumer.as_str(),
    )
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
id = "listener-pdp"
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = ["resources"]
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
        assert_eq!(manifest.diport_providers[0].required_features, ["backend"]);
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
            [LifecycleChannel::Resources]
        );
        manifest.validate_basic().expect("valid manifest");
    }

    #[test]
    fn provider_roles_are_required_closed_and_unique() {
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("id = \"listener-pdp\"\n", ""))
                .is_err()
        );

        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("listener-pdp", "Listener_Pdp"))
                .is_err()
        );

        let mut duplicate = AssemblyManifest::from_toml_str(MINIMAL).expect("manifest");
        duplicate
            .diport_providers
            .push(duplicate.diport_providers[0].clone());
        assert!(duplicate.basic_validation_errors().contains(
            &ManifestValidationError::Duplicate {
                field: "diportProviders.id"
            }
        ));
    }

    #[test]
    fn parses_closed_dlx_lifecycle_provider_ports() {
        for (port, expected) in [
            (
                "diport::DlxLifecycleRepository",
                DiportPort::DlxLifecycleRepository,
            ),
            ("diport::DlxArchiveStore", DiportPort::DlxArchiveStore),
        ] {
            let source = MINIMAL.replace("diport::Pdp", port);
            let manifest = AssemblyManifest::from_toml_str(&source).expect("DLX port parses");
            assert_eq!(manifest.diport_providers[0].port, expected);
        }
    }

    #[test]
    fn parses_service_token_replay_store_provider_port() {
        let source = MINIMAL.replace("diport::Pdp", "diport::ServiceTokenReplayStore");
        let manifest =
            AssemblyManifest::from_toml_str(&source).expect("service-token replay port parses");
        assert_eq!(
            manifest.diport_providers[0].port,
            DiportPort::ServiceTokenReplayStore
        );
    }

    #[test]
    fn rejects_retired_eventexec_dlx_ports_and_cipher_port() {
        for retired in [
            ["eventexec::DlxLifecycle", "Repository"].concat(),
            ["eventexec::DlxArchive", "Store"].concat(),
            ["eventexec::DlxArchive", "Cipher"].concat(),
        ] {
            let source = MINIMAL.replace("diport::Pdp", &retired);
            assert!(
                AssemblyManifest::from_toml_str(&source).is_err(),
                "retired port unexpectedly parsed: {retired}"
            );
        }
    }

    #[test]
    fn framework_contracts_are_required_non_empty_and_unique() {
        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace("frameworkContracts = []\n", ""))
                .is_err()
        );

        assert!(
            AssemblyManifest::from_toml_str(&MINIMAL.replace(
                "frameworkContracts = []",
                "frameworkContracts = [\"seed.echo\"]",
            ))
            .is_err(),
            "legacy string declarations must not parse"
        );

        let invalid = AssemblyManifest::from_toml_str(&MINIMAL.replace(
            "frameworkContracts = []",
            "frameworkContracts = [{ id = \"\", listener = \"admin\" }, { id = \"seed.echo\", listener = \"admin\" }, { id = \"seed.echo\", listener = \"primary\" }]",
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
    fn framework_contract_listener_must_be_declared() {
        let invalid = AssemblyManifest::from_toml_str(&MINIMAL.replace(
            "frameworkContracts = []",
            "frameworkContracts = [{ id = \"seed.echo\", listener = \"admin\" }]",
        ))
        .expect("typed framework mount parses before graph validation");
        let errors = invalid
            .validate_graph_evidence()
            .expect_err("undeclared listener must fail")
            .into_vec();
        assert!(
            errors.contains(&GraphEvidenceValidationError::UnknownFrameworkListener {
                contract_id: "seed.echo".to_string(),
                listener: AssemblyListenerKind::Admin,
            })
        );
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
        let missing_provider = MINIMAL.replace("outputs = [\"resources\"]\n", "");
        assert!(AssemblyManifest::from_toml_str(&missing_provider).is_err());
    }
}
