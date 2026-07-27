//! Bundled RuntimePlan compiler.

mod domain;
mod domain_exec;
mod listener;
mod placement;
mod placement_exec;

use crate::config::SnapshotConfig;
use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, AssemblyManifest, ListenerAuth, ParsedAssemblyLock,
    RuntimePlan as TypedRuntimePlan, RuntimePlanV1Input,
};
use primitives::{AuthScheme, ListenerKind};
use std::fmt;

const BUNDLED_ASSEMBLY_TOML: &str = include_str!("../assembly.toml");
const BUNDLED_ASSEMBLY_LOCK: &[u8] = include_bytes!("../assembly.lock.json");
const BUNDLED_DEPLOYMENT_PLAN: &[u8] =
    include_bytes!("../../../deploy/generated/runtime.deployment-plan.json");

pub(crate) use domain_exec::DomainExecutionPlan;
pub(crate) use placement_exec::PlacementExecutionPlan;
#[cfg(test)]
pub(crate) use placement_exec::{PlacementExecutionSpec, PlacementMode};

/// Runtime-owned entrypoint around the shared, sealed protocol value.
pub struct RuntimePlan {
    plan: TypedRuntimePlan,
    assembly_identity: String,
}

/// A validated listener projection that can only be minted from [`RuntimePlan`].
///
/// INVARIANT: RUNTIME-LISTENER-PLAN-EXECUTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private execution fields plus RuntimePlan-only mint and consuming FinalizedListenerSet handoff" } -- runtime listener identity, domain placement, authentication and launch membership cross the composition root only through this plan-derived capability.
pub(crate) struct ListenerExecutionPlan {
    listeners: Vec<ListenerExecutionSpec>,
}

pub(crate) struct ListenerExecutionSpec {
    id: String,
    kind: ListenerKind,
    auth_scheme: AuthScheme,
    domains: Vec<AssemblyDomain>,
}

impl ListenerExecutionPlan {
    pub(crate) fn listeners(&self) -> &[ListenerExecutionSpec] {
        &self.listeners
    }

    pub(crate) fn into_listeners(self) -> Vec<ListenerExecutionSpec> {
        self.listeners
    }
}

impl ListenerExecutionSpec {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) const fn kind(&self) -> ListenerKind {
        self.kind
    }

    pub(crate) const fn auth_scheme(&self) -> AuthScheme {
        self.auth_scheme
    }

    pub(crate) fn domains(&self) -> &[AssemblyDomain] {
        &self.domains
    }

    /// Project a fingerprint-verified access-listener fixture onto the closed Federated profile.
    ///
    /// This exists only for integration tests that exercise non-User principals. It accepts no
    /// raw scheme and preserves the fixture's listener identity and domain membership.
    #[cfg(feature = "integration")]
    pub(crate) fn into_federated_access_fixture(mut self) -> anyhow::Result<Self> {
        anyhow::ensure!(
            matches!(self.kind, ListenerKind::Primary | ListenerKind::Admin)
                && self.auth_scheme == AuthScheme::RssAccessToken,
            "Federated integration fixture requires a plan-declared access listener"
        );
        self.auth_scheme = AuthScheme::FederatedAccessToken;
        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn health_for_test() -> Self {
        Self {
            id: "health-main".to_owned(),
            kind: ListenerKind::Health,
            auth_scheme: AuthScheme::NoAuth,
            domains: Vec::new(),
        }
    }
}

impl RuntimePlan {
    /// Build the exact bundled plan from the committed manifest, lock and captured configuration.
    pub(crate) fn bundled(config: SnapshotConfig<'_>) -> Result<Self, RuntimePlanError> {
        Self::from_bundled_artifacts(BUNDLED_ASSEMBLY_TOML, BUNDLED_ASSEMBLY_LOCK, config)
    }

    fn from_bundled_artifacts(
        manifest_toml: &str,
        assembly_lock_json: &[u8],
        config: SnapshotConfig<'_>,
    ) -> Result<Self, RuntimePlanError> {
        let manifest = AssemblyManifest::from_toml_str(manifest_toml)
            .map_err(RuntimePlanError::ManifestParse)?
            .canonicalize_v1()
            .map_err(RuntimePlanError::ManifestCanonicalization)?;
        let lock = ParsedAssemblyLock::from_json_slice(assembly_lock_json)
            .map_err(RuntimePlanError::AssemblyLock)?;

        let mut input = RuntimePlanV1Input::from_manifest(&manifest);
        listener::append(&manifest, config, &mut input)?;
        domain::append(&manifest, &mut input);
        placement::append(&manifest, &lock, config, &mut input)?;

        let plan = TypedRuntimePlan::compile_v1(&manifest, &lock, input)
            .map_err(RuntimePlanError::Protocol)?;
        Ok(Self {
            plan,
            assembly_identity: lock.identity().name().to_owned(),
        })
    }

    pub const fn as_typed(&self) -> &TypedRuntimePlan {
        &self.plan
    }

    #[cfg_attr(not(test), allow(dead_code))]
    // reason: assembly identity accessor for placement matrix / inventory tests.
    pub(crate) fn assembly_identity(&self) -> &str {
        &self.assembly_identity
    }

    pub(crate) fn listener_execution_plan(&self) -> ListenerExecutionPlan {
        listener_execution_plan_from_typed(&self.plan)
    }

    /// Project exclusive Local / Remote placement execution facts.
    ///
    /// INVARIANT: RUNTIME-PLACEMENT-PLAN-EXECUTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private execution fields plus RuntimePlan-only mint and exclusive Local composition or Remote transport binding" } -- this is the sole mint for [`PlacementExecutionPlan`].
    pub(crate) fn placement_execution_plan(
        &self,
        config: SnapshotConfig<'_>,
    ) -> PlacementExecutionPlan {
        placement_exec::mint(&self.plan, &self.assembly_identity, config)
    }

    /// Project the exact locally composed domain sequence from plan declarations and placement.
    pub(crate) fn domain_execution_plan(
        &self,
        placement: &PlacementExecutionPlan,
    ) -> DomainExecutionPlan {
        domain_exec::mint(&self.plan, placement)
    }

    pub(crate) fn bundled_deployment_plan(
        &self,
    ) -> Result<assembly_schema::ParsedDeploymentPlan, RuntimePlanError> {
        assembly_schema::ParsedDeploymentPlan::from_json_slice(&self.plan, BUNDLED_DEPLOYMENT_PLAN)
            .map_err(RuntimePlanError::DeploymentPlan)
    }
}

fn listener_execution_plan_from_typed(plan: &TypedRuntimePlan) -> ListenerExecutionPlan {
    ListenerExecutionPlan {
        listeners: plan
            .listener_plans()
            .iter()
            .map(|listener| ListenerExecutionSpec {
                id: listener.id().to_owned(),
                kind: runtime_listener_kind(listener.kind()),
                auth_scheme: runtime_auth_scheme(listener.auth()),
                domains: listener.domains().to_vec(),
            })
            .collect(),
    }
}

pub(crate) fn is_kebab_case_workload(value: &str) -> bool {
    let mut chars = value.chars().peekable();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    let mut prev_hyphen = false;
    for ch in chars {
        match ch {
            'a'..='z' | '0'..='9' => prev_hyphen = false,
            '-' if !prev_hyphen => prev_hyphen = true,
            _ => return false,
        }
    }
    !prev_hyphen
}

#[cfg(feature = "integration")]
pub(crate) fn fixture_listener_spec(
    kind: AssemblyListenerKind,
) -> anyhow::Result<ListenerExecutionSpec> {
    let manifest = AssemblyManifest::from_toml_str(BUNDLED_ASSEMBLY_TOML)
        .map_err(|error| anyhow::anyhow!("parse bundled fixture manifest: {error}"))?
        .canonicalize_v1()
        .map_err(|error| anyhow::anyhow!("canonicalize bundled fixture manifest: {error}"))?;
    let lock = ParsedAssemblyLock::from_json_slice(BUNDLED_ASSEMBLY_LOCK)
        .map_err(|error| anyhow::anyhow!("parse bundled fixture lock: {error}"))?;
    let parsed = assembly_schema::ParsedRuntimePlan::from_json_slice_bound(
        include_bytes!("../runtime-plan.json"),
        &manifest,
        &lock,
    )
    .map_err(|error| anyhow::anyhow!("parse fingerprint-verified RuntimePlan fixture: {error}"))?;
    listener_execution_plan_from_typed(parsed.as_plan())
        .into_listeners()
        .into_iter()
        .find(|listener| listener.kind() == runtime_listener_kind(kind))
        .ok_or_else(|| anyhow::anyhow!("RuntimePlan fixture does not declare requested listener"))
}

const fn runtime_listener_kind(kind: AssemblyListenerKind) -> ListenerKind {
    match kind {
        AssemblyListenerKind::Primary => ListenerKind::Primary,
        AssemblyListenerKind::Internal => ListenerKind::Internal,
        AssemblyListenerKind::Admin => ListenerKind::Admin,
        AssemblyListenerKind::Health => ListenerKind::Health,
    }
}

const fn runtime_auth_scheme(auth: ListenerAuth) -> AuthScheme {
    match auth {
        ListenerAuth::NoAuth => AuthScheme::NoAuth,
        ListenerAuth::RssAccessToken => AuthScheme::RssAccessToken,
        ListenerAuth::FederatedAccessToken => AuthScheme::FederatedAccessToken,
        ListenerAuth::Mtls => AuthScheme::Mtls,
        ListenerAuth::ServiceToken => AuthScheme::ServiceToken,
    }
}

impl fmt::Debug for RuntimePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.plan.fmt(f)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RuntimePlanError {
    #[error("parse bundled runtime assembly manifest failed")]
    ManifestParse(#[source] toml::de::Error),
    #[error("canonicalize bundled runtime assembly manifest failed")]
    ManifestCanonicalization(#[source] assembly_schema::AssemblyManifestCanonicalizationError),
    #[error("parse bundled runtime AssemblyLock failed")]
    AssemblyLock(#[source] assembly_schema::AssemblyLockError),
    #[error(
        "resolve RSS_PRIMARY_TOKEN_PROFILE, RSS_ADMIN_TOKEN_PROFILE, or RSS_INTERNAL_AUTH_SCHEME failed; expected rss-access/federated-access and mtls/service-token"
    )]
    ListenerAuth,
    #[error("resolve {env} failed; expected a non-empty lowercase kebab-case workload name")]
    PlacementWorkload {
        /// Exact `RSS_<DOMAIN>_DOMAIN_PLACEMENT_WORKLOAD` env key that failed validation.
        env: String,
    },
    #[error("parse bundled DeploymentPlan failed")]
    DeploymentPlan(#[source] assembly_schema::DeploymentPlanError),
    #[error("compile bundled RuntimePlan protocol failed: {0}")]
    Protocol(#[source] assembly_schema::RuntimePlanError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    // reason: bundled protocol/golden tests should stop at the exact local drift assertion.

    use super::*;
    use crate::config::test_snapshot;
    use assembly_schema::{
        AssemblyDomain, AssemblyListenerKind, CanonicalAssemblyManifestV1, DomainLifecyclePhase,
        ListenerAuth, ProviderLifecycle, RuntimePlanErrorStage,
    };
    use std::collections::BTreeMap;
    use std::error::Error as _;

    const SECRET_BAIT: &str = "ZZ_RUNTIME_PLAN_SECRET_1788";
    const IDENTITY_AUDIT_ASSEMBLY_LOCK: &[u8] =
        include_bytes!("../../identityaudit/assembly.lock.json");

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mutation {
        MissingProvider,
        DuplicateProvider,
        MissingListener,
        DuplicateListener,
        MissingDomain,
        DuplicateDomain,
        MissingPlacement,
        DuplicatePlacement,
        DanglingListener,
        DanglingPlacement,
        ReverseListeners,
        ReversePlacements,
    }

    fn profile_snapshot(entries: &[(&str, &str)]) -> crate::config::RuntimeConfigSnapshot {
        let mut merged = BTreeMap::from([
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ]);
        merged.extend(entries.iter().copied());
        let merged = merged.into_iter().collect::<Vec<_>>();
        test_snapshot(&merged).expect("test snapshot")
    }

    fn bundled(entries: &[(&str, &str)]) -> RuntimePlan {
        let snapshot = profile_snapshot(entries);
        RuntimePlan::bundled(snapshot.view()).expect("bundled RuntimePlan")
    }

    fn artifact_error(manifest_toml: &str, assembly_lock_json: &[u8]) -> RuntimePlanError {
        let snapshot = profile_snapshot(&[("RSS_VAULT_TOKEN", SECRET_BAIT)]);
        RuntimePlan::from_bundled_artifacts(manifest_toml, assembly_lock_json, snapshot.view())
            .expect_err("invalid bundled artifact must fail")
    }

    fn canonical_manifest(source: &str) -> CanonicalAssemblyManifestV1 {
        AssemblyManifest::from_toml_str(source)
            .expect("manifest")
            .canonicalize_v1()
            .expect("canonical manifest")
    }

    fn parsed_lock(source: &[u8]) -> ParsedAssemblyLock {
        ParsedAssemblyLock::from_json_slice(source).expect("AssemblyLock")
    }

    fn compile_error(
        manifest: &CanonicalAssemblyManifestV1,
        lock: &ParsedAssemblyLock,
    ) -> assembly_schema::RuntimePlanError {
        TypedRuntimePlan::compile_v1(manifest, lock, compiler_input(manifest, lock, None))
            .expect_err("mismatched manifest/lock must fail")
    }

    fn compiler_input(
        manifest: &CanonicalAssemblyManifestV1,
        lock: &ParsedAssemblyLock,
        mutation: Option<Mutation>,
    ) -> RuntimePlanV1Input {
        let mut input = RuntimePlanV1Input::new();
        append_candidate_providers(manifest, mutation, &mut input);
        append_candidate_listeners(manifest, mutation, &mut input);
        append_candidate_domains(manifest, mutation, &mut input);
        append_candidate_placements(manifest, lock, mutation, &mut input);
        input
    }

    fn append_candidate_providers(
        manifest: &CanonicalAssemblyManifestV1,
        mutation: Option<Mutation>,
        input: &mut RuntimePlanV1Input,
    ) {
        let mut providers = manifest.diport_providers().iter().collect::<Vec<_>>();
        providers.retain(|provider| provider.lifecycle == ProviderLifecycle::Active);
        providers.sort_by_key(|provider| provider.id.as_str());
        for (index, provider) in providers.iter().enumerate() {
            if index == 0 && mutation == Some(Mutation::MissingProvider) {
                continue;
            }
            input.provider(
                provider.id.as_str(),
                provider.provider,
                provider.outputs.clone(),
            );
            if index == 0 && mutation == Some(Mutation::DuplicateProvider) {
                input.provider(
                    provider.id.as_str(),
                    provider.provider,
                    provider.outputs.clone(),
                );
            }
        }
    }

    fn append_candidate_listeners(
        manifest: &CanonicalAssemblyManifestV1,
        mutation: Option<Mutation>,
        input: &mut RuntimePlanV1Input,
    ) {
        let mut listeners = manifest
            .listeners()
            .iter()
            .map(|listener| {
                let auth = match listener.kind {
                    AssemblyListenerKind::Primary | AssemblyListenerKind::Admin => {
                        ListenerAuth::RssAccessToken
                    }
                    AssemblyListenerKind::Internal => ListenerAuth::Mtls,
                    AssemblyListenerKind::Health => ListenerAuth::NoAuth,
                };
                (listener.kind, auth, listener.domains.clone())
            })
            .collect::<Vec<_>>();
        listeners.sort_by_key(|(kind, _, _)| kind.as_str());
        if mutation == Some(Mutation::ReverseListeners) {
            listeners.reverse();
        }
        for (index, (kind, auth, domains)) in listeners.iter().enumerate() {
            if index == 0 && mutation == Some(Mutation::MissingListener) {
                continue;
            }
            let domains = if index == 0 && mutation == Some(Mutation::DanglingListener) {
                vec![AssemblyDomain::Contractreg]
            } else {
                domains.clone()
            };
            input.listener(*kind, *auth, domains.clone());
            if index == 0 && mutation == Some(Mutation::DuplicateListener) {
                input.listener(*kind, *auth, domains);
            }
        }
    }

    fn append_candidate_domains(
        manifest: &CanonicalAssemblyManifestV1,
        mutation: Option<Mutation>,
        input: &mut RuntimePlanV1Input,
    ) {
        for (index, domain) in manifest.domains().iter().enumerate() {
            if index == 0 && mutation == Some(Mutation::MissingDomain) {
                continue;
            }
            input.domain(*domain);
            if index == 0 && mutation == Some(Mutation::DuplicateDomain) {
                input.domain(*domain);
            }
        }
    }

    fn append_candidate_placements(
        manifest: &CanonicalAssemblyManifestV1,
        lock: &ParsedAssemblyLock,
        mutation: Option<Mutation>,
        input: &mut RuntimePlanV1Input,
    ) {
        let mut placements = manifest
            .domains()
            .iter()
            .map(|domain| (*domain, lock.identity().name()))
            .collect::<Vec<_>>();
        placements
            .sort_by(|left, right| (left.0.as_str(), left.1).cmp(&(right.0.as_str(), right.1)));
        if mutation == Some(Mutation::ReversePlacements) {
            placements.reverse();
        }
        for (index, (domain, workload)) in placements.iter().enumerate() {
            if index == 0 && mutation == Some(Mutation::MissingPlacement) {
                continue;
            }
            let domain = if index == 0 && mutation == Some(Mutation::DanglingPlacement) {
                AssemblyDomain::Contractreg
            } else {
                *domain
            };
            input.placement(domain, *workload);
            if index == 0 && mutation == Some(Mutation::DuplicatePlacement) {
                input.placement(domain, *workload);
            }
        }
    }

    #[test]
    fn runtime_plan_bundled_closes_every_declared_fact_in_stable_order() {
        let plan = bundled(&[]);
        let typed = plan.as_typed();
        let provider_ids = typed
            .provider_plans()
            .iter()
            .map(assembly_schema::ProviderPlan::id)
            .collect::<Vec<_>>();
        assert_eq!(
            provider_ids,
            [
                "auth-audit-sink",
                "device-revocation-store",
                "distributed-cas-store",
                "distributed-lock-store",
                "dlx-archive-key-provider",
                "dlx-archive-store",
                "dlx-lifecycle-repository",
                "event-publisher",
                "event-subscriber",
                "identity-signer",
                "listener-pdp",
                "listener-rate-limiter",
                "runtime-object-store",
                "service-token-replay-store",
                "settings-key-provider",
                "settings-secret-resolver",
            ]
        );
        assert_eq!(
            typed
                .listener_plans()
                .iter()
                .map(|listener| (listener.id(), listener.auth()))
                .collect::<Vec<_>>(),
            [
                ("admin-main", ListenerAuth::RssAccessToken),
                ("health-main", ListenerAuth::NoAuth),
                ("internal-main", ListenerAuth::Mtls),
                ("primary-main", ListenerAuth::RssAccessToken),
            ]
        );
        assert_eq!(
            typed
                .domain_plans()
                .iter()
                .map(|domain| domain.id().as_str())
                .collect::<Vec<_>>(),
            ["settings", "identity", "audit"]
        );
        assert!(typed.domain_plans().iter().all(|domain| domain.lifecycle()
            == [
                DomainLifecyclePhase::Construct,
                DomainLifecyclePhase::Ready,
                DomainLifecyclePhase::Shutdown
            ]));
        assert_eq!(
            typed
                .placement_plans()
                .iter()
                .map(|placement| (placement.domain().as_str(), placement.workload()))
                .collect::<Vec<_>>(),
            [
                ("audit", "runtime"),
                ("identity", "runtime"),
                ("settings", "runtime"),
            ]
        );
    }

    #[test]
    fn runtime_plan_listener_profiles_are_typed_but_secret_only_config_is_excluded() {
        let default = bundled(&[]);
        let service_token = bundled(&[("RSS_INTERNAL_AUTH_SCHEME", "service-token")]);
        assert_ne!(
            default.as_typed().runtime_plan_fingerprint().as_str(),
            service_token.as_typed().runtime_plan_fingerprint().as_str()
        );
        assert_eq!(
            service_token.as_typed().listener_plans()[2].auth(),
            ListenerAuth::ServiceToken
        );

        let federated = bundled(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "federated-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "federated-access"),
        ]);
        assert_ne!(
            default.as_typed().runtime_plan_fingerprint().as_str(),
            federated.as_typed().runtime_plan_fingerprint().as_str()
        );
        assert_eq!(
            federated.as_typed().listener_plans()[0].auth(),
            ListenerAuth::FederatedAccessToken
        );
        assert_eq!(
            federated.as_typed().listener_plans()[3].auth(),
            ListenerAuth::FederatedAccessToken
        );

        let secret_only = bundled(&[("RSS_VAULT_TOKEN", SECRET_BAIT)]);
        assert_eq!(
            default.as_typed().runtime_plan_fingerprint().as_str(),
            secret_only.as_typed().runtime_plan_fingerprint().as_str()
        );
        let json = serde_json::to_string(secret_only.as_typed()).expect("plan JSON");
        let debug = format!("{secret_only:?}");
        assert!(!json.contains(SECRET_BAIT));
        assert!(!debug.contains(SECRET_BAIT));
        assert!(!debug.contains("oidc::OidcProvider"));
    }

    #[test]
    fn runtime_plan_unknown_internal_auth_fails_closed_without_echoing_value() {
        let snapshot = profile_snapshot(&[("RSS_INTERNAL_AUTH_SCHEME", SECRET_BAIT)]);
        let error = RuntimePlan::bundled(snapshot.view()).expect_err("invalid auth must fail");
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("RSS_INTERNAL_AUTH_SCHEME"));
        assert!(diagnostic.contains("mtls"));
        assert!(diagnostic.contains("service-token"));
        assert!(!diagnostic.contains(SECRET_BAIT));
        assert!(!format!("{error:?}").contains(SECRET_BAIT));
    }

    #[test]
    fn runtime_plan_rejects_asymmetric_federated_primary_selection() {
        let snapshot = profile_snapshot(&[("RSS_PRIMARY_TOKEN_PROFILE", "federated-access")]);
        let error = RuntimePlan::bundled(snapshot.view())
            .expect_err("federated Primary with RSS Admin must fail");
        assert!(error.to_string().contains("RSS_PRIMARY_TOKEN_PROFILE"));
    }

    #[test]
    fn runtime_plan_compiler_rejects_manifest_lock_name_mismatch() {
        let manifest = canonical_manifest(BUNDLED_ASSEMBLY_TOML);
        let lock = parsed_lock(IDENTITY_AUDIT_ASSEMBLY_LOCK);

        let error = compile_error(&manifest, &lock);
        assert_eq!(error.stage(), RuntimePlanErrorStage::AssemblyIdentity);
        assert_eq!(
            error.to_string(),
            "RuntimePlan identity does not match the canonical assembly manifest and lock"
        );
    }

    #[test]
    fn runtime_plan_compiler_rejects_manifest_lock_profile_mismatch() {
        let source =
            BUNDLED_ASSEMBLY_TOML.replacen("profile = \"production\"", "profile = \"demo\"", 1);
        let manifest = canonical_manifest(&source);
        let lock = parsed_lock(BUNDLED_ASSEMBLY_LOCK);

        let error = compile_error(&manifest, &lock);
        assert_eq!(error.stage(), RuntimePlanErrorStage::AssemblyIdentity);
        assert_eq!(
            error.to_string(),
            "RuntimePlan identity does not match the canonical assembly manifest and lock"
        );
    }

    #[test]
    fn runtime_plan_compiler_rejects_manifest_digest_mismatch() {
        let source = BUNDLED_ASSEMBLY_TOML.replacen(
            "purpose = \"device-certificate-revocation\"",
            "purpose = \"device-certificate-revocation-v2\"",
            1,
        );
        let manifest = canonical_manifest(&source);
        let lock = parsed_lock(BUNDLED_ASSEMBLY_LOCK);

        let error = compile_error(&manifest, &lock);
        assert_eq!(error.stage(), RuntimePlanErrorStage::ManifestDigest);
        assert_eq!(
            error.to_string(),
            "RuntimePlan canonical manifest digest does not match AssemblyLock"
        );
    }

    #[test]
    fn runtime_plan_bundled_manifest_parse_error_preserves_safe_source() {
        let error = artifact_error("name = [", BUNDLED_ASSEMBLY_LOCK);

        assert_eq!(
            error.to_string(),
            "parse bundled runtime assembly manifest failed"
        );
        assert!(
            error
                .source()
                .is_some_and(|source| source.is::<toml::de::Error>())
        );
        assert!(!format!("{error:?}").contains(SECRET_BAIT));
    }

    #[test]
    fn runtime_plan_bundled_manifest_canonicalization_error_preserves_safe_source() {
        let source = BUNDLED_ASSEMBLY_TOML.replacen(
            "domains = [\"settings\", \"identity\", \"audit\"]",
            "domains = []",
            1,
        );
        let error = artifact_error(&source, BUNDLED_ASSEMBLY_LOCK);

        assert_eq!(
            error.to_string(),
            "canonicalize bundled runtime assembly manifest failed"
        );
        assert!(error.source().is_some_and(|source| {
            source.is::<assembly_schema::AssemblyManifestCanonicalizationError>()
        }));
        assert!(!format!("{error:?}").contains(SECRET_BAIT));
    }

    #[test]
    fn runtime_plan_bundled_lock_parse_error_preserves_safe_source_chain() {
        let error = artifact_error(BUNDLED_ASSEMBLY_TOML, b"{");

        assert_eq!(
            error.to_string(),
            "parse bundled runtime AssemblyLock failed"
        );
        let source = error.source().expect("AssemblyLock source");
        assert!(source.is::<assembly_schema::AssemblyLockError>());
        assert!(
            source
                .source()
                .is_some_and(|source| source.is::<serde_json::Error>())
        );
        assert!(!format!("{error:?}").contains(SECRET_BAIT));
    }

    #[test]
    fn runtime_plan_compiler_rejects_complete_negative_matrix() {
        let manifest = AssemblyManifest::from_toml_str(BUNDLED_ASSEMBLY_TOML)
            .expect("manifest")
            .canonicalize_v1()
            .expect("canonical manifest");
        let lock =
            ParsedAssemblyLock::from_json_slice(BUNDLED_ASSEMBLY_LOCK).expect("AssemblyLock");

        TypedRuntimePlan::compile_v1(&manifest, &lock, compiler_input(&manifest, &lock, None))
            .expect("unmutated candidate facts must compile");
        for mutation in [
            Mutation::MissingProvider,
            Mutation::DuplicateProvider,
            Mutation::MissingListener,
            Mutation::DuplicateListener,
            Mutation::MissingDomain,
            Mutation::DuplicateDomain,
            Mutation::MissingPlacement,
            Mutation::DuplicatePlacement,
            Mutation::DanglingListener,
            Mutation::DanglingPlacement,
            Mutation::ReverseListeners,
            Mutation::ReversePlacements,
        ] {
            assert!(
                TypedRuntimePlan::compile_v1(
                    &manifest,
                    &lock,
                    compiler_input(&manifest, &lock, Some(mutation))
                )
                .is_err(),
                "compiler accepted {mutation:?}"
            );
        }
    }

    #[test]
    fn runtime_plan_bundled_json_matches_full_golden() {
        let mut actual =
            serde_json::to_string_pretty(bundled(&[]).as_typed()).expect("RuntimePlan JSON");
        actual.push('\n');
        assert_eq!(
            actual.as_bytes(),
            include_bytes!("../runtime-plan.json"),
            "runtime RuntimePlan artifact drift"
        );
    }

    #[test]
    fn listener_plan_execution_projects_bundled_four_listener_baseline() {
        let runtime_plan = bundled(&[]);
        let execution = runtime_plan.listener_execution_plan();
        let actual = execution
            .listeners()
            .iter()
            .map(|listener| {
                (
                    listener.id(),
                    listener.kind(),
                    listener.auth_scheme(),
                    listener.domains().to_vec(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            actual,
            vec![
                (
                    "admin-main",
                    primitives::ListenerKind::Admin,
                    primitives::AuthScheme::RssAccessToken,
                    vec![AssemblyDomain::Audit],
                ),
                (
                    "health-main",
                    primitives::ListenerKind::Health,
                    primitives::AuthScheme::NoAuth,
                    vec![],
                ),
                (
                    "internal-main",
                    primitives::ListenerKind::Internal,
                    primitives::AuthScheme::Mtls,
                    vec![],
                ),
                (
                    "primary-main",
                    primitives::ListenerKind::Primary,
                    primitives::AuthScheme::RssAccessToken,
                    vec![AssemblyDomain::Settings, AssemblyDomain::Identity],
                ),
            ]
        );
    }

    #[test]
    fn auth_plan_execution_projects_every_closed_listener_scheme() {
        let service_token = bundled(&[("RSS_INTERNAL_AUTH_SCHEME", "service-token")]);
        let service_token_schemes = service_token
            .listener_execution_plan()
            .listeners()
            .iter()
            .map(|listener| (listener.kind(), listener.auth_scheme()))
            .collect::<Vec<_>>();
        assert!(service_token_schemes.contains(&(
            primitives::ListenerKind::Internal,
            primitives::AuthScheme::ServiceToken,
        )));

        let federated = bundled(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "federated-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "federated-access"),
        ]);
        let federated_schemes = federated
            .listener_execution_plan()
            .listeners()
            .iter()
            .map(|listener| (listener.kind(), listener.auth_scheme()))
            .collect::<Vec<_>>();
        assert!(federated_schemes.contains(&(
            primitives::ListenerKind::Primary,
            primitives::AuthScheme::FederatedAccessToken,
        )));
        assert!(federated_schemes.contains(&(
            primitives::ListenerKind::Admin,
            primitives::AuthScheme::FederatedAccessToken,
        )));
        assert!(federated_schemes.contains(&(
            primitives::ListenerKind::Health,
            primitives::AuthScheme::NoAuth,
        )));
    }
}
