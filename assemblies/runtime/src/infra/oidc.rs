use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use diport::{
    DynManagedResource, FederatedAccessProfile, ManagedResource, RssAccessProfile,
    ServiceTokenProfile, ShutdownError, TokenProfileMarker,
};
use oidc::{AccessJwksKeyIsolation, IsolatedJwksKeySource, JwksReadinessHandle, OidcProvider};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use tokio_util::sync::CancellationToken;

use crate::SystemClock;
use crate::config::{FederatedAccessTokenConfig, RssAccessTokenConfig, ServiceTokenConfig};

pub(crate) const RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME: &str = "rss_access_token_jwks_ready";
pub(crate) const FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME: &str =
    "federated_access_token_jwks_ready";

const RSS_ACCESS_TOKEN_JWKS_SOURCE_ID: &str = "rss-access-token";
const FEDERATED_ACCESS_TOKEN_JWKS_SOURCE_ID: &str = "federated-access-token";
const RSS_ACCESS_TOKEN_RESOURCE_NAME: &str = "rss_access_token_verifier";
const FEDERATED_ACCESS_TOKEN_RESOURCE_NAME: &str = "federated_access_token_verifier";
const SERVICE_TOKEN_RESOURCE_NAME: &str = "service_token_verifier";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessProfile {
    Rss,
    Federated,
}

impl AccessProfile {
    const fn jwks_path_env(self) -> &'static str {
        match self {
            Self::Rss => "RSS_ACCESS_TOKEN_JWKS_PATH",
            Self::Federated => "RSS_FEDERATED_ACCESS_TOKEN_JWKS_PATH",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JwksFailureReason {
    Unreadable,
    Malformed,
    NoUsableKeys,
    InvalidKey,
    KeyMaterialOverlap,
    Setup,
}

impl std::fmt::Display for JwksFailureReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unreadable => "is unreadable",
            Self::Malformed => "is malformed",
            Self::NoUsableKeys => "contains no usable keys",
            Self::InvalidKey => "contains a non-keyed or non-ES256 key",
            Self::KeyMaterialOverlap => "reuses another active access profile key",
            Self::Setup => "could not be initialized",
        })
    }
}

/// Secret-safe, closed classification of profile-specific JWKS startup failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{} {reason}", profile.jwks_path_env())]
struct RuntimeJwksLoadError {
    profile: AccessProfile,
    reason: JwksFailureReason,
}

impl RuntimeJwksLoadError {
    fn from_oidc(profile: AccessProfile, error: oidc::JwksError) -> Self {
        let reason = match error {
            oidc::JwksError::Unreadable => JwksFailureReason::Unreadable,
            oidc::JwksError::Malformed => JwksFailureReason::Malformed,
            oidc::JwksError::NoUsableKeys => JwksFailureReason::NoUsableKeys,
            oidc::JwksError::InvalidKey => JwksFailureReason::InvalidKey,
            oidc::JwksError::KeyMaterialOverlap => JwksFailureReason::KeyMaterialOverlap,
            oidc::JwksError::ZeroInterval | oidc::JwksError::NoRuntime => JwksFailureReason::Setup,
            _ => JwksFailureReason::Setup,
        };
        Self { profile, reason }
    }
}

/// A runtime access-token verifier whose marker fixes the accepted token profile.
pub(crate) struct RuntimeAccessProvider<P: TokenProfileMarker> {
    provider: Arc<OidcProvider<P>>,
    jwks_readiness: ProfileJwksReadiness<P>,
    resource_name: &'static str,
}

impl<P: TokenProfileMarker> RuntimeAccessProvider<P> {
    pub(crate) fn provider(&self) -> Arc<OidcProvider<P>> {
        Arc::clone(&self.provider)
    }

    pub(crate) fn jwks_readiness(&self) -> ProfileJwksReadiness<P> {
        self.jwks_readiness.clone()
    }

    pub(crate) fn managed_resource(&self) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(OidcProviderGuard {
            provider: Arc::clone(&self.provider),
            resource_name: self.resource_name,
        })
    }
}

/// Readiness remains bound to the same sealed profile marker as its provider.
pub(crate) struct ProfileJwksReadiness<P: TokenProfileMarker> {
    handle: JwksReadinessHandle,
    profile: PhantomData<fn() -> P>,
}

impl<P: TokenProfileMarker> ProfileJwksReadiness<P> {
    fn new(handle: JwksReadinessHandle) -> Self {
        Self {
            handle,
            profile: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_ready(&self) -> bool {
        self.handle.is_ready()
    }
}

impl<P: TokenProfileMarker> Clone for ProfileJwksReadiness<P> {
    fn clone(&self) -> Self {
        Self::new(self.handle.clone())
    }
}

/// The service-token verifier is physically separate from both access-token verifiers.
pub(crate) struct RuntimeServiceTokenProvider {
    provider: Arc<OidcProvider<ServiceTokenProfile>>,
}

impl RuntimeServiceTokenProvider {
    pub(crate) fn provider(&self) -> Arc<OidcProvider<ServiceTokenProfile>> {
        Arc::clone(&self.provider)
    }

    pub(crate) fn managed_resource(&self) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(OidcProviderGuard {
            provider: Arc::clone(&self.provider),
            resource_name: SERVICE_TOKEN_RESOURCE_NAME,
        })
    }
}

struct OidcProviderGuard<P: TokenProfileMarker> {
    provider: Arc<OidcProvider<P>>,
    resource_name: &'static str,
}

impl<P: TokenProfileMarker> ManagedResource for OidcProviderGuard<P> {
    fn name(&self) -> &str {
        self.resource_name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        ManagedResource::shutdown(&*self.provider).await
    }
}

/// Profile-specific readiness probe. The constructor fixes the exact public probe name.
pub(crate) struct AccessTokenJwksReadyProbe {
    name: ProbeName,
    handle: JwksReadinessHandle,
}

impl AccessTokenJwksReadyProbe {
    #[allow(clippy::expect_used)]
    pub(crate) fn rss_access(readiness: ProfileJwksReadiness<RssAccessProfile>) -> Self {
        Self {
            name: ProbeName::parse(RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME)
                .expect("valid RSS access-token probe name"),
            handle: readiness.handle,
        }
    }

    #[allow(clippy::expect_used)]
    pub(crate) fn federated_access(
        readiness: ProfileJwksReadiness<FederatedAccessProfile>,
    ) -> Self {
        Self {
            name: ProbeName::parse(FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME)
                .expect("valid federated access-token probe name"),
            handle: readiness.handle,
        }
    }
}

impl bootstrap::HealthProbe for AccessTokenJwksReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.handle.is_ready() {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "degraded")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct AccessProviderBuildContext<P: TokenProfileMarker> {
    cancellation: CancellationToken,
    isolation: Option<AccessJwksKeyIsolation<P>>,
    clock: Box<dyn diport::Clock>,
}

impl<P: TokenProfileMarker> AccessProviderBuildContext<P> {
    fn new(
        cancellation: CancellationToken,
        isolation: Option<AccessJwksKeyIsolation<P>>,
        clock: Box<dyn diport::Clock>,
    ) -> Self {
        Self {
            cancellation,
            isolation,
            clock,
        }
    }
}

/// Build the verifier for RSS-issued access tokens from only the RSS namespace.
pub(crate) fn build_rss_access_provider(
    config: &RssAccessTokenConfig,
    cancellation: CancellationToken,
    isolation: Option<AccessJwksKeyIsolation<RssAccessProfile>>,
) -> anyhow::Result<RuntimeAccessProvider<RssAccessProfile>> {
    build_rss_access_provider_from_values(
        config.issuer(),
        config.audience(),
        config
            .trusted_kinds()
            .iter()
            .copied()
            .map(crate::config::AccessPrincipalKind::as_str),
        config.jwks_path(),
        config.jwks_refresh_interval(),
        AccessProviderBuildContext::new(cancellation, isolation, Box::new(SystemClock)),
    )
}

/// Build the verifier for federated access tokens from only the federated namespace.
pub(crate) fn build_federated_access_provider(
    config: &FederatedAccessTokenConfig,
    cancellation: CancellationToken,
    isolation: Option<AccessJwksKeyIsolation<FederatedAccessProfile>>,
) -> anyhow::Result<RuntimeAccessProvider<FederatedAccessProfile>> {
    build_federated_access_provider_from_values(
        config.issuer(),
        config.audience(),
        config
            .trusted_kinds()
            .iter()
            .copied()
            .map(crate::config::AccessPrincipalKind::as_str),
        config.jwks_path(),
        config.jwks_refresh_interval(),
        AccessProviderBuildContext::new(cancellation, isolation, Box::new(SystemClock)),
    )
}

/// Closed production owner set for durable service-token replay.
///
/// Keeping this trait inside the private runtime OIDC module makes an in-memory or process-local
/// replay store unrepresentable at every production service-token composition site.
mod service_token_replay_owner_sealed {
    pub trait Sealed {}

    impl Sealed for postgres::PgRuntimeDeps {}
    impl Sealed for postgres::PgMaintenanceDeps {}
}

pub(crate) trait ServiceTokenReplayOwner: service_token_replay_owner_sealed::Sealed {
    fn service_token_replay_store(&self) -> Arc<diport::DynServiceTokenReplayStore<'static>>;
}

impl ServiceTokenReplayOwner for postgres::PgRuntimeDeps {
    fn service_token_replay_store(&self) -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        postgres::PgRuntimeDeps::service_token_replay_store(self)
    }
}

impl ServiceTokenReplayOwner for postgres::PgMaintenanceDeps {
    fn service_token_replay_store(&self) -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        postgres::PgMaintenanceDeps::service_token_replay_store(self)
    }
}

/// Build the service-token verifier from only the service-token namespace and the closed durable
/// PostgreSQL replay-owner set.
pub(crate) fn build_service_token_provider(
    config: &ServiceTokenConfig,
    replay_owner: &impl ServiceTokenReplayOwner,
    replay_timeout: Duration,
) -> anyhow::Result<RuntimeServiceTokenProvider> {
    self::build_service_token_provider_from_values(
        config.issuer(),
        config.audience(),
        config.hs256_kid(),
        config.hs256_secret(),
        replay_owner.service_token_replay_store(),
        replay_timeout,
        Box::new(SystemClock),
    )
}

#[cfg(feature = "integration")]
pub(crate) fn build_service_token_provider_from_values_for_test(
    issuer: &str,
    audience: &str,
    key_id: &str,
    secret: &[u8],
    replay_store: Arc<diport::DynServiceTokenReplayStore<'static>>,
    replay_timeout: Duration,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<Arc<OidcProvider<ServiceTokenProfile>>> {
    build_service_token_provider_from_values(
        issuer,
        audience,
        key_id,
        secret,
        replay_store,
        replay_timeout,
        clock,
    )
    .map(|runtime| runtime.provider())
}

fn build_rss_access_provider_from_values<'a>(
    issuer: &str,
    audience: &str,
    trusted_kinds: impl IntoIterator<Item = &'a str>,
    jwks_path: &std::path::Path,
    refresh_interval: Duration,
    context: AccessProviderBuildContext<RssAccessProfile>,
) -> anyhow::Result<RuntimeAccessProvider<RssAccessProfile>> {
    let AccessProviderBuildContext {
        cancellation,
        isolation,
        clock,
    } = context;
    let (builder, readiness) = match isolation {
        Some(isolation) => {
            let jwks = load_isolated_access_jwks(
                AccessProfile::Rss,
                RSS_ACCESS_TOKEN_JWKS_SOURCE_ID,
                jwks_path,
                refresh_interval,
                cancellation,
                isolation,
            )?;
            let readiness = jwks.readiness_handle();
            let builder = oidc::VerifierConfigBuilder::<RssAccessProfile>::new(issuer, audience)
                .keys_isolated_jwks(jwks);
            (builder, readiness)
        }
        None => {
            let jwks = load_access_jwks(
                AccessProfile::Rss,
                RSS_ACCESS_TOKEN_JWKS_SOURCE_ID,
                jwks_path,
                refresh_interval,
                cancellation,
            )?;
            let readiness = jwks.readiness_handle();
            let builder = oidc::VerifierConfigBuilder::<RssAccessProfile>::new(issuer, audience)
                .keys_jwks(jwks);
            (builder, readiness)
        }
    };
    let jwks_readiness = ProfileJwksReadiness::<RssAccessProfile>::new(readiness);
    let builder = trusted_kinds
        .into_iter()
        .fold(builder, |builder, kind| builder.trust_kind(kind));
    let provider = finish_provider(builder.build(), clock)?;
    Ok(RuntimeAccessProvider {
        provider: Arc::new(provider),
        jwks_readiness,
        resource_name: RSS_ACCESS_TOKEN_RESOURCE_NAME,
    })
}

fn build_federated_access_provider_from_values<'a>(
    issuer: &str,
    audience: &str,
    trusted_kinds: impl IntoIterator<Item = &'a str>,
    jwks_path: &std::path::Path,
    refresh_interval: Duration,
    context: AccessProviderBuildContext<FederatedAccessProfile>,
) -> anyhow::Result<RuntimeAccessProvider<FederatedAccessProfile>> {
    let AccessProviderBuildContext {
        cancellation,
        isolation,
        clock,
    } = context;
    let (builder, readiness) = match isolation {
        Some(isolation) => {
            let jwks = load_isolated_access_jwks(
                AccessProfile::Federated,
                FEDERATED_ACCESS_TOKEN_JWKS_SOURCE_ID,
                jwks_path,
                refresh_interval,
                cancellation,
                isolation,
            )?;
            let readiness = jwks.readiness_handle();
            let builder =
                oidc::VerifierConfigBuilder::<FederatedAccessProfile>::new(issuer, audience)
                    .keys_isolated_jwks(jwks);
            (builder, readiness)
        }
        None => {
            let jwks = load_access_jwks(
                AccessProfile::Federated,
                FEDERATED_ACCESS_TOKEN_JWKS_SOURCE_ID,
                jwks_path,
                refresh_interval,
                cancellation,
            )?;
            let readiness = jwks.readiness_handle();
            let builder =
                oidc::VerifierConfigBuilder::<FederatedAccessProfile>::new(issuer, audience)
                    .keys_jwks(jwks);
            (builder, readiness)
        }
    };
    let jwks_readiness = ProfileJwksReadiness::<FederatedAccessProfile>::new(readiness);
    let builder = trusted_kinds
        .into_iter()
        .fold(builder, |builder, kind| builder.trust_kind(kind));
    let provider = finish_provider(builder.build(), clock)?;
    Ok(RuntimeAccessProvider {
        provider: Arc::new(provider),
        jwks_readiness,
        resource_name: FEDERATED_ACCESS_TOKEN_RESOURCE_NAME,
    })
}

fn load_access_jwks(
    profile: AccessProfile,
    source_id: &'static str,
    path: &std::path::Path,
    refresh_interval: Duration,
    cancellation: CancellationToken,
) -> Result<oidc::JwksKeySource, RuntimeJwksLoadError> {
    oidc::JwksKeySource::load_and_watch(
        source_id,
        path.to_path_buf(),
        refresh_interval,
        cancellation,
    )
    .map_err(|error| RuntimeJwksLoadError::from_oidc(profile, error))
}

fn load_isolated_access_jwks<P: TokenProfileMarker>(
    profile: AccessProfile,
    source_id: &'static str,
    path: &std::path::Path,
    refresh_interval: Duration,
    cancellation: CancellationToken,
    isolation: AccessJwksKeyIsolation<P>,
) -> Result<IsolatedJwksKeySource<P>, RuntimeJwksLoadError> {
    oidc::JwksKeySource::load_and_watch_isolated(
        source_id,
        path.to_path_buf(),
        refresh_interval,
        cancellation,
        isolation,
    )
    .map_err(|error| RuntimeJwksLoadError::from_oidc(profile, error))
}

fn build_service_token_provider_from_values(
    issuer: &str,
    audience: &str,
    key_id: &str,
    secret: &[u8],
    replay_store: Arc<diport::DynServiceTokenReplayStore<'static>>,
    replay_timeout: Duration,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<RuntimeServiceTokenProvider> {
    let keys = oidc::ServiceTokenKeySource::builder()
        .add_hs256_secret(key_id, secret)
        .map_err(|error| anyhow::anyhow!("invalid service-token key configuration: {error}"))?
        .build();
    let config = oidc::VerifierConfigBuilder::<ServiceTokenProfile>::new(issuer, audience)
        .keys_hs256(keys)
        .replay_store(replay_store, replay_timeout)
        .build()
        .map_err(|error| anyhow::anyhow!("invalid service-token verifier config: {error}"))?;
    Ok(RuntimeServiceTokenProvider {
        provider: Arc::new(OidcProvider::new(config, clock)),
    })
}

fn finish_provider<P: TokenProfileMarker>(
    config: Result<oidc::VerifierConfig<P>, oidc::ConfigError>,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<OidcProvider<P>> {
    let config =
        config.map_err(|error| anyhow::anyhow!("invalid access-token verifier config: {error}"))?;
    Ok(OidcProvider::new(config, clock))
}

/// One exact-kid ES256 key for the strictly scoped RSS static verifier.
pub struct KeyedEs256StaticKey<'a> {
    pub key_id: &'a str,
    pub sec1_b64url: &'a str,
}

/// Named inputs for non-serving RSS maintenance/tests. This profile cannot carry an HS key.
pub struct RssAccessStaticProviderConfig<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub trusted_kinds: &'a [&'a str],
    pub keys: &'a [KeyedEs256StaticKey<'a>],
    pub clock: Box<dyn diport::Clock>,
}

/// Construct a keyed, RSS-only static verifier without reading process environment.
pub fn rss_access_provider_from_static_config(
    config: RssAccessStaticProviderConfig<'_>,
) -> anyhow::Result<OidcProvider<RssAccessProfile>> {
    anyhow::ensure!(
        !config.trusted_kinds.is_empty(),
        "RSS access static verifier must trust at least one principal kind"
    );
    let mut keys = oidc::AccessStaticKeySource::builder();
    for key in config.keys {
        let sec1 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key.sec1_b64url)
            .map_err(|_| anyhow::anyhow!("RSS access ES256 key is not valid base64url"))?;
        keys = keys
            .add_es256_sec1(key.key_id, &sec1)
            .map_err(|error| anyhow::anyhow!("invalid RSS access ES256 key: {error}"))?;
    }
    let builder =
        oidc::VerifierConfigBuilder::<RssAccessProfile>::new(config.issuer, config.audience)
            .keys_static(keys.build());
    let builder = config
        .trusted_kinds
        .iter()
        .copied()
        .fold(builder, |builder, kind| builder.trust_kind(kind));
    finish_provider(builder.build(), config.clock)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::SigningKey;

    use super::*;

    struct TestReplayStore;

    impl diport::ServiceTokenReplayStore for TestReplayStore {
        async fn check_and_record(
            &self,
            _key: &diport::ServiceTokenReplayKey,
            _expires_at: std::time::SystemTime,
            _deadline: diport::ServiceTokenReplayDeadline,
        ) -> Result<diport::ServiceTokenReplayDisposition, diport::ServiceTokenReplayStoreError>
        {
            Ok(diport::ServiceTokenReplayDisposition::Recorded)
        }
    }

    fn replay_store() -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        diport::DynServiceTokenReplayStore::new_arc(TestReplayStore)
    }

    static TEMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        let seq = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("rss-runtime-{}-{seq}-{name}", std::process::id()))
    }

    #[allow(clippy::expect_used)]
    fn write_temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = unique_temp_path(name);
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    #[allow(clippy::expect_used)]
    fn es256_fixture(kid: &str) -> (String, String) {
        es256_fixture_with_scalar(kid, [0x42_u8; 32])
    }

    #[allow(clippy::expect_used)]
    fn es256_fixture_with_scalar(kid: &str, scalar: [u8; 32]) -> (String, String) {
        let signing_key = SigningKey::from_slice(&scalar).expect("valid scalar");
        let point = signing_key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"));
        let jwks = format!(
            r#"{{"keys":[{{"kty":"EC","kid":"{kid}","alg":"ES256","crv":"P-256","x":"{x}","y":"{y}"}}]}}"#
        );
        let sec1 = URL_SAFE_NO_PAD.encode(point.as_bytes());
        (jwks, sec1)
    }

    fn hs256_jwks() -> String {
        let key = URL_SAFE_NO_PAD.encode([0x44_u8; 32]);
        format!(r#"{{"keys":[{{"kty":"oct","kid":"service","alg":"HS256","k":"{key}"}}]}}"#)
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rss_and_federated_build_independent_typed_jwks_providers() {
        let (rss_jwks, _) = es256_fixture("rss-kid");
        let (federated_jwks, _) = es256_fixture_with_scalar("federated-kid", [0x11_u8; 32]);
        let rss_path = write_temp_file("rss-access-jwks.json", rss_jwks.as_bytes());
        let federated_path =
            write_temp_file("federated-access-jwks.json", federated_jwks.as_bytes());
        let (rss_isolation, federated_isolation) =
            oidc::AccessJwksKeyIsolationGeneration::new().into_bindings();

        let rss = build_rss_access_provider_from_values(
            "https://rss.issuer.test",
            "rss-audience",
            ["user", "device", "admin", "superAdmin"],
            &rss_path,
            Duration::from_secs(5),
            AccessProviderBuildContext::new(
                CancellationToken::new(),
                Some(rss_isolation),
                Box::new(SystemClock),
            ),
        )
        .expect("RSS access provider");
        let federated = build_federated_access_provider_from_values(
            "https://federated.issuer.test",
            "federated-audience",
            ["user", "device"],
            &federated_path,
            Duration::from_secs(5),
            AccessProviderBuildContext::new(
                CancellationToken::new(),
                Some(federated_isolation),
                Box::new(SystemClock),
            ),
        )
        .expect("federated access provider");

        fn require_rss(_: &OidcProvider<RssAccessProfile>) {}
        fn require_federated(_: &OidcProvider<FederatedAccessProfile>) {}
        require_rss(rss.provider().as_ref());
        require_federated(federated.provider().as_ref());
        assert!(rss.jwks_readiness().is_ready());
        assert!(federated.jwks_readiness().is_ready());
        assert_eq!(
            rss.managed_resource().name(),
            RSS_ACCESS_TOKEN_RESOURCE_NAME
        );
        assert_eq!(
            federated.managed_resource().name(),
            FEDERATED_ACCESS_TOKEN_RESOURCE_NAME
        );

        rss.managed_resource()
            .shutdown()
            .await
            .expect("shutdown RSS provider");
        federated
            .managed_resource()
            .shutdown()
            .await
            .expect("shutdown federated provider");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn active_access_profiles_reject_overlapping_initial_key_material() {
        let (rss_jwks, _) = es256_fixture("rss-kid");
        let (federated_jwks, _) = es256_fixture("federated-kid");
        let rss_path = write_temp_file("isolated-rss-jwks.json", rss_jwks.as_bytes());
        let federated_path =
            write_temp_file("isolated-federated-jwks.json", federated_jwks.as_bytes());
        let (rss_isolation, federated_isolation) =
            oidc::AccessJwksKeyIsolationGeneration::new().into_bindings();

        let rss = build_rss_access_provider_from_values(
            "https://rss.issuer.test",
            "rss-audience",
            ["user"],
            &rss_path,
            Duration::from_secs(5),
            AccessProviderBuildContext::new(
                CancellationToken::new(),
                Some(rss_isolation),
                Box::new(SystemClock),
            ),
        )
        .expect("RSS access provider");
        let error = build_federated_access_provider_from_values(
            "https://federated.issuer.test",
            "federated-audience",
            ["user"],
            &federated_path,
            Duration::from_secs(5),
            AccessProviderBuildContext::new(
                CancellationToken::new(),
                Some(federated_isolation),
                Box::new(SystemClock),
            ),
        )
        .err()
        .expect("overlapping public key must reject federated provider");
        let typed = error
            .downcast_ref::<RuntimeJwksLoadError>()
            .expect("typed runtime JWKS error");
        assert_eq!(typed.profile, AccessProfile::Federated);
        assert_eq!(typed.reason, JwksFailureReason::KeyMaterialOverlap);
        assert!(!error.to_string().contains("rss-kid"));
        assert!(!error.to_string().contains("federated-kid"));

        rss.managed_resource()
            .shutdown()
            .await
            .expect("shutdown RSS provider");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn access_jwks_rejects_hs_key_with_profile_specific_error() {
        let path = write_temp_file("rss-access-hs-jwks.json", hs256_jwks().as_bytes());
        let error = build_rss_access_provider_from_values(
            "https://rss.issuer.test",
            "rss-audience",
            ["user"],
            &path,
            Duration::from_secs(5),
            AccessProviderBuildContext::new(CancellationToken::new(), None, Box::new(SystemClock)),
        )
        .err()
        .expect("HS key cannot enter access profile");
        let typed = error
            .downcast_ref::<RuntimeJwksLoadError>()
            .expect("typed runtime JWKS error");
        assert_eq!(typed.profile, AccessProfile::Rss);
        assert_eq!(typed.reason, JwksFailureReason::InvalidKey);
        assert!(error.to_string().contains("RSS_ACCESS_TOKEN_JWKS_PATH"));
        assert!(!error.to_string().contains(path.to_string_lossy().as_ref()));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn service_provider_uses_only_keyed_hs256_and_replay() {
        let secret = [0x55_u8; 32];
        let service = build_service_token_provider_from_values(
            "https://service.issuer.test",
            "service-audience",
            "service-kid",
            &secret,
            replay_store(),
            Duration::from_secs(5),
            Box::new(SystemClock),
        )
        .expect("service-token provider");

        fn require_service(_: &OidcProvider<ServiceTokenProfile>) {}
        require_service(service.provider().as_ref());
        assert_eq!(
            service.managed_resource().name(),
            SERVICE_TOKEN_RESOURCE_NAME
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn readiness_probe_names_are_profile_specific() {
        let (rss_jwks, _) = es256_fixture("rss-kid");
        let (federated_jwks, _) = es256_fixture_with_scalar("federated-kid", [0x11_u8; 32]);
        let rss_path = write_temp_file("probe-rss-access-jwks.json", rss_jwks.as_bytes());
        let federated_path = write_temp_file(
            "probe-federated-access-jwks.json",
            federated_jwks.as_bytes(),
        );
        let (rss_isolation, federated_isolation) =
            oidc::AccessJwksKeyIsolationGeneration::new().into_bindings();
        let rss = build_rss_access_provider_from_values(
            "https://rss.issuer.test",
            "rss-audience",
            ["user"],
            &rss_path,
            Duration::from_secs(5),
            AccessProviderBuildContext::new(
                CancellationToken::new(),
                Some(rss_isolation),
                Box::new(SystemClock),
            ),
        )
        .expect("RSS access provider");
        let federated = build_federated_access_provider_from_values(
            "https://federated.issuer.test",
            "federated-audience",
            ["user"],
            &federated_path,
            Duration::from_secs(5),
            AccessProviderBuildContext::new(
                CancellationToken::new(),
                Some(federated_isolation),
                Box::new(SystemClock),
            ),
        )
        .expect("federated access provider");

        let rss_probe = AccessTokenJwksReadyProbe::rss_access(rss.jwks_readiness());
        let federated_probe =
            AccessTokenJwksReadyProbe::federated_access(federated.jwks_readiness());
        let rss_check = bootstrap::HealthProbe::check(&rss_probe);
        let federated_check = bootstrap::HealthProbe::check(&federated_probe);
        assert_eq!(
            rss_check.name().as_str(),
            RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME
        );
        assert_eq!(
            federated_check.name().as_str(),
            FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME
        );
        assert_eq!(rss_check.status(), HealthStatus::Healthy);
        assert_eq!(federated_check.status(), HealthStatus::Healthy);

        rss.managed_resource()
            .shutdown()
            .await
            .expect("shutdown RSS provider");
        federated
            .managed_resource()
            .shutdown()
            .await
            .expect("shutdown federated provider");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn keyed_rss_static_provider_has_no_service_key_path() {
        let (_, sec1) = es256_fixture("static-rss-kid");
        let keys = [KeyedEs256StaticKey {
            key_id: "static-rss-kid",
            sec1_b64url: &sec1,
        }];
        let provider = rss_access_provider_from_static_config(RssAccessStaticProviderConfig {
            issuer: "https://rss.issuer.test",
            audience: "rss-audience",
            trusted_kinds: &["user"],
            keys: &keys,
            clock: Box::new(SystemClock),
        })
        .expect("strict RSS static provider");
        fn require_rss(_: &OidcProvider<RssAccessProfile>) {}
        require_rss(&provider);
    }

    #[test]
    fn service_secret_error_does_not_echo_secret() {
        let secret = b"private";
        let error = build_service_token_provider_from_values(
            "https://service.issuer.test",
            "service-audience",
            "service-kid",
            secret,
            replay_store(),
            Duration::from_secs(5),
            Box::new(SystemClock),
        )
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
        assert!(error.contains("invalid service-token key configuration"));
        assert!(!error.contains("private"));
    }
}
