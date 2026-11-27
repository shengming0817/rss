//! Tenant-bound OIDC adapter with versioned credentials and independent trusted MFA profiles.
//! ref: oauth2-rs src/code.rs @ 5.0.0 (code flow, state and PKCE).
#![deny(missing_docs)]
mod assurance;
mod code;
mod discovery;
mod freshness;
use discovery::Metadata;
mod egress;
mod resources;
pub use resources::ReusePolicy;
use resources::{ClientPool, ProviderResources, Resources};
use std::{collections::HashMap, sync::Arc};
mod profile_token;
/// Protocol fixture helpers for explicitly test-enabled hosts.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub use ipnet::IpNet;
pub mod entra;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use rss_identity_core::{assurance::AuthenticationMode, federation::*};
use rss_request_context::TenantId;
use std::{
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};
use zeroize::Zeroizing;
/// Host time sources for request execution and upstream HTTP cache age.
#[derive(Clone)]
pub struct ProviderClock {
    timer: rss_request_context::SharedExecutionTimer,
    wall: std::sync::Arc<dyn Fn() -> std::time::SystemTime + Send + Sync>,
}
impl ProviderClock {
    /// Use the same execution timer as the host. HTTP Date and Expires use civil time.
    pub fn new(
        timer: rss_request_context::SharedExecutionTimer,
        wall: impl Fn() -> std::time::SystemTime + Send + Sync + 'static,
    ) -> Self {
        Self {
            timer,
            wall: std::sync::Arc::new(wall),
        }
    }
    fn now(&self) -> std::time::Instant {
        rss_request_context::Clock::now(&self.timer)
    }
    async fn until<F: std::future::Future>(
        &self,
        cutoff: rss_request_context::Deadline,
        future: F,
    ) -> Result<F::Output, ()> {
        use rss_request_context::ExecutionTimer;
        tokio::select! { biased; _=self.timer.sleep_until(cutoff)=>Err(()),result=future=>Ok(result) }
    }
}
/// Host-selected finite upstream time and document budgets.
#[derive(Clone, Copy, Debug)]
pub struct TransportPolicy {
    request_timeout: Duration,
    connect_timeout: Duration,
    max_response_bytes: usize,
    max_jwks_keys: usize,
}
impl TransportPolicy {
    /// Validate technical ranges; callers choose deployment capacity.
    pub fn new(
        request_timeout: Duration,
        connect_timeout: Duration,
        max_response_bytes: usize,
        max_jwks_keys: usize,
    ) -> Result<Self, FederationError> {
        if request_timeout.is_zero()
            || connect_timeout.is_zero()
            || request_timeout == Duration::MAX
            || connect_timeout == Duration::MAX
            || max_response_bytes == 0
            || max_jwks_keys == 0
        {
            return Err(FederationError::Configuration);
        }
        Ok(Self {
            request_timeout,
            connect_timeout,
            max_response_bytes,
            max_jwks_keys,
        })
    }
    fn validate_at(self, now: std::time::Instant) -> Result<(), FederationError> {
        check_durations(now, &[self.request_timeout, self.connect_timeout])
    }
}
fn check_durations(now: std::time::Instant, durations: &[Duration]) -> Result<(), FederationError> {
    if durations
        .iter()
        .all(|duration| now.checked_add(*duration).is_some())
    {
        Ok(())
    } else {
        Err(FederationError::Configuration)
    }
}
fn remaining(
    clock: &ProviderClock,
    deadline: rss_request_context::Deadline,
) -> Result<Duration, FederationError> {
    left(clock, deadline, ProviderStage::Exchange)
}
fn left(
    clock: &ProviderClock,
    deadline: rss_request_context::Deadline,
    stage: ProviderStage,
) -> Result<Duration, FederationError> {
    deadline
        .remaining(clock.now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| failure(stage, ProviderReason::Timeout))
}
/// Host-approved interpretation of verified authentication facts. Not IdP admission.
#[derive(Clone)]
pub struct TrustedAssuranceProfile {
    /// Exact tenant owning this authentication policy.
    pub tenant: TenantId,
    /// Exact issuer owning the verified token.
    pub issuer: String,
    /// Registered RP client.
    pub client_id: String,
    /// The operator verified this client uses the Keycloak password/TOTP LoA 2 flow.
    pub keycloak_totp: bool,
}
/// Host-owned permission for one tenant's exact upstream client to reach private networks.
/// This grants transport access only, never trusted MFA or resource authorization.
#[derive(Clone)]
pub struct PrivateProviderAccess {
    /// Exact tenant permitted to use this destination.
    pub tenant: TenantId,
    /// Full HTTPS issuer, including its realm path and port.
    pub issuer: String,
    /// Exact upstream RP client.
    pub client_id: String,
    /// Canonical, unique RFC1918 or IPv6 ULA subnets (1 to 16).
    pub cidrs: Vec<IpNet>,
}
fn failure(stage: ProviderStage, reason: ProviderReason) -> FederationError {
    FederationError::provider(stage, reason)
}
#[derive(Debug, thiserror::Error)]
#[error("invalid protocol destination")]
struct EgressDenied;
/// Protocol transport with tenant credentials supplied for each exact provider version.
pub struct HttpOidc {
    future_skew_seconds: u32,
    policy: TransportPolicy,
    bindings: Bindings,
    resources: Arc<Resources>,
    revisions: ProviderRevisions,
    loopback: bool,
}
#[derive(Default)]
struct Grant {
    cidrs: Vec<IpNet>,
    assurance: Option<bool>,
}
type Bindings = HashMap<TenantId, HashMap<String, HashMap<String, Grant>>>;

impl HttpOidc {
    /// Select the accepted signed-time skew; it never extends token expiry.
    pub fn with_future_skew(mut self, seconds: u32) -> Self {
        self.future_skew_seconds = seconds;
        self
    }

    /// Production uses HTTPS and vetted public or explicitly authorized private addresses.
    /// Every DNS answer is checked against the current tenant/issuer/client permission.
    pub fn new(
        clock: ProviderClock,
        profiles: Vec<TrustedAssuranceProfile>,
        private_access: Vec<PrivateProviderAccess>,
        policy: TransportPolicy,
        reuse: ReusePolicy,
    ) -> Result<Self, FederationError> {
        Self::build(clock, profiles, private_access, false, policy, reuse)
    }
    /// Explicit loopback protocol fixture.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_loopback_test(
        clock: ProviderClock,
        profiles: Vec<TrustedAssuranceProfile>,
        policy: TransportPolicy,
        reuse: ReusePolicy,
    ) -> Result<Self, FederationError> {
        Self::build(clock, profiles, vec![], true, policy, reuse)
    }
    fn build(
        clock: ProviderClock,
        profiles: Vec<TrustedAssuranceProfile>,
        private_access: Vec<PrivateProviderAccess>,
        loopback: bool,
        policy: TransportPolicy,
        reuse: ReusePolicy,
    ) -> Result<Self, FederationError> {
        policy.validate_at(clock.now())?;
        if profiles.len() > 1024 || private_access.len() > 1024 {
            return Err(FederationError::Configuration);
        }
        let mut bindings = Bindings::new();
        for mut grant in private_access {
            grant.cidrs.sort_unstable();
            if grant.cidrs.is_empty()
                || grant.cidrs.len() > 16
                || grant.cidrs.iter().any(|n| !egress::private_network(*n))
                || grant.cidrs.windows(2).any(|pair| pair[0] == pair[1])
            {
                return Err(FederationError::Configuration);
            }
            rss_identity_core::IssuerId::parse(&grant.issuer)
                .map_err(|_| FederationError::Configuration)?;
            rss_identity_core::ClientId::parse(&grant.client_id)
                .map_err(|_| FederationError::Configuration)?;
            parse_url(&grant.issuer, false, &grant.cidrs)?;
            let entry = bindings
                .entry(grant.tenant)
                .or_default()
                .entry(grant.issuer)
                .or_default()
                .entry(grant.client_id)
                .or_default();
            if !entry.cidrs.is_empty() {
                return Err(FederationError::Configuration);
            }
            entry.cidrs = grant.cidrs;
        }
        for profile in profiles {
            if profile.client_id.is_empty() || profile.client_id.len() > 256 {
                return Err(FederationError::Configuration);
            }
            let clients = bindings
                .entry(profile.tenant)
                .or_default()
                .entry(profile.issuer.clone())
                .or_default();
            let entry = clients.entry(profile.client_id).or_default();
            parse_url(&profile.issuer, loopback, &entry.cidrs)?;
            if entry.assurance.replace(profile.keycloak_totp).is_some() {
                return Err(FederationError::Configuration);
            }
        }
        Ok(Self {
            bindings,
            resources: Resources::new(reuse, clock)?,
            revisions: ProviderRevisions::new(
                reuse.max_providers.saturating_add(reuse.max_refreshes),
            ),
            policy,
            loopback,
            future_skew_seconds: 30,
        })
    }
    fn grant(&self, tenant: TenantId, issuer: &str, client: &str) -> Option<&Grant> {
        self.bindings.get(&tenant)?.get(issuer)?.get(client)
    }
    fn private_for(&self, tenant: TenantId, issuer: &str, client: &str) -> &[IpNet] {
        self.grant(tenant, issuer, client).map_or(&[], |g| &g.cidrs)
    }
    fn trusted(&self, tenant: TenantId, c: &ProviderSettings) -> bool {
        self.grant(tenant, c.issuer().as_str(), c.client_id().as_str())
            .and_then(|g| g.assurance)
            == Some(true)
    }
    fn build_client(
        &self,
        credentials: &ProviderCredentials,
        cidrs: &[IpNet],
    ) -> Result<reqwest::Client, FederationError> {
        let resolver = egress::VettedResolver::new(self.loopback, cidrs.to_vec());
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(Arc::new(resolver))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(self.resources.policy.max_idle_per_host)
            .pool_idle_timeout(self.resources.policy.idle_timeout)
            .timeout(self.policy.request_timeout)
            .connect_timeout(self.policy.connect_timeout);
        for root in certificates(credentials)? {
            builder = builder.add_root_certificate(root);
        }
        builder
            .build()
            .map_err(|_| failure(ProviderStage::Binding, ProviderReason::InvalidTrustAnchor))
    }
    fn transport(
        &self,
        provider: BoundProvider,
        deadline: rss_request_context::Deadline,
        probe: bool,
    ) -> Result<Transport, FederationError> {
        left(&self.resources.clock, deadline, ProviderStage::Binding)?;
        let c = provider.settings();
        let cidrs = self.private_for(
            provider.revision().tenant,
            c.issuer().as_str(),
            c.client_id().as_str(),
        );
        let origin = parse_url(c.issuer().as_str(), self.loopback, cidrs)?
            .origin()
            .ascii_serialization();
        self.revisions.check(&provider)?;
        let slot = if probe {
            None
        } else {
            Some(self.resources.bind(&provider)?)
        };
        let http = if let Some(slot) = &slot {
            let mut pooled = slot
                .client
                .lock()
                .map_err(|_| failure(ProviderStage::Binding, ProviderReason::Unavailable))?;
            if let Some(client) = pooled.as_ref() {
                client.clone()
            } else {
                let permit = self.resources.client_permit()?;
                let client = Arc::new(ClientPool {
                    http: self.build_client(provider.credentials(), cidrs)?,
                    _permit: Some(permit),
                });
                *pooled = Some(client.clone());
                client
            }
        } else {
            Arc::new(ClientPool {
                http: self.build_client(provider.credentials(), cidrs)?,
                _permit: None,
            })
        };
        Ok(Transport {
            channel: Channel {
                clock: self.resources.clock.clone(),
                policy: self.policy,
                http,
                origin,
                installed: provider.installed().clone(),
            },
            slot,
            deadline,
            requests: AtomicU8::new(0),
        })
    }
    async fn discover(
        &self,
        provider: BoundProvider,
        deadline: rss_request_context::Deadline,
    ) -> Result<(Metadata, Arc<discovery::Representation>, Transport), FederationError> {
        let t = self.transport(provider.clone(), deadline, false)?;
        let kind = discovery::Kind::Discovery {
            issuer: provider.settings().issuer().as_str().into(),
        };
        let (doc, _) = t
            .slot
            .as_ref()
            .ok_or(FederationError::Configuration)?
            .discovery
            .read(&self.resources, &t, kind, None)
            .await?;
        Ok((doc.metadata()?, doc, t))
    }

    async fn signing_keys(
        &self,
        doc: &discovery::Representation,
        t: &Transport,
        kid: Option<&str>,
    ) -> Result<discovery::Jwks, FederationError> {
        let (uri, slot) = doc.keys()?;
        let kind = || discovery::Kind::Keys { uri: uri.clone() };
        let (first, cached) = slot.read(&self.resources, t, kind(), None).await?;
        let keys = first.jwks()?;
        if cached
            && kid.is_some_and(|id| {
                !id.is_empty()
                    && !keys
                        .keys
                        .iter()
                        .any(|v| v.get("kid").and_then(|v| v.as_str()) == Some(id))
            })
        {
            let identity = first.identity.clone();
            drop(first);
            return slot
                .read(&self.resources, t, kind(), Some(&identity))
                .await?
                .0
                .jwks();
        }
        Ok(keys)
    }
}
fn certificates(
    credentials: &ProviderCredentials,
) -> Result<Vec<reqwest::Certificate>, FederationError> {
    match credentials.ca_pem() {
        None => Ok(Vec::new()),
        Some(pem) => {
            let roots = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
                .map_err(|_| failure(ProviderStage::Binding, ProviderReason::InvalidTrustAnchor))?;
            if roots.is_empty() || roots.len() > 16 {
                return Err(failure(
                    ProviderStage::Binding,
                    ProviderReason::InvalidTrustAnchor,
                ));
            }
            Ok(roots)
        }
    }
}
fn parse_url(value: &str, loopback: bool, cidrs: &[IpNet]) -> Result<Url, FederationError> {
    let u = Url::parse(value).map_err(|_| FederationError::Configuration)?;
    let local = loopback
        && u.scheme() == "http"
        && matches!(u.host_str(), Some("127.0.0.1") | Some("localhost"));
    if (!local && u.scheme() != "https")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_some()
    {
        return Err(FederationError::Configuration);
    }
    let host = u.host_str().ok_or(FederationError::Configuration)?;
    if host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| !egress::allowed(ip, loopback, cidrs))
    {
        return Err(failure(
            ProviderStage::Binding,
            ProviderReason::EgressDenied,
        ));
    }
    Ok(u)
}
struct Transport {
    channel: Channel,
    slot: Option<Arc<ProviderResources>>,
    deadline: rss_request_context::Deadline,
    requests: AtomicU8,
}
impl Transport {
    fn charge(&self, stage: ProviderStage) -> Result<(), FederationError> {
        self.channel.check()?;
        left(&self.channel.clock, self.deadline, stage)?;
        // Discovery, token POST, JWKS, and one directed key refresh.
        self.requests
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < 4).then(|| n + 1)
            })
            .map_err(|_| failure(stage, ProviderReason::Unavailable))?;
        Ok(())
    }
    async fn call(
        &self,
        stage: ProviderStage,
        request: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, FederationError> {
        self.charge(stage)?;
        self.channel.call(stage, self.deadline, request).await
    }
}
#[derive(Clone)]
struct Channel {
    clock: ProviderClock,
    policy: TransportPolicy,
    http: Arc<ClientPool>,
    origin: String,
    installed: InstalledRevision,
}
impl Channel {
    fn check(&self) -> Result<(), FederationError> {
        self.installed.check()
    }
    fn request_error(&self, stage: ProviderStage, error: reqwest::Error) -> FederationError {
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        while let Some(value) = cause {
            if value.is::<EgressDenied>() {
                return failure(stage, ProviderReason::EgressDenied);
            }
            if value.is::<rustls::Error>() {
                return failure(stage, ProviderReason::TlsRejected);
            }
            cause = if let Some(io) = value.downcast_ref::<std::io::Error>() {
                io.get_ref()
                    .map(|v| v as &(dyn std::error::Error + 'static))
                    .or_else(|| value.source())
            } else {
                value.source()
            };
        }
        failure(
            stage,
            if error.is_timeout() {
                ProviderReason::Timeout
            } else {
                ProviderReason::Unavailable
            },
        )
    }
    async fn call(
        &self,
        stage: ProviderStage,
        deadline: rss_request_context::Deadline,
        request: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, FederationError> {
        tokio::select! {
            biased;
            _ = self.installed.retired() => Err(FederationError::StaleConfiguration),
            _ = rss_request_context::ExecutionTimer::sleep_until(&self.clock.timer,deadline) => Err(failure(stage,ProviderReason::Timeout)),
            result = self.execute(stage, deadline, request) => result,
        }
    }
    async fn execute(
        &self,
        stage: ProviderStage,
        deadline: rss_request_context::Deadline,
        request: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, FederationError> {
        self.check()?;
        let u = Url::parse(&request.uri().to_string())
            .map_err(|_| failure(stage, ProviderReason::InvalidResponse))?;
        if u.origin().ascii_serialization() != self.origin
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return Err(failure(stage, ProviderReason::EgressDenied));
        }
        let mut request: reqwest::Request = request
            .try_into()
            .map_err(|_| failure(stage, ProviderReason::InvalidResponse))?;
        *request.timeout_mut() =
            Some(left(&self.clock, deadline, stage)?.min(self.policy.request_timeout));
        let mut response = self
            .http
            .http
            .execute(request)
            .await
            .map_err(|e| self.request_error(stage, e))?;
        let status = response.status();
        if status.is_server_error() || status.as_u16() == 429 {
            return Err(failure(stage, ProviderReason::Unavailable));
        }
        let headers = response.headers().clone();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| self.request_error(stage, e))?
        {
            if bytes.len().saturating_add(chunk.len()) > self.policy.max_response_bytes {
                return Err(failure(stage, ProviderReason::InvalidResponse));
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut result = http::Response::new(bytes);
        *result.status_mut() = status;
        *result.headers_mut() = headers;
        Ok(result)
    }
}
impl UpstreamOidc for HttpOidc {
    fn assurance_profile(&self, tenant: TenantId, c: &ProviderSettings) -> AssuranceProfile {
        let approved = self.trusted(tenant, c);
        AssuranceProfile {
            fingerprint: assurance::profile_identity(approved),
            supports_step_up: approved,
        }
    }
    fn validate(
        &self,
        tenant: TenantId,
        c: &ProviderSettings,
        credentials: &ProviderCredentials,
    ) -> Result<(), FederationError> {
        parse_url(
            c.issuer().as_str(),
            self.loopback,
            self.private_for(tenant, c.issuer().as_str(), c.client_id().as_str()),
        )?;
        let roots = certificates(credentials)?;
        if !roots.is_empty() {
            let mut builder = reqwest::Client::builder().no_proxy();
            for root in roots {
                builder = builder.add_root_certificate(root);
            }
            builder
                .build()
                .map_err(|_| failure(ProviderStage::Binding, ProviderReason::InvalidTrustAnchor))?;
        }
        Ok(())
    }
    fn revisions(&self) -> &ProviderRevisions {
        &self.revisions
    }
    fn prepare<'a>(
        &'a self,
        provider: BoundProvider,
        m: &'a ProtocolMaterial,
        mode: AuthenticationMode,
        deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, String> {
        Box::pin(async move {
            let (tenant, c) = (provider.revision().tenant, provider.settings());
            if !code::valid_verifier(m.verifier.as_str()) {
                return Err(FederationError::Rejected);
            }
            if mode == AuthenticationMode::StepUp
                && !self.assurance_profile(tenant, c).supports_step_up
            {
                return Err(FederationError::Configuration);
            }
            let (metadata, _, transport) = self.discover(provider.clone(), deadline).await?;

            let scope = std::iter::once("openid")
                .chain(
                    c.scopes()
                        .iter()
                        .map(String::as_str)
                        .filter(|s| *s != "openid"),
                )
                .collect::<Vec<_>>()
                .join(" ");
            let challenge = URL_SAFE_NO_PAD.encode(digest(m.verifier.as_str()));
            let mut url = metadata.authorization_endpoint;
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("response_type", "code")
                    .append_pair("client_id", c.client_id().as_str())
                    .append_pair("state", m.state.as_str())
                    .append_pair("redirect_uri", c.redirect_uri())
                    .append_pair("scope", &scope)
                    .append_pair("nonce", m.nonce.as_str())
                    .append_pair("code_challenge", &challenge)
                    .append_pair("code_challenge_method", "S256");
                if mode != AuthenticationMode::Login {
                    query
                        .append_pair("prompt", "login")
                        .append_pair("max_age", "0");
                }
                if mode == AuthenticationMode::StepUp {
                    query.append_pair("acr_values", assurance::KEYCLOAK_TOTP_ACR);
                }
            }
            let url = url.into();
            transport.channel.check()?;
            remaining(&self.resources.clock, deadline)?;
            Ok(url)
        })
    }

    fn exchange<'a>(
        &'a self,
        provider: BoundProvider,
        m: ProtocolMaterial,
        code: Zeroizing<String>,
        deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, UpstreamClaims> {
        Box::pin(async move {
            let (tenant, c, credentials) = (
                provider.revision().tenant,
                provider.settings(),
                provider.credentials(),
            );
            if code.is_empty() || code.len() > 4096 || !code::valid_verifier(m.verifier.as_str()) {
                return Err(FederationError::Rejected);
            }

            let (metadata, doc, transport) = self.discover(provider.clone(), deadline).await?;

            let endpoint = metadata
                .token_endpoint
                .as_ref()
                .ok_or(FederationError::Configuration)?;
            let id_token =
                code::exchange(&transport, &endpoint.url, c, credentials, &m, &code).await?;
            let header = profile_token::approved_header(&id_token, &metadata)?;
            let keys = if profile_token::symmetric(header.alg) {
                None
            } else {
                Some(
                    self.signing_keys(&doc, &transport, header.kid.as_deref())
                        .await?,
                )
            };
            let key =
                profile_token::signing_key(&header, keys.as_ref(), credentials.client_secret())?;
            let claims = profile_token::verify(
                &id_token,
                header.alg,
                &key,
                &metadata,
                &m.nonce,
                c.client_id().as_str(),
                self.future_skew_seconds,
                (self.resources.clock.wall)(),
            )?;
            let all = serde_json::to_value(&claims).map_err(|_| FederationError::Claims)?;

            let groups = mapped_groups(c.claims().groups.as_deref(), &all)?;

            let value = UpstreamClaims {
                issuer: c.issuer().as_str().to_owned(),
                subject: mapped_subject(&c.claims().subject, &claims.sub, &all)?,
                profile: rss_identity_core::profile::Profile::from_claims(
                    all.as_object().ok_or(FederationError::Claims)?,
                    &c.claims().profile,
                ),
                groups,
                department_snapshot: mapped_department(
                    c.claims().department_snapshot.as_ref().map(|d| d.claim()),
                    &all,
                ),
                issued_at: claims.iat,
                expires_at: claims.exp,
                assurance: assurance::normalize(
                    claims.auth_time,
                    claims.acr.as_deref(),
                    claims.amr.clone().unwrap_or_default(),
                    self.trusted(tenant, c),
                )?,
            };

            value.validate()?;
            transport.channel.check()?;

            remaining(&self.resources.clock, deadline)?;
            Ok(value)
        })
    }

    fn test<'a>(
        &'a self,
        provider: BoundProvider,
        deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, ConnectionReport> {
        Box::pin(async move {
            let c = provider.settings();
            let t = self.transport(provider.clone(), deadline, true)?;
            let bytes = discovery::Kind::Discovery {
                issuer: c.issuer().as_str().into(),
            }
            .probe(&t, &self.resources)
            .await?;
            let metadata: Metadata = serde_json::from_slice(&bytes)
                .map_err(|_| failure(ProviderStage::Discovery, ProviderReason::InvalidResponse))?;
            discovery::Kind::Keys {
                uri: metadata.jwks_uri.clone(),
            }
            .probe(&t, &self.resources)
            .await?;
            t.channel.check()?;
            if !metadata.authorization_response_iss_parameter_supported {
                return Err(failure(
                    ProviderStage::Discovery,
                    ProviderReason::IssuerResponseUnsupported,
                ));
            }
            if deadline.is_expired(self.resources.clock.now()) {
                return Err(FederationError::Unavailable);
            }
            Ok(ConnectionReport {
                checks: vec![
                    ProviderStage::Binding,
                    ProviderStage::Discovery,
                    ProviderStage::Jwks,
                ],
                tls_verified: c.issuer().as_str().starts_with("https://"),
                authorization_response_issuer: true,
            })
        })
    }
}

fn mapped_groups(
    claim: Option<&str>,
    claims: &serde_json::Value,
) -> Result<rss_identity_core::groups::UpstreamGroups, FederationError> {
    use rss_identity_core::groups::UpstreamGroups;
    match claim {
        None => Ok(UpstreamGroups::NotConfigured),
        Some(key) => match claims.get(key) {
            None | Some(serde_json::Value::Null) => Ok(UpstreamGroups::Missing),
            Some(serde_json::Value::Array(values)) => UpstreamGroups::present(
                values
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned).ok_or(FederationError::Claims))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            _ => Err(FederationError::Claims),
        },
    }
}

fn mapped_department(
    claim: Option<&str>,
    claims: &serde_json::Value,
) -> rss_identity_core::department::UpstreamDepartmentSnapshot {
    use rss_identity_core::department::{DepartmentSnapshot, UpstreamDepartmentSnapshot};
    match claim {
        None => UpstreamDepartmentSnapshot::NotConfigured,
        Some(key) => match claims.get(key) {
            None => UpstreamDepartmentSnapshot::Missing,
            Some(value) => match serde_json::from_value::<DepartmentSnapshot>(value.clone()) {
                Ok(snapshot) => UpstreamDepartmentSnapshot::Present(snapshot),
                Err(_) => UpstreamDepartmentSnapshot::Invalid,
            },
        },
    }
}

#[cfg(test)]
mod tests;

fn mapped_subject(
    mapping: &rss_identity_core::entra::SubjectMapping,
    sub: &str,
    all: &serde_json::Value,
) -> Result<rss_identity_core::entra::ExternalSubject, FederationError> {
    use rss_identity_core::entra::{ExternalSubject, SubjectMapping};
    let subject = match mapping {
        SubjectMapping::Oidc => ExternalSubject::Oidc(sub.to_owned()),
        SubjectMapping::Entra { tenant } => {
            let tid = all
                .get("tid")
                .and_then(serde_json::Value::as_str)
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .ok_or(FederationError::Claims)?;
            let user = all
                .get("oid")
                .and_then(serde_json::Value::as_str)
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .ok_or(FederationError::Claims)?;
            if tid != *tenant {
                return Err(FederationError::Claims);
            }
            ExternalSubject::Entra { tenant: tid, user }
        }
    };
    subject.validate()?;
    Ok(subject)
}

pub mod enterprise;
