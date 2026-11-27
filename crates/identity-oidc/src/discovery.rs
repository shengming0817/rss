//! Bounded discovery using the existing vetted transport; JWT verification has one owner.
//! ref: openidconnect-rs src/discovery/mod.rs @ b639b5d39eac6903238867aeb2b29326502e6b26.
use super::{
    Channel, Transport, failure,
    resources::{ByteLease, Resources},
};
use futures_util::{
    FutureExt,
    future::{BoxFuture, WeakShared},
};
use http::{HeaderMap, HeaderValue, header};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, jwk::Jwk};
use rss_identity_core::federation::{FederationError, ProviderReason, ProviderStage};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use url::Url;

#[derive(Deserialize)]
struct WireKeys {
    keys: Vec<serde_json::Value>,
}

pub(super) struct Jwks {
    pub keys: Vec<Candidate>,
}

#[cfg_attr(test, derive(Clone))]
pub(super) struct Candidate {
    pub kid: Option<Box<str>>,
    family: Option<AlgorithmFamily>,
    algorithm: Option<Algorithm>,
    key: Option<DecodingKey>,
}
impl From<serde_json::Value> for Candidate {
    fn from(value: serde_json::Value) -> Self {
        let kid = value.get("kid").and_then(|v| v.as_str()).map(Into::into);
        let algorithm = value
            .get("alg")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok());
        let usable = value.get("use").is_none_or(|v| v.as_str() == Some("sig"))
            && value.get("key_ops").is_none_or(|v| {
                v.as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")))
            })
            && (value.get("alg").is_none() || algorithm.is_some());
        let family = match value.get("kty").and_then(|v| v.as_str()).filter(|_| usable) {
            Some("RSA") => Some(AlgorithmFamily::Rsa),
            Some("EC") => Some(AlgorithmFamily::Ec),
            Some("OKP") => Some(AlgorithmFamily::Ed),
            _ => None,
        };
        // A matching malformed key still counts towards ambiguous selection.
        let key = family
            .and_then(|_| serde_json::from_value::<Jwk>(value).ok())
            .and_then(|jwk| DecodingKey::from_jwk(&jwk).ok());
        Self {
            kid,
            family,
            algorithm,
            key,
        }
    }
}
impl Candidate {
    fn heap_bytes(&self) -> usize {
        self.kid.as_deref().map_or(0, str::len)
            + self.key.as_ref().map_or(0, |key| match key.kind() {
                DecodingKeyKind::SecretOrDer(bytes) => bytes.capacity(),
                DecodingKeyKind::RsaModulusExponent { n, e } => n.capacity() + e.capacity(),
            })
    }
}
impl Jwks {
    pub fn select(&self, header: &jsonwebtoken::Header) -> Result<&DecodingKey, FederationError> {
        let mut matches = self.keys.iter().filter(|k| {
            header
                .kid
                .as_deref()
                .is_none_or(|id| k.kid.as_deref() == Some(id))
                && k.family == Some(header.alg.family())
                && k.algorithm.is_none_or(|alg| alg == header.alg)
        });
        let first = matches.next().ok_or(FederationError::Claims)?;
        if matches.next().is_some() {
            return Err(FederationError::Claims);
        }
        first.key.as_ref().ok_or(FederationError::Claims)
    }
}

#[derive(Deserialize)]
pub(super) struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Option<TokenEndpoint>,
    pub jwks_uri: Url,
    #[serde(
        rename = "response_types_supported",
        deserialize_with = "validate_strings"
    )]
    _response_types_supported: (),
    #[serde(
        rename = "subject_types_supported",
        deserialize_with = "validate_strings"
    )]
    _subject_types_supported: (),
    #[serde(deserialize_with = "signing_algorithms")]
    pub id_token_signing_alg_values_supported: Box<[Algorithm]>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

fn validate_strings<'de, D: serde::Deserializer<'de>>(de: D) -> Result<(), D::Error> {
    Vec::<String>::deserialize(de).map(drop)
}
fn signing_algorithms<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Box<[Algorithm]>, D::Error> {
    Ok(Vec::<String>::deserialize(de)?
        .iter()
        .filter_map(|value| value.parse().ok())
        .collect())
}

impl Metadata {
    pub(super) fn bound_token_endpoint(&self, registered: &str) -> Result<&str, FederationError> {
        self.token_endpoint
            .as_ref()
            .filter(|endpoint| endpoint.advertised == registered)
            .map(|endpoint| endpoint.advertised.as_str())
            .ok_or(FederationError::Configuration)
    }
}

#[derive(Deserialize)]
#[serde(try_from = "String")]
pub(super) struct TokenEndpoint {
    pub url: Url,
    // The enterprise exchange compares the advertised endpoint against the exact host binding.
    advertised: String,
}

impl TryFrom<String> for TokenEndpoint {
    type Error = url::ParseError;

    fn try_from(advertised: String) -> Result<Self, Self::Error> {
        let url = Url::parse(&advertised)?;
        Ok(Self { url, advertised })
    }
}

#[derive(Clone)]
pub(super) enum Kind {
    Discovery { issuer: String },
    Keys { uri: Url },
}
impl Kind {
    pub async fn probe(
        &self,
        t: &Transport,
        resources: &Resources,
    ) -> Result<PublicDocument, FederationError> {
        let stage = self.stage();
        let _permit = resources
            .refreshes
            .clone()
            .try_acquire_owned()
            .map_err(|_| failure(stage, ProviderReason::Unavailable))?;
        let request = http::Request::get(self.url())
            .header(header::ACCEPT, "application/json")
            .body(Vec::new())
            .map_err(|_| invalid(stage))?;
        let response = t.call(stage, request).await?;
        if response.status() != http::StatusCode::OK || !valid_media(response.headers(), stage) {
            return Err(invalid(stage));
        }
        self.validate(response.body(), &t.channel)
    }
    fn stage(&self) -> ProviderStage {
        match self {
            Self::Discovery { .. } => ProviderStage::Discovery,
            Self::Keys { .. } => ProviderStage::Jwks,
        }
    }
    fn url(&self) -> String {
        match self {
            Self::Discovery { issuer } => format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ),
            Self::Keys { uri } => uri.to_string(),
        }
    }
    fn validate(&self, bytes: &[u8], channel: &Channel) -> Result<PublicDocument, FederationError> {
        match self {
            Self::Discovery { issuer } => {
                let mut metadata: Metadata = decode(bytes, self.stage())?;
                if metadata.issuer != *issuer {
                    return Err(failure(self.stage(), ProviderReason::IssuerMismatch));
                }
                let token = metadata
                    .token_endpoint
                    .as_mut()
                    .ok_or_else(|| failure(self.stage(), ProviderReason::EgressDenied))?;
                for url in [
                    &metadata.authorization_endpoint,
                    &token.url,
                    &metadata.jwks_uri,
                ] {
                    if url.origin().ascii_serialization() != channel.origin
                        || !url.username().is_empty()
                        || url.password().is_some()
                        || url.fragment().is_some()
                    {
                        return Err(failure(self.stage(), ProviderReason::EgressDenied));
                    }
                }
                // URL normalization can shorten the input considerably. Keep compact URL clones.
                metadata.authorization_endpoint = metadata.authorization_endpoint.clone();
                metadata.jwks_uri = metadata.jwks_uri.clone();
                token.url = token.url.clone();
                Ok(PublicDocument::Metadata(Box::new(metadata)))
            }
            Self::Keys { .. } => {
                let keys: WireKeys = decode(bytes, self.stage())?;
                if keys.keys.len() > channel.policy.max_jwks_keys {
                    return Err(invalid(self.stage()));
                }
                Ok(PublicDocument::Keys(Jwks {
                    keys: keys.keys.into_iter().map(Into::into).collect(),
                }))
            }
        }
    }
}
// Detach a retained validator from the potentially much larger transport header buffer.
fn copy_validator(
    headers: &HeaderMap,
    name: header::HeaderName,
) -> Result<Option<HeaderValue>, FederationError> {
    headers
        .get(name)
        .map(|h| HeaderValue::from_bytes(h.as_bytes()).map_err(|_| FederationError::Unavailable))
        .transpose()
}
fn invalid(stage: ProviderStage) -> FederationError {
    failure(stage, ProviderReason::InvalidResponse)
}
fn decode<T: DeserializeOwned>(bytes: &[u8], stage: ProviderStage) -> Result<T, FederationError> {
    serde_json::from_slice(bytes).map_err(|_| invalid(stage))
}
struct Fetched {
    value: Arc<Representation>,
    // A no-store response may only satisfy one of the coalesced requests.
    consumed: Option<AtomicBool>,
}
type Flight = BoxFuture<'static, Result<Option<Arc<Fetched>>, FederationError>>;

#[derive(Default)]
struct State {
    cached: Option<Cached>,
    flight: Option<WeakShared<Flight>>,
    next_unknown: Option<Instant>,
}
struct Cached {
    value: Arc<Representation>,
    until: Instant,
    freshness: crate::freshness::Freshness,
}
pub(super) enum PublicDocument {
    Metadata(Box<Metadata>),
    Keys(Jwks),
}
impl PublicDocument {
    pub fn metadata(&self) -> Result<&Metadata, FederationError> {
        match self {
            Self::Metadata(value) => Ok(value),
            _ => Err(invalid(ProviderStage::Discovery)),
        }
    }
    fn heap_bytes(&self) -> usize {
        match self {
            Self::Metadata(m) => {
                size_of::<Metadata>()
                    + m.issuer.capacity()
                    + m.authorization_endpoint.as_str().len()
                    + m.jwks_uri.as_str().len()
                    + m.token_endpoint
                        .as_ref()
                        .map_or(0, |v| v.url.as_str().len() + v.advertised.capacity())
                    + size_of_val(m.id_token_signing_alg_values_supported.as_ref())
            }
            Self::Keys(j) => {
                j.keys.capacity() * size_of::<Candidate>()
                    + j.keys.iter().map(Candidate::heap_bytes).sum::<usize>()
            }
        }
    }
}
pub(super) struct Representation {
    pub document: PublicDocument,
    etag: Option<HeaderValue>,
    modified: Option<HeaderValue>,
    keys: Option<(Url, Arc<Document>)>,
    lease: ByteLease,
    pub identity: Arc<()>,
}
impl Representation {
    fn admit(
        state: &mut State,
        resources: &Resources,
        document: PublicDocument,
        headers: &HeaderMap,
        stage: ProviderStage,
    ) -> Result<Arc<Self>, FederationError> {
        let uri = match &document {
            PublicDocument::Metadata(m) => Some(m.jwks_uri.clone()),
            PublicDocument::Keys(_) => None,
        };
        let reused = state
            .cached
            .as_ref()
            .and_then(|old| old.value.keys.as_ref())
            .filter(|(old, _)| Some(old) == uri.as_ref())
            .map(|(_, d)| d.clone());
        let etag = copy_validator(headers, header::ETAG)?;
        let modified = copy_validator(headers, header::LAST_MODIFIED)?;
        if state
            .cached
            .as_ref()
            .is_some_and(|old| retire_changed_keys(&old.value, reused.as_ref()))
        {
            state.cached = None;
        }
        let child_charge = if uri.is_some() && reused.is_none() {
            size_of::<Document>()
        } else {
            0
        };
        let overhead = size_of::<Self>()
            + etag.as_ref().map_or(0, |v| v.as_bytes().len())
            + modified.as_ref().map_or(0, |v| v.as_bytes().len())
            + uri.as_ref().map_or(0, |u| u.as_str().len());
        let total = document
            .heap_bytes()
            .checked_add(overhead)
            .and_then(|n| n.checked_add(child_charge))
            .ok_or(FederationError::Unavailable)?;
        let replaced = state
            .cached
            .as_mut()
            .and_then(|old| Arc::get_mut(&mut old.value))
            .map(|v| &mut v.lease);
        let mut lease = resources
            .reserve(total, replaced)
            .map_err(|_| failure(stage, ProviderReason::Unavailable))?;
        let keys = uri.map(|uri| {
            (
                uri,
                reused.unwrap_or_else(|| {
                    Arc::new(Document {
                        _lease: Some(lease.split(child_charge)),
                        ..Default::default()
                    })
                }),
            )
        });
        Ok(Arc::new(Self {
            document,
            etag,
            modified,
            keys,
            lease,
            identity: Arc::new(()),
        }))
    }
    pub fn jwks(&self) -> Result<&Jwks, FederationError> {
        match &self.document {
            PublicDocument::Keys(keys) => Ok(keys),
            _ => Err(invalid(ProviderStage::Jwks)),
        }
    }
    pub fn keys(&self) -> Result<(&Url, &Arc<Document>), FederationError> {
        self.keys
            .as_ref()
            .map(|(url, doc)| (url, doc))
            .ok_or_else(|| invalid(ProviderStage::Discovery))
    }
}
#[derive(Default)]
pub(super) struct Document {
    _lease: Option<ByteLease>,
    state: Mutex<State>,
    retired: AtomicBool,
}
impl Document {
    fn check(&self) -> Result<(), FederationError> {
        if self.retired.load(Ordering::Acquire) {
            Err(FederationError::StaleConfiguration)
        } else {
            Ok(())
        }
    }
    // A weak handle lets callers drive a single public GET without spawning a detached task.
    // Each waiter has its own timeout; when the last one leaves, HTTP I/O and its permit drop.
    pub async fn read(
        self: &Arc<Self>,
        resources: &Arc<Resources>,
        t: &Transport,
        kind: Kind,
        unknown_in: Option<&Arc<()>>,
    ) -> Result<(Arc<Representation>, bool), FederationError> {
        for _ in 0..2 {
            if let Some(read) = self.read_once(resources, t, &kind, unknown_in).await? {
                return Ok(read);
            }
        }
        Err(invalid(kind.stage()))
    }
    async fn read_once(
        self: &Arc<Self>,
        resources: &Arc<Resources>,
        t: &Transport,
        kind: &Kind,
        unknown_in: Option<&Arc<()>>,
    ) -> Result<Option<(Arc<Representation>, bool)>, FederationError> {
        let stage = kind.stage();
        self.check()?;
        t.channel.check()?;
        super::left(&t.channel.clock, t.deadline, stage)?;
        let flight = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = resources.now();
            let running = state.flight.as_ref().and_then(WeakShared::upgrade);
            if let Some(hit) = &state.cached {
                let fresh = hit.until > now;
                let reuse = match unknown_in {
                    None => fresh,
                    Some(seen) => {
                        fresh && !Arc::ptr_eq(seen, &hit.value.identity)
                            || running.is_none()
                                && state.next_unknown.is_some_and(|deadline| deadline > now)
                                && fresh
                    }
                };
                if reuse {
                    return Ok(Some((hit.value.clone(), true)));
                }
            }
            t.charge(stage)?;
            if let Some(running) = running {
                running
            } else {
                let permit = resources
                    .refreshes
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| failure(stage, ProviderReason::Unavailable))?;
                let owner = self.clone();
                let resources = resources.clone();
                let channel = t.channel.clone();
                if unknown_in.is_some() {
                    state.next_unknown = now.checked_add(resources.policy.refresh_cooldown);
                }
                let request_kind = kind.clone();
                let work = async move {
                    let _permit = permit;
                    let result = owner.fetch(&resources, &channel, &request_kind).await;
                    owner
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .flight = None;
                    result
                }
                .boxed()
                .shared();
                state.flight = work.downgrade();
                work
            }
        };
        let result = t
            .channel
            .clock
            .until(t.deadline, flight)
            .await
            .map_err(|_| failure(stage, ProviderReason::Timeout))??;
        self.check()?;
        t.channel.check()?;
        super::left(&t.channel.clock, t.deadline, stage)?;
        let Some(result) = result else {
            return Ok(None);
        };
        if result
            .consumed
            .as_ref()
            .is_some_and(|used| used.swap(true, Ordering::AcqRel))
        {
            t.charge(stage)?;
            let private = Document::default();
            let _permit = resources
                .refreshes
                .clone()
                .try_acquire_owned()
                .map_err(|_| failure(stage, ProviderReason::Unavailable))?;
            let own = t
                .channel
                .clock
                .until(t.deadline, private.fetch(resources, &t.channel, kind))
                .await
                .map_err(|_| failure(stage, ProviderReason::Timeout))??;
            self.check()?;
            t.channel.check()?;
            return Ok(own.map(|r| (r.value.clone(), false)));
        }
        Ok(Some((result.value.clone(), false)))
    }

    async fn fetch(
        &self,
        resources: &Resources,
        channel: &Channel,
        kind: &Kind,
    ) -> Result<Option<Arc<Fetched>>, FederationError> {
        let stage = kind.stage();
        let previous = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cached
            .as_ref()
            .map(|c| (c.value.clone(), c.freshness));
        let mut request = http::Request::get(kind.url()).header(header::ACCEPT, "application/json");
        if let Some((old, _)) = &previous {
            if let Some(tag) = &old.etag {
                request = request.header(header::IF_NONE_MATCH, tag);
            } else if let Some(date) = &old.modified {
                request = request.header(header::IF_MODIFIED_SINCE, date);
            }
        }
        self.check()?;
        let started = channel.clock.now();
        let cutoff = started
            .checked_add(channel.policy.request_timeout)
            .ok_or(FederationError::Configuration)?;
        let response = channel
            .call(
                stage,
                rss_request_context::Deadline::at(cutoff),
                request.body(Vec::new()).map_err(|_| invalid(stage))?,
            )
            .await?;
        self.check()?;
        channel.check()?;
        let (parts, bytes) = response.into_parts();
        let cap = match &kind {
            Kind::Discovery { .. } => resources.policy.discovery_ttl,
            Kind::Keys { .. } => resources.policy.jwks_ttl,
        };
        // Decode and prepare public keys outside the publication lock. Recheck retirement under it.
        let decoded = if parts.status != http::StatusCode::NOT_MODIFIED {
            if parts.status != http::StatusCode::OK || !valid_media(&parts.headers, stage) {
                return Err(invalid(stage));
            }
            #[cfg(any(test, feature = "test-support"))]
            resources.decodes.fetch_add(1, Ordering::Relaxed);
            Some(kind.validate(&bytes, channel)?)
        } else {
            None
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.check()?;
        channel.check()?;
        let mut freshness = crate::freshness::Freshness::default();
        let value = if parts.status == http::StatusCode::NOT_MODIFIED {
            let (old, prior) = previous.as_ref().ok_or_else(|| invalid(stage))?;
            freshness = *prior;
            if old.etag.is_none() && old.modified.is_none() {
                return Err(invalid(stage));
            }
            if parts
                .headers
                .get(header::ETAG)
                .is_some_and(|tag| Some(tag) != old.etag.as_ref())
            {
                // No stored representation matches this validator. Discard the obsolete
                // conditions and let each waiter charge a bounded unconditional GET.
                if let Some(old) = state.cached.take() {
                    retire_changed_keys(&old.value, None);
                }
                return Ok(None);
            }
            old.clone()
        } else {
            let document = decoded.ok_or_else(|| invalid(stage))?;
            drop(previous);
            Representation::admit(&mut state, resources, document, &parts.headers, stage)?
        };
        let freshness = freshness.update(&parts.headers);
        let ttl = freshness.remaining(
            &parts.headers,
            cap,
            channel.clock.now().saturating_duration_since(started),
            (channel.clock.wall)(),
        );
        if let Some(old) = &state.cached {
            retire_changed_keys(&old.value, value.keys.as_ref().map(|(_, doc)| doc));
        }
        state.cached = if freshness.storable() {
            Some(Cached {
                value: value.clone(),
                freshness,
                until: resources
                    .now()
                    .checked_add(ttl)
                    .ok_or(FederationError::Configuration)?,
            })
        } else {
            None
        };
        Ok(Some(Arc::new(Fetched {
            value,
            consumed: (!freshness.storable()).then(|| AtomicBool::new(false)),
        })))
    }
}
fn retire_changed_keys(old: &Representation, next: Option<&Arc<Document>>) -> bool {
    if let Some((_, old_keys)) = &old.keys
        && next.is_none_or(|new_keys| !Arc::ptr_eq(old_keys, new_keys))
    {
        old_keys.retired.store(true, Ordering::Release);
        old_keys
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cached
            .take();
        return true;
    }
    false
}
fn valid_media(headers: &HeaderMap, stage: ProviderStage) -> bool {
    headers.get(header::CONTENT_TYPE).is_none_or(|value| {
        value.to_str().is_ok_and(|s| {
            let media = s.split(';').next().unwrap_or("").trim();
            media.eq_ignore_ascii_case("application/json")
                || stage == ProviderStage::Jwks
                    && media.eq_ignore_ascii_case("application/jwk-set+json")
        })
    })
}

#[cfg(test)]
mod budget_tests;
