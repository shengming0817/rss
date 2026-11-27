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
use rss_identity_core::federation::{FederationError, ProviderReason, ProviderStage};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use url::Url;

#[derive(Default, Deserialize, Serialize)]
pub(super) struct Jwks {
    pub keys: Vec<serde_json::Value>,
}
#[derive(Deserialize)]
pub(super) struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Option<TokenEndpoint>,
    pub jwks_uri: Url,
    #[serde(rename = "response_types_supported")]
    _response_types_supported: Vec<String>,
    #[serde(rename = "subject_types_supported")]
    _subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
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
    ) -> Result<Vec<u8>, FederationError> {
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
        self.validate(response.body(), &t.channel)?;
        Ok(response.into_body())
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
    fn validate(&self, bytes: &[u8], channel: &Channel) -> Result<Option<Url>, FederationError> {
        match self {
            Self::Discovery { issuer } => {
                let metadata: Metadata = decode(bytes, self.stage())?;
                if metadata.issuer != *issuer {
                    return Err(failure(self.stage(), ProviderReason::IssuerMismatch));
                }
                let token = metadata
                    .token_endpoint
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
                Ok(Some(metadata.jwks_uri))
            }
            Self::Keys { .. } => {
                let keys: Jwks = decode(bytes, self.stage())?;
                if keys.keys.len() > channel.policy.max_jwks_keys {
                    return Err(invalid(self.stage()));
                }
                Ok(None)
            }
        }
    }
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
pub(super) struct Representation {
    bytes: Box<[u8]>,
    etag: Option<HeaderValue>,
    modified: Option<HeaderValue>,
    keys: Option<(Url, Arc<Document>)>,
    lease: ByteLease,
    pub identity: Arc<()>,
}
impl Representation {
    pub fn metadata(&self) -> Result<Metadata, FederationError> {
        decode(&self.bytes, ProviderStage::Discovery)
    }
    pub fn jwks(&self) -> Result<Jwks, FederationError> {
        decode(&self.bytes, ProviderStage::Jwks)
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
        super::left(t.deadline, stage)?;
        let flight = {
            let mut state = self.state.lock().unwrap();
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
                    owner.state.lock().unwrap().flight = None;
                    result
                }
                .boxed()
                .shared();
                state.flight = work.downgrade();
                work
            }
        };
        let result = tokio::time::timeout_at(t.deadline.instant().into(), flight)
            .await
            .map_err(|_| failure(stage, ProviderReason::Timeout))??;
        self.check()?;
        t.channel.check()?;
        super::left(t.deadline, stage)?;
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
            let own = tokio::time::timeout_at(
                t.deadline.instant().into(),
                private.fetch(resources, &t.channel, kind),
            )
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
            .unwrap()
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
        let started = Instant::now();
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
        let mut state = self.state.lock().unwrap();
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
            if parts.status != http::StatusCode::OK || !valid_media(&parts.headers, stage) {
                return Err(invalid(stage));
            }
            let keys_uri = kind.validate(&bytes, channel)?;
            let etag = parts.headers.get(header::ETAG).cloned();
            let modified = parts.headers.get(header::LAST_MODIFIED).cloned();
            let keys = keys_uri.map(|uri| {
                let doc = previous
                    .as_ref()
                    .and_then(|(r, _)| r.keys.as_ref())
                    .filter(|(old, _)| old == &uri)
                    .map(|(_, d)| d.clone())
                    .unwrap_or_default();
                (uri, doc)
            });
            // Account exact stored bytes. Parsed DTOs live only in their caller.
            let overhead = etag.as_ref().map_or(0, |v| v.as_bytes().len())
                + modified.as_ref().map_or(0, |v| v.as_bytes().len())
                + keys.as_ref().map_or(0, |(u, _)| u.as_str().len());
            // Parent and child leave the cache together even if admission of the new
            // representation fails. A later request then starts without obsolete validators.
            if let Some((old, _)) = &previous
                && retire_changed_keys(old, keys.as_ref())
            {
                state.cached = None;
            }
            drop(previous);
            let replaced = state
                .cached
                .as_mut()
                .and_then(|old| Arc::get_mut(&mut old.value))
                .map(|old| &mut old.lease);
            let lease = resources
                .reserve(
                    bytes
                        .len()
                        .checked_add(overhead)
                        .ok_or(FederationError::Unavailable)?,
                    replaced,
                )
                .map_err(|_| failure(stage, ProviderReason::Unavailable))?;
            Arc::new(Representation {
                bytes: bytes.into_boxed_slice(),
                etag,
                modified,
                keys,
                lease,
                identity: Arc::new(()),
            })
        };
        let freshness = freshness.update(&parts.headers);
        let ttl = freshness.remaining(
            &parts.headers,
            cap,
            started.elapsed(),
            std::time::SystemTime::now(),
        );
        if let Some(old) = &state.cached {
            retire_changed_keys(&old.value, value.keys.as_ref());
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
fn retire_changed_keys(old: &Representation, next: Option<&(Url, Arc<Document>)>) -> bool {
    if let Some((_, old_keys)) = &old.keys
        && next.is_none_or(|(_, new_keys)| !Arc::ptr_eq(old_keys, new_keys))
    {
        old_keys.retired.store(true, Ordering::Release);
        old_keys.state.lock().unwrap().cached.take();
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
