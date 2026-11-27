use crate::support::*;
use rss_identity_core::federation::*;
use rss_identity_postgres::StateSigner;
use rss_identity_postgres::*;
use rss_request_context::TenantId;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
pub const BROWSER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
pub const RETURN: &str = "https://identity.example.test/done";
pub struct ScriptedOidc {
    revisions: ProviderRevisions,
    pub assurance: Mutex<Option<rss_identity_core::assurance::Assurance>>,
    pub calls: AtomicUsize,
    pub checks: AtomicUsize,
    pub probe_error: Mutex<Option<FederationError>>,
    trusted: bool,
}
impl ScriptedOidc {
    pub fn new(trusted: bool) -> Arc<Self> {
        Arc::new(Self {
            revisions: ProviderRevisions::new(16),
            assurance: Mutex::new(None),
            calls: AtomicUsize::new(0),
            checks: AtomicUsize::new(0),
            probe_error: Mutex::new(None),
            trusted,
        })
    }
}
impl UpstreamOidc for ScriptedOidc {
    fn assurance_profile(&self, _tenant: TenantId, _c: &ProviderSettings) -> AssuranceProfile {
        self.checks.fetch_add(1, Ordering::SeqCst);
        AssuranceProfile {
            fingerprint: [u8::from(self.trusted); 32],
            supports_step_up: self.trusted,
        }
    }
    fn validate(
        &self,
        _tenant: TenantId,
        _c: &ProviderSettings,
        _: &ProviderCredentials,
    ) -> Result<(), FederationError> {
        Ok(())
    }
    fn revisions(&self) -> &ProviderRevisions {
        &self.revisions
    }
    fn prepare<'a>(
        &'a self,
        _: BoundProvider,
        m: &'a ProtocolMaterial,
        _: rss_identity_core::assurance::AuthenticationMode,
        _deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, String> {
        Box::pin(async move {
            Ok(format!(
                "https://idp.example.test/authorize?state={}",
                m.state.as_str()
            ))
        })
    }
    #[allow(
        clippy::disallowed_methods,
        clippy::unwrap_used,
        reason = "test fixture"
    )]
    fn exchange<'a>(
        &'a self,
        provider: BoundProvider,
        _: ProtocolMaterial,
        code: Zeroizing<String>,
        _deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, UpstreamClaims> {
        Box::pin(async move {
            let c = provider.settings();
            self.calls.fetch_add(1, Ordering::SeqCst);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            Ok(UpstreamClaims {
                department_snapshot:
                    rss_identity_core::department::UpstreamDepartmentSnapshot::NotConfigured,
                issuer: c.issuer().as_str().into(),
                subject: rss_identity_core::entra::ExternalSubject::Oidc(code.to_string()),
                profile: rss_identity_core::profile::Profile::missing(),
                groups: rss_identity_core::groups::UpstreamGroups::present(vec!["staff".into()])?,
                issued_at: now,
                expires_at: now + 600,
                assurance: self.assurance.lock().unwrap().clone().unwrap_or(
                    rss_identity_core::assurance::Assurance::new(
                        Some(now),
                        rss_identity_core::assurance::Acr::Unspecified,
                        vec![],
                    )?,
                ),
            })
        })
    }
    #[allow(clippy::unwrap_used, reason = "test fixture")]
    fn test<'a>(
        &'a self,
        _: BoundProvider,
        _deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, ConnectionReport> {
        Box::pin(async move {
            if let Some(error) = *self.probe_error.lock().unwrap() {
                return Err(error);
            }
            Ok(ConnectionReport {
                checks: vec![
                    ProviderStage::Binding,
                    ProviderStage::Discovery,
                    ProviderStage::Jwks,
                ],
                tls_verified: true,
                authorization_response_issuer: true,
            })
        })
    }
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn service(f: &Fixture) -> Federation {
    service_at(f, settings().redirect_uri())
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn service_at(f: &Fixture, callback: &str) -> Federation {
    service_on(f.store.clone(), callback)
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn service_on(authority: Authority, callback: &str) -> Federation {
    Federation::new(
        rss_identity_core::groups::GroupFactsMaxAge::new(300).unwrap(),
        authority,
        StateSigner::new([7; 32], "https://identity.example.test").unwrap(),
        FederationConfig {
            callback: callback.into(),
            credential_keys: credential_keys(),
            targets: BTreeMap::from([("home".into(), RETURN.into())]),
        },
    )
    .unwrap()
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn settings() -> ProviderSettings {
    (rss_identity_core::federation::ProviderSettingsInput {
        issuer: "https://idp.example.test".into(),
        client_id: "identity".into(),

        redirect_uri: "https://identity.example.test/api/v1/identity/oidc/callback".into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            subject: rss_identity_core::entra::SubjectMapping::Oidc,
            department_snapshot: None,
            profile: rss_identity_core::profile::ProfileSettings::default(),
            groups: Some("groups".into()),
        },
        jit: true,
    })
    .try_into()
    .unwrap()
}
pub async fn actor(f: &Fixture) -> anyhow::Result<AuthenticatedSession> {
    f.reset_attempts().await?;
    f.actor().await
}
pub async fn enabled(f: &Fixture, s: &Federation) -> anyhow::Result<ProviderView> {
    enabled_settings(f, s, settings()).await
}
#[allow(clippy::unwrap_used, reason = "test fixture and ordered assertions")]
async fn enabled_settings(
    f: &Fixture,
    s: &Federation,
    settings: ProviderSettings,
) -> anyhow::Result<ProviderView> {
    let p = s
        .create_provider(
            actor(f).await?,
            settings,
            rss_identity_core::federation::ProviderCredentials::new("fixture-secret".into(), None)
                .unwrap(),
            deadline(),
        )
        .await?;
    Ok(
        s.enable_provider(actor(f).await?, p.id, p.version, true, deadline())
            .await?,
    )
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
pub fn state(redirect: FederatedRedirect) -> String {
    url::Url::parse(&redirect.url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned()
}
pub async fn begin(f: &Fixture, s: &Federation, p: &ProviderView) -> anyhow::Result<String> {
    f.reset_attempts().await?;
    Ok(state(
        s.begin_login(
            rss_identity_postgres::LoginRequest {
                binding: crate::support::binding(f.key.tenant),
                provider: p.id,
                browser: BROWSER.into(),
                target: "home".into(),
                replacement: None,
                source: source(),
            },
            deadline(),
        )
        .await?,
    ))
}
pub async fn finish(
    s: &Federation,
    state: String,
    subject: &str,
) -> Result<FederatedOutcome, AuthorityError> {
    s.complete(
        state,
        BROWSER.into(),
        Zeroizing::new(subject.into()),
        "https://idp.example.test".into(),
        None,
        deadline(),
    )
    .await
}
#[allow(clippy::panic, reason = "test fixture")]
pub fn issued(outcome: FederatedOutcome) -> IssuedSession {
    match outcome {
        FederatedOutcome::Session {
            issued, return_url, ..
        } => {
            assert_eq!(return_url, RETURN);
            issued
        }
        _ => panic!("unexpected reauthentication step"),
    }
}
#[allow(clippy::unwrap_used, reason = "test fixture and ordered assertions")]
pub fn secret(s: &IssuedSession) -> rss_identity_core::session::SessionSecret {
    rss_identity_core::session::SessionSecret::parse(s.secret().expose().into()).unwrap()
}
