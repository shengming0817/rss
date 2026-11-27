#![allow(dead_code)]
use crate::support::*;
use rss_identity_core::federation::*;
use rss_identity_postgres::StateSigner;
use rss_identity_postgres::*;
use rss_request_context::TenantId;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
pub const BROWSER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
pub const RETURN: &str = "https://identity.example.test/done";
type Hook = Box<dyn FnOnce() -> UpstreamFuture<'static, ()> + Send>;
pub struct ScriptedOidc {
    revisions: ProviderRevisions,
    pub fail: AtomicBool,
    pub trusted_assurance: AtomicBool,
    pub step_up_disabled: AtomicBool,
    pub assurance: Mutex<Option<rss_identity_core::assurance::Assurance>>,
    pub calls: AtomicUsize,
    pub email_verified: AtomicBool,
    pub profile: Mutex<Option<rss_identity_core::profile::Profile>>,
    pub groups: Mutex<Vec<String>>,
    pub department_snapshot: Mutex<rss_identity_core::department::UpstreamDepartmentSnapshot>,
    pub issued_at_offset: AtomicI64,
    pub gate: Mutex<Option<Arc<tokio::sync::Barrier>>>,
    pub arrivals: AtomicUsize,
    pub hook: Mutex<Option<Hook>>,
}
impl ScriptedOidc {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            revisions: ProviderRevisions::new(1024),
            fail: AtomicBool::new(false),
            trusted_assurance: AtomicBool::new(true),
            step_up_disabled: AtomicBool::new(false),
            assurance: Mutex::new(None),
            calls: AtomicUsize::new(0),
            email_verified: AtomicBool::new(true),
            profile: Mutex::new(None),
            groups: Mutex::new(vec!["staff".into()]),
            department_snapshot: Mutex::new(
                rss_identity_core::department::UpstreamDepartmentSnapshot::Present(
                    department_snapshot(Some("dept-01")),
                ),
            ),
            issued_at_offset: AtomicI64::new(0),
            gate: Mutex::new(None),
            arrivals: AtomicUsize::new(0),
            hook: Mutex::new(None),
        })
    }
}
impl UpstreamOidc for ScriptedOidc {
    fn assurance_profile(&self, _tenant: TenantId, _c: &ProviderSettings) -> AssuranceProfile {
        let approved = self.trusted_assurance.load(Ordering::SeqCst);
        AssuranceProfile {
            fingerprint: [u8::from(approved); 32],
            supports_step_up: approved && !self.step_up_disabled.load(Ordering::SeqCst),
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
            let gate = self.gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                self.arrivals.fetch_add(1, Ordering::SeqCst);
                gate.wait().await;
            }
            let hook = self.hook.lock().unwrap().take();
            if let Some(hook) = hook {
                hook().await?;
            }
            if self.fail.load(Ordering::SeqCst) || code.is_empty() {
                return Err(FederationError::Unavailable);
            }
            Ok(UpstreamClaims {
                department_snapshot: if c.claims().department_snapshot.is_some() {
                    self.department_snapshot.lock().unwrap().clone()
                } else {
                    rss_identity_core::department::UpstreamDepartmentSnapshot::NotConfigured
                },
                issuer: c.issuer().as_str().to_owned(),
                subject: match c.claims().subject {
                    rss_identity_core::entra::SubjectMapping::Oidc => {
                        rss_identity_core::entra::ExternalSubject::Oidc(code.to_string())
                    }
                    rss_identity_core::entra::SubjectMapping::Entra { tenant } => {
                        rss_identity_core::entra::ExternalSubject::Entra {
                            tenant,
                            user: uuid::Uuid::parse_str(&code)
                                .map_err(|_| FederationError::Claims)?,
                        }
                    }
                },
                profile: self.profile.lock().unwrap().clone().unwrap_or_else(||rss_identity_core::profile::Profile::from_claims(
                    serde_json::json!({"email":"same@example.test","email_verified":self.email_verified.load(Ordering::SeqCst)}).as_object().unwrap(), &c.claims().profile)),

                groups: rss_identity_core::groups::UpstreamGroups::present(
                    self.groups.lock().unwrap().clone(),
                )?,
                issued_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    + self.issued_at_offset.load(Ordering::SeqCst),
                expires_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    + 600,
                assurance: self.assurance.lock().unwrap().clone().unwrap_or(
                    rss_identity_core::assurance::Assurance::new(
                        Some(
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64,
                        ),
                        rss_identity_core::assurance::Acr::Unspecified,
                        vec![],
                    )?,
                ),
            })
        })
    }
    fn test<'a>(
        &'a self,
        _: BoundProvider,
        _deadline: rss_request_context::Deadline,
    ) -> UpstreamFuture<'a, ConnectionReport> {
        Box::pin(async move {
            let hook = self.hook.lock().unwrap().take();
            if let Some(hook) = hook {
                hook().await?;
            }

            if self.fail.load(Ordering::SeqCst) {
                Err(FederationError::provider(
                    ProviderStage::Jwks,
                    ProviderReason::Unavailable,
                ))
            } else {
                Ok(ConnectionReport {
                    checks: vec![
                        ProviderStage::Binding,
                        ProviderStage::Discovery,
                        ProviderStage::Jwks,
                    ],
                    tls_verified: true,
                    authorization_response_issuer: true,
                })
            }
        })
    }
}
pub fn service(f: &Fixture, oidc: Arc<dyn UpstreamOidc>) -> Federation {
    Federation::new(
        rss_identity_core::groups::GroupFactsMaxAge::new(300).unwrap(),
        f.store.clone(),
        oidc,
        StateSigner::new([7; 32], "https://identity.example.test").unwrap(),
        FederationConfig {
            callback: "https://identity.example.test/api/v1/identity/oidc/callback".into(),
            credential_keys: credential_keys(),
            targets: BTreeMap::from([("home".into(), RETURN.into())]),
        },
    )
    .unwrap()
}
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
pub async fn enabled_department(
    f: &Fixture,
    s: &Federation,
    max_age: i64,
) -> anyhow::Result<ProviderView> {
    let mut input = settings().input();
    input.claims.department_snapshot =
        Some(rss_identity_core::department::DepartmentSnapshotClaim::new(
            "organization_snapshot".into(),
            max_age,
        )?);
    enabled_settings(f, s, input.try_into()?).await
}
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
pub async fn session(f: &Fixture) -> anyhow::Result<IssuedSession> {
    f.login().await
}
pub fn secret(s: &IssuedSession) -> rss_identity_core::session::SessionSecret {
    rss_identity_core::session::SessionSecret::parse(s.secret().expose().into()).unwrap()
}

/// Small complete organization assertion used by the trusted scripted adapter.
pub fn department_snapshot(
    member: Option<&str>,
) -> rss_identity_core::department::DepartmentSnapshot {
    use rss_identity_core::department::{DepartmentId, DepartmentNode, DepartmentSnapshot};
    let root = DepartmentId::new("root".into()).unwrap();
    let id = DepartmentId::new(member.unwrap_or("dept-01").into()).unwrap();
    DepartmentSnapshot::new(
        "fixture-r1".into(),
        vec![
            DepartmentNode::new(root.clone(), "Company".into(), None).unwrap(),
            DepartmentNode::new(id.clone(), "Department".into(), Some(root)).unwrap(),
        ],
        member.map(|_| id).into_iter().collect(),
    )
    .unwrap()
}
