//! Different sessions using the same qualified platform binding share one verifier call.
use crate::{federation_support::secret, support::*};
use futures::future::BoxFuture;
use rss_identity_postgres::{Authority, platform::*};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use uuid::Uuid;

struct Verifier(AtomicUsize);
impl PlatformVerifier for Verifier {
    fn audience(&self) -> &str {
        "page-fixture"
    }
    fn authorize_purpose<'a>(
        &'a self,
        _: &'a PlatformBinding,
        _: &'a PlatformPurpose,
        _: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async { Err(PlatformError::Rejected) })
    }
    fn resolve<'a>(
        &'a self,
        _: rss_identity_core::InstanceId,
        _: TenantId,
        _: Uuid,
        _: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<PlatformBinding, PlatformError>> {
        Box::pin(async { Err(PlatformError::Rejected) })
    }
    fn verify<'a>(
        &'a self,
        _: &'a PlatformChallengeContext,
        _: &'a [u8],
    ) -> BoxFuture<'a, Result<PlatformEvidence, PlatformError>> {
        Box::pin(async { Err(PlatformError::Rejected) })
    }
    fn recheck<'a>(
        &'a self,
        _: &'a PlatformBinding,
        _: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}
pub async fn run(f: &Fixture) -> anyhow::Result<()> {
    let verifier = Arc::new(Verifier(AtomicUsize::new(0)));
    let scope = binding(f.key.tenant);
    let authority = Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(rss_identity_core::account::PasswordKdf::new(
            std::num::NonZeroUsize::MIN,
            std::num::NonZeroU64::new(128 * 1024 * 1024)
                .ok_or_else(|| anyhow::anyhow!("fixture memory"))?,
        )?),
        f.config().with_platform(verifier.clone()),
        scope,
        f.policy.clone(),
        deadline(),
    )
    .await?;
    let first = f.login().await?;
    let second = f.login().await?;
    let binding = PlatformBinding {
        instance: f.instance,
        account: f.key,
        binding_id: Uuid::new_v4(),
        binding_epoch: 1,
        source_id: Uuid::new_v4(),
        source_version: 1,
        external_identity: None,
    };
    let auth = serde_json::json!({"binding":binding,"audience":verifier.audience(),"authenticatedAt":null,"hardwareKey":true,"userPresence":true,"userVerification":true});
    sqlx::query("UPDATE identity_authority.sessions SET authentication_source='platform',local_authenticated_at=NULL,platform_authentication=$2 WHERE session_id=ANY($1)")
        .bind(vec![first.view().id.as_uuid(),second.view().id.as_uuid()]).bind(auth).execute(&f.owner).await?;
    let proof = authority
        .inspect_session(scope, secret(&first), deadline())
        .await?;
    verifier.0.store(0, Ordering::SeqCst);
    let page = authority
        .list_sessions(proof, None, 100, deadline())
        .await?;
    assert!(page.sessions.iter().any(|v| v.id == first.view().id));
    assert!(page.sessions.iter().any(|v| v.id == second.view().id));
    assert_eq!(verifier.0.load(Ordering::SeqCst), 1);
    Ok(())
}
