//! Test host for the storage measurement. A binding identifies one provisioned fixture account.
use futures::future::BoxFuture;
use rss_identity_core::{InstanceId, PrincipalId, account::AccountKey};
use rss_identity_postgres::platform::*;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;

pub(super) struct FixturePlatform;
impl PlatformVerifier for FixturePlatform {
    fn audience(&self) -> &str {
        "identity-measure"
    }
    fn resolve<'a>(
        &'a self,
        instance: InstanceId,
        tenant: TenantId,
        id: Uuid,
        _: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<PlatformBinding, PlatformError>> {
        Box::pin(async move {
            let principal =
                PrincipalId::parse(&id.to_string()).map_err(|_| PlatformError::Rejected)?;
            Ok(PlatformBinding {
                instance,
                account: AccountKey { tenant, principal },
                binding_id: id,
                binding_epoch: 1,
                source_id: id,
                source_version: 1,
                external_identity: None,
            })
        })
    }
    fn authorize_purpose<'a>(
        &'a self,
        _: &'a PlatformBinding,
        purpose: &'a PlatformPurpose,
        _: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            if *purpose == PlatformPurpose::BrowserLogin {
                Ok(())
            } else {
                Err(PlatformError::Rejected)
            }
        })
    }
    fn recheck<'a>(
        &'a self,
        binding: &'a PlatformBinding,
        _: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            if binding.binding_id == binding.account.principal.as_uuid() {
                Ok(())
            } else {
                Err(PlatformError::Rejected)
            }
        })
    }
    fn verify<'a>(
        &'a self,
        challenge: &'a PlatformChallengeContext,
        evidence: &'a [u8],
    ) -> BoxFuture<'a, Result<PlatformEvidence, PlatformError>> {
        Box::pin(async move {
            let payload = challenge.signing_payload()?;
            let (mode, supplied) = evidence.split_first().ok_or(PlatformError::Rejected)?;
            if supplied != payload {
                return Err(PlatformError::Rejected);
            }
            Ok(PlatformEvidence {
                key_possession: true,
                hardware_key: false,
                user_presence: true,
                user_verification: true,
                authenticated_at: Some(challenge.created_at),
                profile: if *mode == 0 {
                    PlatformProfile::Unavailable
                } else {
                    PlatformProfile::IdentityLocal
                },
            })
        })
    }
}
