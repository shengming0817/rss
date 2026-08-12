use authn::JwtIssuer;
use diport::ServiceTokenProfile;

fn arbitrary_service_subject_cannot_be_minted<S>(
    issuer: &JwtIssuer<ServiceTokenProfile, S>,
    tenant: rss_request_context::TenantId,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = issuer.issue_service_token("arbitrary-service", tenant);
}

fn main() {}
