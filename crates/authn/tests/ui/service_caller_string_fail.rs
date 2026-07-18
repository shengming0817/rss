use authn::JwtIssuer;
use diport::ServiceTokenProfile;

fn arbitrary_service_subject_cannot_be_minted<S>(
    issuer: &JwtIssuer<ServiceTokenProfile, S>,
    binding: diport::ServiceTokenTenantBinding,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = issuer.issue_service_token("arbitrary-service", binding);
}

fn main() {}
