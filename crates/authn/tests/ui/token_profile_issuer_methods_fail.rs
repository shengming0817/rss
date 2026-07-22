use authn::{JwtIssuer, RssAccessIssueInput};
use diport::{RssAccessProfile, ServiceTokenProfile};

fn rss_cannot_sign_service<S>(
    issuer: &JwtIssuer<RssAccessProfile, S>,
    binding: diport::ServiceTokenTenantBinding,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = issuer.issue_service_token("service", binding);
}

fn service_cannot_sign_access<S>(
    issuer: &JwtIssuer<ServiceTokenProfile, S>,
    input: RssAccessIssueInput<'_>,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = issuer.issue_access(input);
}

fn main() {}
