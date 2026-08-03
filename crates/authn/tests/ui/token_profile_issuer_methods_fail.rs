use authn::{JwtIssuer, RssAccessIssueInput};
use diport::{RssAccessProfile, ServiceTokenProfile};

fn rss_cannot_sign_service<S>(
    issuer: &JwtIssuer<RssAccessProfile, S>,
    tenant: vocab::TenantId,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = issuer.issue_service_token("service", tenant);
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
