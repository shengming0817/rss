use authn::{JwtAccessPrincipal, JwtIssuer};
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
    principal: JwtAccessPrincipal<'_>,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = issuer.issue_access(principal);
}

fn main() {}
