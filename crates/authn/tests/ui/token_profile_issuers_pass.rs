use std::time::Duration;

use authn::{JwtAccessPrincipal, JwtIssuer, JwtIssuerConfig};
use diport::{KeyId, RssAccessProfile, ServiceTokenProfile, SigningPurpose};

fn rss_can_only_sign_access<S>(
    issuer: &JwtIssuer<RssAccessProfile, S>,
    principal: JwtAccessPrincipal<'_>,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = issuer.issue_access(principal);
}

fn service_can_only_sign_service<S>(
    issuer: &JwtIssuer<ServiceTokenProfile, S>,
    caller: vocab::ServiceCallerDomain,
    binding: diport::ServiceTokenTenantBinding,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = issuer.issue_service_token(caller, binding);
}

fn main() {
    let _: JwtIssuerConfig<RssAccessProfile> = JwtIssuerConfig::rss_access(
        authn::SigningKeyRing::single(KeyId::new("rss-kid")).expect("non-empty signing key id"),
        SigningPurpose::new("auth.rss-access"),
        "https://rss.example",
        "rss-api",
        Duration::from_secs(900),
    );
    let _: JwtIssuerConfig<ServiceTokenProfile> = JwtIssuerConfig::service_token(
        authn::SigningKeyRing::single(KeyId::new("service-kid")).expect("non-empty signing key id"),
        SigningPurpose::new("auth.service-token"),
        "https://service.rss.example",
        "rss-internal",
        Duration::from_secs(300),
    );

    let _ = rss_can_only_sign_access::<NeverSigner>;
    let _ = service_can_only_sign_service::<NeverSigner>;
}

struct NeverSigner;

impl diport::Signer for NeverSigner {
    async fn sign(
        &self,
        _request: diport::SignRequest,
    ) -> Result<diport::Signature, diport::SignerError> {
        std::future::pending().await
    }

    async fn shutdown(&self) -> Result<(), diport::SignerError> {
        std::future::pending().await
    }
}
