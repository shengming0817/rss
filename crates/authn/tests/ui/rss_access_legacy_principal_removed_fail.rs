enum JwtAccessPrincipal<'a> {
    User {
        subject: &'a str,
        tenant: vocab::TenantId,
    },
}

fn old_issue_call<S>(
    issuer: &authn::JwtIssuer<diport::RssAccessProfile, S>,
    principal: JwtAccessPrincipal<'_>,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = issuer.issue_access(principal);
}

fn main() {}
