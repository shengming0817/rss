use platform_application_waist_contract::{RequestContext, VerifiedPrincipal, VerifiedTenant};

fn forge<'a>(
    principal: VerifiedPrincipal<'a>,
    tenant: VerifiedTenant<'a>,
) -> RequestContext<'a> {
    RequestContext {
        principal,
        tenant,
        request_id: "forged-request",
        correlation_id: None,
    }
}

fn main() {
    let _ = forge;
}
