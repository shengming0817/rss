async fn bypass_durable_audit(
    principal: &authn::Principal,
    ctx: &runctx::AppCtx,
    clock: &dyn diport::Clock,
    audit: &authn::CrossTenantAuditContext,
) {
    let _forged = principal
        .audited_cross_tenant_visibility(ctx, clock, audit, |_| async { Ok(()) })
        .await;
}

fn main() {}
