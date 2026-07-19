use identity::RefreshService;

async fn issue_from_bare_ids<S>(
    service: &RefreshService<S>,
    tenant: vocab::TenantId,
    user_id: ids::UserId,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let _ = service.issue(tenant, user_id).await;
    let _ = service.issue_initial(tenant, user_id).await;
}

fn main() {}
