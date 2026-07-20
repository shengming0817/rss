use identity::RefreshService;

fn value<T>() -> T {
    panic!("compile-fail fixture")
}

async fn issue_from_bare_ids<S>(
    service: &RefreshService<S>,
) where
    S: diport::Signer + Send + Sync + 'static,
{
    let grant = value();
    let _ = service.prepare_initial(&grant).await;
}

fn main() {}
