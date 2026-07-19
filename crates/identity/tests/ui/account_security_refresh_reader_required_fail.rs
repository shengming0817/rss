use std::{sync::Arc, time::Duration};

fn construct_with_optional_security_reader<S>(
    store: Box<identity::ports::DynRefreshTokenStore<'static>>,
    issuer: Arc<authn::JwtIssuer<diport::RssAccessProfile, S>>,
    clock: Box<dyn diport::Clock>,
)
where
    S: diport::Signer + Send + Sync + 'static,
{
    let _service = identity::RefreshService::<S>::new(
        store,
        None,
        issuer,
        clock,
        Duration::from_secs(3_600),
    );
}

fn main() {}
