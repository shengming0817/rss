use postgres::PgReadinessSamplerFactory;
use tokio_util::sync::CancellationToken;

fn factory_spawns_once(factory: PgReadinessSamplerFactory, token: CancellationToken) {
    let _first = factory.spawn(token.clone());
    let _second = factory.spawn(token);
}

fn main() {}
