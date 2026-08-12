use postgres::PgRuntimeMonitorFactory;
use tokio_util::sync::CancellationToken;

fn factory_spawns_once(factory: PgRuntimeMonitorFactory, token: CancellationToken) {
    let _first = factory.spawn(token.clone());
    let _second = factory.spawn(token);
}

fn main() {}
