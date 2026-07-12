use postgres::PgReadinessSamplerFactory;

fn requires_clone<T: Clone>(_: &T) {}

fn factory_is_single_use(factory: PgReadinessSamplerFactory) {
    requires_clone(&factory);
}

fn main() {}
