use postgres::PgRuntimeMonitorFactory;

fn requires_clone<T: Clone>(_: &T) {}

fn factory_is_single_use(factory: PgRuntimeMonitorFactory) {
    requires_clone(&factory);
}

fn main() {}
