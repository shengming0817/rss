use postgres::PgRuntimeDeps;

fn requires_clone<T: Clone>() {}

fn main() {
    requires_clone::<PgRuntimeDeps>();
}
