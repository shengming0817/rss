use postgres::PgDeviceLatentOperatorDeps;

fn requires_clone<T: Clone>() {}

fn main() {
    requires_clone::<PgDeviceLatentOperatorDeps>();
}
