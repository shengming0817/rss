pub struct SharedRuntimeDeps {
    pub pg: postgres::PgRuntimeDeps,
    pub locker: distributed::Locker,
}
