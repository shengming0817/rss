pub struct SharedRuntimeDeps {
    pub pg: postgres::PgRuntimeHandle,
    pub locker: distributed::Locker,
}
