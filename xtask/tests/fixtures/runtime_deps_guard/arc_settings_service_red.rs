use std::sync::Arc;

pub struct SharedRuntimeDeps {
    pub pg: postgres::PgRuntimeDeps,
    pub settings: Arc<settings::SettingsService>,
}
