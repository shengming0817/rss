use std::sync::Arc;

pub struct SharedRuntimeDeps {
    pub pg: postgres::PgRuntimeHandle,
    pub settings: Arc<settings::SettingsService>,
}
