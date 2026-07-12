pub struct SharedRuntimeDeps {
    pub pg: postgres::PgRuntimeHandle,
    pub settings: settings::SettingsService,
}
