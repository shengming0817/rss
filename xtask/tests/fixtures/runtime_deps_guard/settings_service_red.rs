pub struct SharedRuntimeDeps {
    pub pg: postgres::PgRuntimeDeps,
    pub settings: settings::SettingsService,
}
