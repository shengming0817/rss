use settings::SettingsService;

pub struct SharedRuntimeDeps {
    pub pg: postgres::PgRuntimeHandle,
    pub settings: SettingsService,
}
