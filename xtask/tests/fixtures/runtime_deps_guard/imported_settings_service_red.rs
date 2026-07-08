use settings::SettingsService;

pub struct SharedRuntimeDeps {
    pub pg: postgres::PgRuntimeDeps,
    pub settings: SettingsService,
}
