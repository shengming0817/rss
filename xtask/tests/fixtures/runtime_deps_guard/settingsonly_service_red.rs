//! Synthetic red: settingsonly-shaped SharedRuntimeDeps must reject domain services.
use diport::KeyName;
use postgres::PgRuntimeHandle;
use vault::VaultRuntimeDeps;

pub struct SharedRuntimeDeps {
    pg: PgRuntimeHandle,
    vault: VaultRuntimeDeps,
    config_value_key_name: KeyName,
    settings: settings::SettingsService,
}
