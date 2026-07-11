//! Synthetic red: settingsonly-shaped SharedRuntimeDeps must reject domain services.
use diport::KeyName;
use postgres::PgRuntimeDeps;
use vault::VaultRuntimeDeps;

pub struct SharedRuntimeDeps {
    pg: PgRuntimeDeps,
    vault: VaultRuntimeDeps,
    config_value_key_name: KeyName,
    settings: settings::SettingsService,
}
