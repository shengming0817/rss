use postgres::{LegacyConfigPlaintextPolicy, PgConfig, PgRuntimeDeps};

fn legacy_policy_setup_without_reader(
    migrator_config: &PgConfig,
    serving_config: &PgConfig,
    projection_generation: &'static str,
    projection_inputs: &'static [vocab::ProjectionInputBinding],
) {
    let _setup = PgRuntimeDeps::setup_with_legacy_config_policy(
        migrator_config,
        serving_config,
        LegacyConfigPlaintextPolicy::Deny,
        projection_generation,
        projection_inputs,
    );
}

fn main() {}
