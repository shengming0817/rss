use postgres::{PgConfig, PgRuntimeDeps};

fn plain_config_cannot_fill_tenant_reader_slot(
    migrator_config: &PgConfig,
    serving_config: &PgConfig,
    projection_generation: &'static str,
    projection_inputs: &'static [vocab::ProjectionInputBinding],
) {
    let _setup = PgRuntimeDeps::setup(
        migrator_config,
        serving_config,
        serving_config,
        projection_generation,
        projection_inputs,
    );
}

fn main() {}
