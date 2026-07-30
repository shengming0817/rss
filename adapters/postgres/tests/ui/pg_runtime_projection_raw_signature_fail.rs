use postgres::{PgConfig, PgRuntimeDeps, PgTenantReadConfig};
use vocab::ProjectionInputBinding;

async fn old_raw_projection_setup(
    serving: &PgConfig,
    reader: &PgTenantReadConfig,
    inputs: &[ProjectionInputBinding],
) {
    let _ = PgRuntimeDeps::connect_serving(
        serving,
        reader,
        None,
        "sha256:legacy-generation",
        inputs,
    )
    .await;
}

fn main() {}
