use postgres::{PgRuntimeHandle, caps};

fn legacy_apply_port(handle: &PgRuntimeHandle) {
    let (_reader, apply) = handle
        .for_domain::<caps::Settings>()
        .settings_projection_bundle()
        .into_parts();
    drop(apply);
}

fn main() {}
