use postgres::{ConfigValueProtection, ConfigValueProtections, PgDomainDeps, caps};

fn legacy_pair_must_not_wire_settings(
    deps: PgDomainDeps<caps::Settings>,
    protections: ConfigValueProtections,
) {
    let _ = deps.settings_bundle(protections);
}

fn legacy_single_must_not_exist(_protection: ConfigValueProtection) {}

fn main() {}
