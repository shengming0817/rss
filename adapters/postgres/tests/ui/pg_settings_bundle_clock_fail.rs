use std::sync::Arc;

use diport::Clock;
use postgres::{ConfigValueCrypto, PgDomainDeps, caps};

fn settings_bundle_must_not_accept_clock(
    deps: PgDomainDeps<caps::Settings>,
    clock: Arc<dyn Clock>,
    crypto: ConfigValueCrypto,
) {
    let _ = deps.settings_bundle(clock, crypto);
}

fn main() {}
