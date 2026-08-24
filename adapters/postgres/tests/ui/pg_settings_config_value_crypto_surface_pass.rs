use diport::{DynKeyProvider, KeyName};
use postgres::{ConfigValueCrypto, PgDomainDeps, caps};

fn settings_bundle_accepts_one_crypto_capability(
    deps: PgDomainDeps<caps::Settings>,
    crypto: ConfigValueCrypto,
) {
    let _ = deps.settings_bundle(crypto);
}

fn constructor_accepts_one_provider(
    provider: Box<DynKeyProvider<'static>>,
    key_name: KeyName,
) -> ConfigValueCrypto {
    ConfigValueCrypto::new(provider, key_name)
}

fn main() {}
