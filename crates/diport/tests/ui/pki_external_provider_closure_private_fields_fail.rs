use diport::{ExternalPkiProviderClosure, PkiProviderConfigDigest};

fn main() {
    let _ = ExternalPkiProviderClosure {
        config_digest: PkiProviderConfigDigest::new([7; 32]),
        _sealed: (),
    };
}
