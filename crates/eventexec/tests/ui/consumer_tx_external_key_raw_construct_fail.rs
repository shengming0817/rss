use consistency::ExternalEffectIdempotencyKey;

fn main() {
    let _ = ExternalEffectIdempotencyKey(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    );
    let _ = ExternalEffectIdempotencyKey::derive(&());
}
