use consistency::ExternalEffectIdempotencyKey;

fn assert_public_type<T>() {}

fn main() {
    assert_public_type::<ExternalEffectIdempotencyKey>();
}
