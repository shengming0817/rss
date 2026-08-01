fn main() {
    let _ = consistency::SagaIdempotencyKey {
        bytes: [7; 32],
        phase: consistency::SagaEffectPhase::Forward,
    };
}
