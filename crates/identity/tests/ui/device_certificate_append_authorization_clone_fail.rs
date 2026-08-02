use identity::ports::device_certificate::{ArtifactAppendAuthorization, ProductionEligibility};

fn duplicate(value: ArtifactAppendAuthorization<ProductionEligibility>) {
    let _ = value.clone();
}

fn main() {}
