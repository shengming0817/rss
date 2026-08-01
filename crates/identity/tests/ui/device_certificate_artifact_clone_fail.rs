use identity::ports::device_certificate::{AuthorizedCertificateArtifact, ProductionEligibility};

fn duplicate(value: AuthorizedCertificateArtifact<ProductionEligibility>) {
    let _ = value.clone();
}

fn main() {}
