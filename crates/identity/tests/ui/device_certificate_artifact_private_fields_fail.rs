use identity::ports::device_certificate::{AuthorizedCertificateArtifact, ProductionEligibility};

fn forge() -> AuthorizedCertificateArtifact<ProductionEligibility> {
    AuthorizedCertificateArtifact {
        artifact: Vec::new(),
        eligibility: ProductionEligibility,
    }
}

fn main() {}
