use identity::ports::device_certificate::{
    AuthorizedCertificateArtifact, DraftEligibility, ProductionCertificateArtifactSource,
};

fn production_slot<S: ProductionCertificateArtifactSource>(_source: S) {}

struct DraftSimulator;

impl DraftSimulator {
    fn artifact(&self) -> Option<AuthorizedCertificateArtifact<DraftEligibility>> {
        None
    }
}

fn main() {
    production_slot(DraftSimulator);
}
