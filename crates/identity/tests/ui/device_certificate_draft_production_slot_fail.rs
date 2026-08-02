use identity::ports::device_certificate::{
    AuthorizedCertificateArtifact, CertificateArtifactAcquisition, CertificateArtifactError,
    CertificateArtifactSource, DraftEligibility, ProductionEligibility,
};

fn production_slot<S: CertificateArtifactSource<Eligibility = ProductionEligibility>>(_source: S) {}

struct DraftSimulator;

impl CertificateArtifactSource for DraftSimulator {
    type Eligibility = DraftEligibility;

    async fn acquire(
        &self,
        _request: CertificateArtifactAcquisition,
    ) -> Result<AuthorizedCertificateArtifact<Self::Eligibility>, CertificateArtifactError> {
        unreachable!()
    }
}

fn main() {
    production_slot(DraftSimulator);
}
