use diport::ExternalPkiProviderClosure;
use identity::ports::device_certificate::{CertificateArtifactSource, ProductionEligibility};

fn requires_production_artifact_source<T: CertificateArtifactSource<Eligibility = ProductionEligibility>>() {}

fn main() {
    requires_production_artifact_source::<ExternalPkiProviderClosure>();
}
