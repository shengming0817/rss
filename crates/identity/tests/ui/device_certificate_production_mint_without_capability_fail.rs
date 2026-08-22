use diport::ExternalPkiProviderClosure;
use identity::ports::device_certificate::{
    AuthorizedCertificateArtifact, CertificateArtifactError, CertificateArtifactRequest,
    ProductionEligibility, ProviderCertificateCandidate,
};

type LegacyMint = fn(
    ProviderCertificateCandidate,
    &ExternalPkiProviderClosure,
    &CertificateArtifactRequest,
) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError>;

fn main() {
    let _: LegacyMint = ProviderCertificateCandidate::authorize_production;
}
