use identity::ports::device_certificate::{
    CertificateAttemptFence, CertificateReconcileRepository, PersistedCertificateArtifactSnapshot,
    ProductionEligibility,
};

fn append_restored<R: CertificateReconcileRepository<ProductionEligibility>>(
    repository: &R,
    fence: &CertificateAttemptFence,
    snapshot: PersistedCertificateArtifactSnapshot<ProductionEligibility>,
) {
    let _ = repository.append_artifact_receipt(fence, snapshot);
}

fn main() {}
