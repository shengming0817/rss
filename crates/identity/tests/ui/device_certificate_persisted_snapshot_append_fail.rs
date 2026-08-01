use identity::ports::device_certificate::{
    CertificateAttemptFence, CertificateReconcileRepository, PersistedCertificateArtifactSnapshot,
};

fn append_restored<R: CertificateReconcileRepository>(
    repository: &R,
    fence: &CertificateAttemptFence,
    snapshot: PersistedCertificateArtifactSnapshot,
) {
    let _ = repository.append_artifact_receipt(fence, snapshot);
}

fn main() {}
