use identity::ports::device_certificate::CertificateArtifactSource;

fn artifact_slot<S: CertificateArtifactSource>(_source: S) {}

struct RawSigner;

impl diport::Signer for RawSigner {
    async fn sign(
        &self,
        _request: diport::SignRequest,
    ) -> Result<diport::Signature, diport::SignerError> {
        unreachable!()
    }

    async fn shutdown(&self) -> Result<(), diport::SignerError> {
        Ok(())
    }
}

fn main() {
    artifact_slot(RawSigner);
}
