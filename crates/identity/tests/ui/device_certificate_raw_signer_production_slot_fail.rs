use identity::ports::device_certificate::ProductionCertificateArtifactSource;

fn production_slot<S: ProductionCertificateArtifactSource>(_source: S) {}

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
    production_slot(RawSigner);
}
