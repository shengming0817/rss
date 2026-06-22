//! pass：dynosaur Send DI port 可 native AFIT impl + 经 `Box<DynSigner>` / `Arc<DynSigner>` 注入。
use diport::{DynSigner, KeyId, SignRequest, Signature, Signer, SignerError, SigningPurpose};
use std::sync::Arc;

struct OkSigner;

impl Signer for OkSigner {
    async fn sign(&self, _request: SignRequest) -> Result<Signature, SignerError> {
        Ok(Signature::new(Vec::new()))
    }
    async fn shutdown(&self) -> Result<(), SignerError> {
        Ok(())
    }
}

fn main() {
    let _boxed: Box<DynSigner> = DynSigner::new_box(OkSigner);
    let _arced: Arc<DynSigner> = DynSigner::new_arc(OkSigner);
    let _req = SignRequest {
        key: KeyId::new("k"),
        purpose: SigningPurpose::new("p"),
        message: Vec::new(),
    };
}
