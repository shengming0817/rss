//! pass：dynosaur Send DI port 可 native AFIT impl + 经 `Box<DynSigner>` / `Arc<DynSigner>` 注入。
use diport::{DynSigner, Signer, SignerError};
use std::sync::Arc;

struct OkSigner;

impl Signer for OkSigner {
    async fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(Vec::new())
    }
    async fn shutdown(&self) -> Result<(), SignerError> {
        Ok(())
    }
}

fn main() {
    let _boxed: Box<DynSigner> = DynSigner::new_box(OkSigner);
    let _arced: Arc<DynSigner> = DynSigner::new_arc(OkSigner);
}
