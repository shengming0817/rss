//! pass：representative dynosaur DI ports remain dyn-compatible via `new_box` / `new_arc`.
//! Full Arc Send/Sync coverage is Hard-gated by `classify_ports!` + `assert_send_sync_bound`
//! (DIPORT-DYN-CONCURRENCY-01 native-compile); `ui_assert_*` trybuild is Medium anti-vacuity —
//! not a 24-stub matrix here.
//!
//! Thin matrix: one `async_send` (Signer) + one `async_sync` shared port (SecretResolver).
use diport::{
    DynSecretResolver, DynSigner, KeyId, SecretCoordinate, SecretMaterial, SecretResolver,
    SecretResolverError, SignRequest, Signature, Signer, SignerError, SigningPurpose,
};
use std::sync::Arc;
use rss_request_context::TenantId;

fn assert_send_sync<T: Send + Sync>() {}

struct OkSigner;

impl Signer for OkSigner {
    async fn sign(&self, _request: SignRequest) -> Result<Signature, SignerError> {
        Ok(Signature::new(Vec::new()))
    }
    async fn shutdown(&self) -> Result<(), SignerError> {
        Ok(())
    }
}

struct OkSecretResolver;

impl SecretResolver for OkSecretResolver {
    async fn resolve(
        &self,
        _tenant: TenantId,
        _coord: &SecretCoordinate,
    ) -> Result<SecretMaterial, SecretResolverError> {
        Ok(SecretMaterial::new(Vec::new()))
    }
}

fn main() {
    let _boxed: Box<DynSigner> = DynSigner::new_box(OkSigner);
    let _arced: Arc<DynSigner> = DynSigner::new_arc(OkSigner);
    let _req = SignRequest {
        key: KeyId::new("k"),
        purpose: SigningPurpose::new("p"),
        message: Vec::new().into(),
    };

    let _sr_boxed: Box<DynSecretResolver> = DynSecretResolver::new_box(OkSecretResolver);
    let _sr_arced: Arc<DynSecretResolver> = DynSecretResolver::new_arc(OkSecretResolver);
    assert_send_sync::<Arc<DynSecretResolver<'static>>>();

}
