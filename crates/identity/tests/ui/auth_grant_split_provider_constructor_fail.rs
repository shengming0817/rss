//! INVARIANT: AUTH-GRANT-SAME-PROVIDER-01 { level = "Hard", exec = "test", source = "trybuild" }

use std::sync::Arc;
use std::time::Duration;

use identity::ports::{DynAuthGrantLifecycle, DynCredentialRepo};
use identity::{LoginService, RefreshService};

struct TestSigner;

impl diport::Signer for TestSigner {
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

type OldSplitConstructor = fn(
    Arc<DynCredentialRepo<'static>>,
    Arc<DynAuthGrantLifecycle<'static>>,
    Arc<RefreshService<TestSigner>>,
    secure::PasswordPolicy,
    Box<dyn diport::Clock>,
    Duration,
) -> LoginService<TestSigner>;

fn main() {
    let _split_provider_constructor: OldSplitConstructor = LoginService::new;
}
