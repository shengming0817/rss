//! compile-fail（#1828）：PDP 是多线程 serving state；即使 provider 可 Send，持有 `Cell` 仍因非 Sync 被拒。
use std::cell::Cell;
use std::future::{Future, ready};

use diport::{Pdp, PdpError, RawCredential, VerifiedClaims};

struct NonSyncPdp {
    marker: Cell<()>,
}

impl Pdp for NonSyncPdp {
    fn verify(
        &self,
        _raw: &RawCredential,
    ) -> impl Future<Output = Result<VerifiedClaims, PdpError>> + Send {
        ready(Ok(VerifiedClaims::service_token(
            vocab::ServiceCallerDomain::MaintenanceOperator,
        )))
    }
}

fn main() {
    let _ = NonSyncPdp {
        marker: Cell::new(()),
    };
}
