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
        ready(Ok(VerifiedClaims::service_token(vocab::ServiceCallerDomain::MaintenanceOperator, rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical tenant"))))
    }
}

fn main() {
    let _ = NonSyncPdp {
        marker: Cell::new(()),
    };
}
