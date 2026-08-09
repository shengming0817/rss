use std::io;

use platform_application_waist_contract::{
    BuildError, DiagnosticsSnapshot, RequestContext, VerifiedPrincipal,
};

fn demand_from<T: From<io::Error>>() {}
fn demand_try_from<T: TryFrom<io::Error>>() {}

fn main() {
    demand_from::<BuildError>();
    demand_from::<DiagnosticsSnapshot>();
    demand_try_from::<BuildError>();
    demand_try_from::<DiagnosticsSnapshot>();
    let _ = BuildError {
        source: io::Error::other("SECRET_BAIT provider=https://internal.invalid"),
    };
    let _ = RequestContext::into_inner;
    let _ = VerifiedPrincipal::subject;
}
