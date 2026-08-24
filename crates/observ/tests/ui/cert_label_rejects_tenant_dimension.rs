//! Tenant identity is forbidden as a certificate metric-label dimension.

use observ::CertLabel;

fn main() {
    let _ = CertLabel::TenantClass("enterprise");
}
