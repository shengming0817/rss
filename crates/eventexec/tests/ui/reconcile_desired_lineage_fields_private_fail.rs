//! compile-fail: command lineage cannot be assembled from an independently chosen R/G pair.

fn main() {
    let _ = eventexec::reconcile::DeviceCertificateDesiredLineage;
}
