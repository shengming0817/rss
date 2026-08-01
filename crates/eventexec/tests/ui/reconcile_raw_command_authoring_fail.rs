//! compile-fail：reconcile command 只能由 generated typed spec 构造，不能裸传 routing/payload。

use eventexec::reconcile::{DeviceCertificateSystemProducer, ReviewedFencedCommand};

fn main() {
    let _ = ReviewedFencedCommand::new(
        "attacker.commands.raw",
        br#"{"arbitrary":true}"#.to_vec(),
        DeviceCertificateSystemProducer::install(),
    );
}
