//! compile-fail: fenced reconcile actor identity cannot be supplied as caller-controlled text.

use eventexec::reconcile::DeviceCertificateSystemProducer;

fn main() {
    let _: DeviceCertificateSystemProducer = "attacker.controlled.actor".into();
}
