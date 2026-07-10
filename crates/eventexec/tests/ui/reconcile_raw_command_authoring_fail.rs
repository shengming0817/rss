//! compile-fail：reconcile command 只能由 generated typed spec 构造，不能裸传 routing/payload。

use diport::{EnvelopeSubjectId, OpaqueActorId, OutboxActor};
use eventexec::reconcile::{ReviewedCommand, StableDispatchKey};

fn main() {
    let tenant = vocab::TenantId::parse("11111111-1111-1111-1111-111111111111").expect("tenant");
    let _ = ReviewedCommand::new(
        StableDispatchKey::parse("device-1-create").expect("stable key"),
        "attacker.commands.raw",
        vocab::ContractBinding::from_static(
            "attacker",
            "attacker.raw",
            "v1",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        tenant,
        br#"{"arbitrary":true}"#.to_vec(),
        EnvelopeSubjectId::from_opaque("device-1").expect("subject"),
        OutboxActor::service(OpaqueActorId::from_opaque("raw-author").expect("actor")),
    );
}
