use std::sync::Arc;

use audit_composition::{AuditModuleDeps, wire};
use bootstrap::compose_bindings;
use diport::Clock;
use postgres::PgRuntimeHandle;
use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

#[derive(Clone)]
struct TestMac;

impl MacVerifier for TestMac {
    fn sign(&self, _key: &MacKey, _algorithm: MacAlgorithm, _message: &[u8]) -> Mac {
        Mac::from_bytes(vec![0x42; 32])
    }

    fn verify(&self, _key: &MacKey, _algorithm: MacAlgorithm, _message: &[u8], _tag: &Mac) -> bool {
        true
    }
}

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH
    }
}

fn deps(key_len: usize) -> AuditModuleDeps<TestMac> {
    AuditModuleDeps::new(
        PgRuntimeHandle::for_module_test().for_domain(),
        TestMac,
        MacKey::from_bytes(vec![0x5a; key_len]),
        Arc::new(TestClock),
    )
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn wire_builds_stable_single_owned_binding() {
    let mut bindings = vec![wire(deps(32)).expect("audit composition builds")];
    assert_eq!(bindings[0].name(), "audit");

    let (_, output) = compose_bindings(&mut bindings).expect("audit domain composes");
    assert!(bindings.is_empty());
    assert!(output.probes.is_empty());
    assert!(output.resources.is_empty());
    assert!(output.workers.is_empty());
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn wire_rejects_weak_key_without_exposing_material() {
    let error = wire(deps(31))
        .err()
        .expect("weak audit key must fail closed");
    let message = format!("{error:#}");
    assert!(message.contains("at least 32 bytes"));
    assert!(!message.contains("5a5a"));
}
