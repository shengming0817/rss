//! Always-on Medium ownership gate for the MQTT mTLS fixture public surface.
//!
//! Kept outside `#![cfg(feature = "containers")]` so ArchRules can enroll `exec = "test"`
//! against default-feature AST symbols (synthetic-red / anti-vacuity).

/// INVARIANT: MQTT-FIXTURE-NO-SIGNING-KEY-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "exposes_broker_signing_private_key_red", anti_vacuity = "broker_signing_private_key_has_no_public_getter" }
///
/// The broker fixture may install the assertion signing key in the container, but its public Rust
/// API must expose only the verification key. This exact source guard complements the typed
/// `[u8; 32]` assertion until the public-api golden includes the feature-gated testkit API.
fn exposes_broker_signing_private_key(source: &str) -> bool {
    source.lines().any(|line| {
        let signature = line.trim_start();
        (signature.starts_with("pub fn ") || signature.starts_with("pub async fn "))
            && signature.contains("private")
            && signature.contains("key")
            && (signature.contains("assertion")
                || signature.contains("signing")
                || signature.contains("broker"))
    })
}

#[test]
fn broker_signing_private_key_has_no_public_getter() {
    let source = concat!(
        include_str!("../src/containers/mod.rs"),
        include_str!("../src/containers/mqtt.rs")
    );
    assert!(
        !exposes_broker_signing_private_key(source),
        "MqttMtlsFixture must not expose a public signing-private-key getter"
    );
}

#[test]
fn exposes_broker_signing_private_key_red() {
    // Synthetic red / missing-capability: prove the guard does not pass vacuously.
    assert!(exposes_broker_signing_private_key(
        "pub fn broker_assertion_private_key(&self) -> &[u8] { todo!() }"
    ));
}
