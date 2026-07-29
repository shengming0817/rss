//! Production auth bridge must remain genuinely asynchronous.
//!
//! INVARIANT: AUTHN-BRIDGE-ASYNC-ONLY-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "async_bridge_guard_rejects_sync_drivers_and_escape_hatches", anti_vacuity = "production_auth_bridge_is_async_only" }.

const FORBIDDEN: &[&str] = &[
    "block_on(",
    "block_in_place(",
    "executor::",
    "LocalPool",
    "runtime::Builder",
    "Runtime::new(",
    "new_current_thread(",
    "new_multi_thread(",
    "noop_waker",
    "Context::from_waker",
    "poll_unpin(",
    "Future::poll(",
    ".poll(",
    "now_or_never(",
    "tokio::time::timeout(",
    "TimeoutLayer",
    "Timeout::new(",
    "allow(clippy::disallowed_methods)",
];

fn forbidden_mechanism(source: &str) -> Option<&'static str> {
    let compact: String = source
        .chars()
        .filter(|char| !char.is_whitespace())
        .collect();
    FORBIDDEN
        .iter()
        .copied()
        .find(|needle| compact.contains(needle))
}

#[test]
fn async_bridge_guard_rejects_sync_drivers_and_escape_hatches() {
    for forbidden in FORBIDDEN {
        let spaced = forbidden.replace('(', " (");
        let synthetic = format!("fn weak_bridge() {{ {spaced} }}");
        assert_eq!(forbidden_mechanism(&synthetic), Some(*forbidden));
    }
}

#[test]
fn production_auth_bridge_is_async_only() {
    let source = include_str!("../src/auth_bridge.rs");
    assert_eq!(forbidden_mechanism(source), None);
    assert!(source.contains("async fn verify_principal"));
    assert!(source.contains("async fn mint_evidence"));
    assert!(source.contains(".instrument(span)"));
}
