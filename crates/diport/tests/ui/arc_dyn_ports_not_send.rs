//! compile-fail（#1095 / #1331，INVARIANT: DIPORT-ASYNC-ARC-SEND-01 · DIPORT-DYN-CONCURRENCY-01
//! { level = "Medium", exec = "test", source = "trybuild" }）：`async_send` Dyn* wrappers are
//! `Send` but **non-`Sync`**, so `Arc<DynX>` is `!Send` and cannot be held across `tokio::spawn` /
//! Send `'static` futures.
//!
//! The port list is **not** hand-maintained here — [`diport::ui_assert_async_send_arc_not_send!`]
//! expands from the sole `classify_ports!` identity table (`async_send` bucket exact set).
//! Shared Sync exceptions live in the `async_sync` bucket and are locked by the pass UI
//! `async_sync_arc_send_sync_pass.rs`.
//!
//! Sanctioned shape (ADR-003 amendment §注入形态收口): multi-call async consumers use generic
//! static dispatch (`<S: X + Send + Sync + 'static>` + `Arc<S>`), not `Arc<DynX>`; `Box<DynX>` for
//! single-owner inject. If any `async_send` wrapper gains Sync (Option A, #1152), the matching
//! `assert_send` becomes compile-ok and this fail UI forces a conscious ADR + table update.
//!
//! stderr churn: after intentional `classify_ports!` edits, refresh with
//! `TRYBUILD=overwrite cargo test -p diport --test trybuild` (see `tests/trybuild.rs`).
fn assert_send<T: Send>() {}

fn main() {
    // Each Arc<DynX>: Send needs DynX: Send + Sync; async_send ports are Send-only ⇒ all !Send (E0277).
    diport::ui_assert_async_send_arc_not_send!();
}
