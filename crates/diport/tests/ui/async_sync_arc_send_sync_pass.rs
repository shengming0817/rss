//! pass（#1331 / #1319，INVARIANT: DIPORT-DYN-CONCURRENCY-01
//! { level = "Medium", exec = "test", source = "trybuild" }）：every `async_sync` Dyn* from
//! `classify_ports!` satisfies `Arc<DynX>: Send + Sync` (closed Sync-exception set).
//! Hard Arc Send+Sync proof lives in `effect.rs` (`assert_send_sync_bound`); this UI is Medium
//! anti-vacuity only.
//!
//! Port identity comes solely from [`diport::ui_assert_async_sync_arc_send_sync!`] — do not hand-list
//! ports here when adding a new shared async DI port; tag it `async_sync` in `effect.rs`.
fn assert_send_sync<T: Send + Sync>() {}

fn main() {
    diport::ui_assert_async_sync_arc_send_sync!();
}
