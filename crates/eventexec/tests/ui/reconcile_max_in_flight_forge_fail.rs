//! compile-fail：durable scheduler concurrency bound cannot bypass `try_new`.

use eventexec::ReconcileMaxInFlight;

fn main() {
    let _forged = ReconcileMaxInFlight(2);
}
