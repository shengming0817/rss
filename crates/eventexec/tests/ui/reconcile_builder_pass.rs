//! compile-pass：三参齐全（reconciler + tenancy + trigger）→ build()。

use std::time::Duration;

use consistency::{Context, Outcome, ReconcileError, Reconciler, Request};
use eventexec::reconcile::{Builder, Tenancy, Trigger};

struct NoopReconciler;

impl Reconciler for NoopReconciler {
    async fn reconcile(&self, _ctx: &Context, _req: Request) -> Result<Outcome, ReconcileError> {
        Ok(Outcome::settled())
    }
}

fn main() {
    let trigger = Trigger::interval(Duration::from_secs(30)).expect("non-zero interval");
    let _loop = Builder::new(NoopReconciler, Tenancy::single_tenant(), trigger).build();
}
