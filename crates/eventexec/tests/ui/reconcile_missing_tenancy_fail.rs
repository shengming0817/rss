//! compile-fail：漏 tenancy（仅传 reconciler）→ E0061（RECONCILE-TENANCY-REQ-01 Hard）。

use consistency::{Context, Outcome, ReconcileError, Reconciler, Request};
use eventexec::reconcile::Builder;

struct NoopReconciler;

impl Reconciler for NoopReconciler {
    async fn reconcile(&self, _ctx: &Context, _req: Request) -> Result<Outcome, ReconcileError> {
        Ok(Outcome::settled())
    }
}

fn main() {
    // 缺 tenancy + trigger 位置参 → 编译错（不可表达漏声明租户命名空间）。
    let _loop = Builder::new(NoopReconciler).build();
}
