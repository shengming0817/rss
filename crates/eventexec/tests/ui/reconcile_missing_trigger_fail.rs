//! compile-fail：漏 trigger（仅传 reconciler + tenancy）→ E0061（RECONCILE-TENANCY-REQ-01 Hard）。

use consistency::{Context, Outcome, ReconcileError, Reconciler, Request};
use eventexec::reconcile::{Builder, Tenancy};

struct NoopReconciler;

impl Reconciler for NoopReconciler {
    async fn reconcile(&self, _ctx: &Context, _req: Request) -> Result<Outcome, ReconcileError> {
        Ok(Outcome::settled())
    }
}

fn main() {
    // 缺 trigger 位置参 → 编译错（build() 强制一个 Trigger 上移到类型系统）。
    let _loop = Builder::new(NoopReconciler, Tenancy::single_tenant()).build();
}
