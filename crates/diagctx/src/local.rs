//! [`DiagnosticCtx`] 的 `task_local!` 传播 + **fail-open** 访问器。
//!
//! 与 `runctx::local` 刻意相反：诊断信号缺失返回 `None`（best-effort 省略），**绝不 deny / panic**——
//! 它不是授权闸门，丢失只影响可观测关联，不影响正确性 / 安全（ADR-002 §D1-bis）。`scope` 在信任边界
//! （httpserve correlation middleware）每请求绑定一次；深层 adapter（outbox emit）经 [`correlation`] 读回。
//!
//! `tokio::task_local!` 的 `with` / `get` 在未绑定时**会 panic**，故本模块只封装 `try_with`
//! （workspace `panic`/`unwrap_used`/`expect_used` 均 deny）。`spawn` / `spawn_blocking` 不继承 task_local：
//! 跨任务诊断关联丢失 ⇒ fail-open 省略（benign），不像 runctx 需「捕获-重绑」（缺失不越权）。
//!
//! # 跨 `tokio::spawn` 透传（惯用 recipe）
//!
//! 若后台任务需保留关联链路（如 outbox emit / audit 后台写），**spawn 前捕获、子任务内重绑**：
//!
//! ```ignore
//! // 后台任务需保关联：spawn 前捕获、子任务内重绑
//! match diagctx::current() {
//!     Some(ctx) => tokio::spawn(diagctx::scope(ctx, async { /* outbox emit */ })),
//!     None => tokio::spawn(async { /* 无关联，fail-open */ }),
//! };
//! ```
//!
//! **不需重绑的场景**：httpserve correlation middleware 的 `diagctx::scope(ctx, next.run(req))` 已覆盖
//! axum handler + application + adapter emit 的同步调用链（同一 task），子 future 在同一 scope 内自然
//! 继承。只有 `tokio::spawn` 隔断 task 时才需要显式捕获-重绑。

use crate::ctx::{CorrelationId, DiagnosticCtx};
use std::future::Future;

tokio::task_local! {
    static DIAGNOSTIC_CTX: DiagnosticCtx;
}

/// 在 `fut` 执行期间绑定诊断 `ctx`。httpserve correlation middleware 每请求调一次。
///
/// 返回**不透明** `Future`（隐藏 tokio 内部 `TaskLocalFuture`）；绑定生命周期 = 被 await 的 future。
#[must_use = "scope 返回的 future 不 await 不会绑定诊断 ctx"]
pub fn scope<F>(ctx: DiagnosticCtx, fut: F) -> impl Future<Output = F::Output>
where
    F: Future,
{
    DIAGNOSTIC_CTX.scope(ctx, fut)
}

/// clone 出当前 correlation；不在任何 [`scope`] 内时返回 `None`（**fail-open**，绝不 panic）。
/// outbox emit adapter 据此「有则盖章、无则省略」。
pub fn correlation() -> Option<CorrelationId> {
    DIAGNOSTIC_CTX.try_with(|c| c.correlation().clone()).ok()
}

/// clone 出当前诊断 ctx；缺失返回 `None`（fail-open）。
pub fn current() -> Option<DiagnosticCtx> {
    DIAGNOSTIC_CTX.try_with(Clone::clone).ok()
}

#[cfg(test)]
mod tests {
    use crate::ctx::{CorrelationId, DiagnosticCtx};
    use crate::local::{correlation, current, scope};

    // 测试 fixture：合法诊断 ctx。item-level carve-out（workspace expect_used=deny）。
    // reason: 仅测试 fixture，输入恒为白名单合法串。
    #[allow(clippy::expect_used)]
    fn ctx(raw: &str) -> DiagnosticCtx {
        DiagnosticCtx::new(CorrelationId::parse(raw).expect("test fixture valid"))
    }

    // happy path：scope 绑定后深层 correlation() 取回同值。
    #[tokio::test]
    async fn scope_binds_and_correlation_reads() {
        let seen = scope(ctx("corr-1"), async { correlation() }).await;
        assert_eq!(
            seen.map(|c| c.as_str().to_string()),
            Some("corr-1".to_string())
        );
    }

    // fail-open 核心不变式（与 runctx fail-closed 刻意相反）：无 scope 返回 None，绝不 panic / Err。
    #[tokio::test]
    async fn correlation_outside_scope_is_none() {
        assert_eq!(correlation(), None);
    }

    // total 函数：缺失产出 None，永不 panic（workspace panic=deny）。
    #[tokio::test]
    async fn current_outside_scope_does_not_panic() {
        assert!(current().is_none());
    }

    // current() 取整 ctx。
    #[tokio::test]
    async fn current_inside_scope_reads_ctx() {
        let seen = scope(ctx("corr-2"), async { current() }).await;
        assert_eq!(seen, Some(ctx("corr-2")));
    }

    // 嵌套：内层 scope 遮蔽外层；内层完成后外层快照恢复。
    #[tokio::test]
    async fn nested_scope_inner_shadows_outer() {
        let (inner, outer) = scope(ctx("outer"), async {
            let inner = scope(ctx("inner"), async { correlation() }).await;
            let outer = correlation();
            (inner, outer)
        })
        .await;
        assert_eq!(
            inner.map(|c| c.as_str().to_string()),
            Some("inner".to_string())
        );
        assert_eq!(
            outer.map(|c| c.as_str().to_string()),
            Some("outer".to_string())
        );
    }

    // spawn 不继承 task_local（fail-open footgun，benign）：子任务 correlation() == None。
    #[tokio::test]
    async fn spawned_task_does_not_inherit_correlation() {
        let bare = scope(ctx("t"), async {
            tokio::spawn(async { correlation() }).await.ok().flatten()
        })
        .await;
        assert_eq!(bare, None);
    }

    // 并发隔离：两任务各自 scope 不同 correlation，互不串台。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scope_isolation_across_concurrent_tasks() {
        let a = tokio::spawn(scope(ctx("ca"), async { correlation() }));
        let b = tokio::spawn(scope(ctx("cb"), async { correlation() }));
        let (ra, rb) = tokio::join!(a, b);
        assert!(ra.is_ok() && rb.is_ok(), "task join failed");
        assert_eq!(
            ra.ok().flatten().map(|c| c.as_str().to_string()),
            Some("ca".to_string())
        );
        assert_eq!(
            rb.ok().flatten().map(|c| c.as_str().to_string()),
            Some("cb".to_string())
        );
    }
}
