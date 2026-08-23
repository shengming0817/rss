//! [`AppCtx`] 的 `task_local!` 传播 + fail-closed 访问器。
//!
//! `scope` 在信任边界绑定一次，`try_with` / `try_current` 在深层取用；ctx 缺失返回
//! [`MissingCtx`]（绝不 panic、绝不伪造 ctx —— ADR-002 §D6）。
//!
//! 注意 `tokio::task_local!` 的 `with` / `get` 在未绑定时**会 panic**，故本模块只封装
//! `try_with`（workspace `panic`/`unwrap_used`/`expect_used` 均 deny）。

use crate::ctx::AppCtx;
use std::future::Future;

tokio::task_local! {
    // 单一 monomorphized 实例（一个进程一套 auth 模型 —— ADR-002 §后果 R1）。
    static REQUEST_CTX: AppCtx;
}

/// 在 `fut` 执行期间绑定 `ctx`。框架信任边界（httpserve middleware / authn）每请求调一次。
///
/// 返回**不透明** `Future`（隐藏 tokio 内部 `TaskLocalFuture`，consumer 签名不被实现类型绑定）；
/// 零额外分配，绑定生命周期 = 被 await 的 future。
#[must_use = "scope 返回的 future 不 await 不会绑定 ctx"]
pub fn scope<F>(ctx: AppCtx, fut: F) -> impl Future<Output = F::Output>
where
    F: Future,
{
    REQUEST_CTX.scope(ctx, fut)
}

/// 借用当前 ctx 求值 `f`，免 clone。深层代码优先用此入口。
///
/// fail-closed：不在任何 `scope` 内时返回 `Err(MissingCtx)`，绝不伪造 anonymous / default-tenant。
pub fn try_with<R>(f: impl FnOnce(&AppCtx) -> R) -> Result<R, MissingCtx> {
    REQUEST_CTX.try_with(f).map_err(|_| MissingCtx)
}

/// clone 出当前 ctx。fail-closed 同 [`try_with`]。
pub fn try_current() -> Result<AppCtx, MissingCtx> {
    try_with(Clone::clone)
}

/// 当前任务不在任何 [`scope`] 内 —— 控制流值缺失。调用方必须 fail-closed（deny），
/// 不得回退到 anonymous / default-tenant（ADR-002 §D6）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("request context missing: caller is outside an authenticated scope")]
pub struct MissingCtx;

#[cfg(test)]
mod tests {
    use crate::ctx::{AppCtx, PrincipalFacet, RequestCtx, TestPrincipalFacet};
    use crate::local::{MissingCtx, scope, try_current, try_with};
    use rss_request_context::PrincipalKind;
    use rss_request_context::TenantId;
    use std::sync::Arc;

    // 测试 fixture：把任意 label 确定性映射到合法 canonical UUID（distinct label ⇒ distinct id，
    // 同 label ⇒ 同 id），使租户隔离 / 相等断言可辨。`DefaultHasher` 在**同次运行内**确定即够本测试
    // （每次运行内构造并比对，不跨运行复现；不依赖 std 未保证的跨版本 hash 稳定性）。
    // reason: `| 1` 保证非 nil、`from_u64_pair → hyphenated` 必为 canonical lowercase，故 parse 在此恒 Ok；
    // item-level carve-out 仅作用本 helper。
    #[allow(clippy::unwrap_used)]
    fn tid(label: &str) -> TenantId {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        label.hash(&mut hasher);
        let hi = hasher.finish() | 1; // 置最低位 ⇒ 整体 u128 非 nil
        label.len().hash(&mut hasher);
        let lo = hasher.finish();
        let canonical = uuid::Uuid::from_u64_pair(hi, lo).hyphenated().to_string();
        TenantId::parse(&canonical).unwrap()
    }

    fn sample(tenant: &str, principal: &str) -> AppCtx {
        let facet: Arc<dyn PrincipalFacet> =
            Arc::new(TestPrincipalFacet::new(PrincipalKind::User, principal));
        RequestCtx::new(tid(tenant), facet)
    }

    // `AppCtx` 的 principal payload 是 trait object（`Arc<dyn PrincipalFacet>`），无 `PartialEq`——
    // ambient 能力快照非值类型。测试经可观测字段断言：tenant 相等 + principal kind/subject 匹配。
    fn assert_ctx(ctx: &AppCtx, tenant: &str, subject: &str) {
        assert_eq!(ctx.tenant(), &tid(tenant), "tenant 不匹配");
        assert_eq!(ctx.principal().kind(), PrincipalKind::User, "kind 不匹配");
        assert!(
            ctx.principal().matches_subject(subject),
            "principal subject 不匹配"
        );
    }

    // happy path：scope 绑定后深层 try_current 取回同一快照。
    #[allow(clippy::unwrap_used)] // reason: 测试断言 scope 内 try_current 必为 Ok。
    #[tokio::test]
    async fn scope_binds_and_current_reads() {
        let seen = scope(sample("t1", "u1"), async { try_current() }).await;
        assert_ctx(&seen.unwrap(), "t1", "u1");
    }

    // fail-closed 核心不变式（ADR-002 §D6）：无 scope 时返回 Err，绝不伪造 ctx。
    #[tokio::test]
    async fn try_current_outside_scope_is_err() {
        assert_eq!(try_current().err(), Some(MissingCtx));
    }

    // try_current 是 total 函数：ctx 缺失产出 Err，永不 panic（workspace panic=deny）。
    #[tokio::test]
    async fn current_outside_scope_does_not_panic() {
        assert!(try_current().is_err());
    }

    // try_with 是免 clone 主入口：scope 内借用 ctx 求值。
    #[tokio::test]
    async fn try_with_inside_scope_borrows_payload() {
        let tenant = scope(sample("t1", "u1"), async { try_with(|ctx| *ctx.tenant()) }).await;
        assert_eq!(tenant, Ok(tid("t1")));
    }

    // try_with fail-closed：无 scope 时 Err，且闭包根本不被调用（绝不在缺 ctx 时跑业务）。
    #[tokio::test]
    async fn try_with_outside_scope_is_err_without_invoking_closure() {
        let called = std::cell::Cell::new(false);
        let r = try_with(|_| called.set(true));
        assert_eq!(r, Err(MissingCtx));
        assert!(!called.get(), "ctx 缺失时闭包不应被调用");
    }

    // 嵌套：内层 scope 遮蔽外层；内层 future 完成后外层快照恢复。
    #[allow(clippy::unwrap_used)] // reason: 测试断言两层 scope 内 try_current 均为 Ok。
    #[tokio::test]
    async fn nested_scope_inner_shadows_outer() {
        let (inner_seen, outer_seen) = scope(sample("outer", "u"), async {
            let inner_seen = scope(sample("inner", "u"), async { try_current() }).await;
            let outer_seen = try_current();
            (inner_seen, outer_seen)
        })
        .await;
        assert_ctx(&inner_seen.unwrap(), "inner", "u");
        assert_ctx(&outer_seen.unwrap(), "outer", "u");
    }

    // ctx 访问器返回绑定的 payload（覆盖 ctx.rs）。
    #[test]
    fn ctx_accessors_return_bound_payload() {
        let ctx = sample("t", "p");
        assert_eq!(ctx.tenant(), &tid("t"));
        assert_eq!(ctx.principal().kind(), PrincipalKind::User);
        assert!(ctx.principal().matches_subject("p"));
    }

    // 并发隔离：两个任务各自 scope 不同 tenant，互不串台（多租户隔离）。
    #[allow(clippy::unwrap_used)] // reason: 已先断言 JoinHandle is_ok，unwrap 等价 assert。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scope_isolation_across_concurrent_tasks() {
        let a = tokio::spawn(scope(sample("ta", "ua"), async { try_current() }));
        let b = tokio::spawn(scope(sample("tb", "ub"), async { try_current() }));
        let (ra, rb) = tokio::join!(a, b);
        // 先显式断言 JoinHandle 未 panic / abort，再断言各自取回自己 scope 的快照。
        assert!(ra.is_ok(), "task a join failed: {ra:?}");
        assert!(rb.is_ok(), "task b join failed: {rb:?}");
        assert_ctx(&ra.unwrap().unwrap(), "ta", "ua");
        assert_ctx(&rb.unwrap().unwrap(), "tb", "ub");
    }

    // spawn 不继承 task_local（R2 footgun）+ 受认可的「捕获-重绑」传播范式。
    #[tokio::test]
    async fn spawned_task_does_not_inherit_ctx() {
        // (a) scope 内裸 spawn 的子任务看不到父 ctx。
        let bare = scope(sample("t", "p"), async {
            tokio::spawn(async { try_current() }).await.ok()
        })
        .await;
        // bare = Some(Err(MissingCtx))：子任务无继承 ctx。
        assert!(
            matches!(bare, Some(Err(MissingCtx))),
            "裸 spawn 子任务不应继承父 ctx"
        );

        // (b) 范式：spawn 前捕获，子任务内重新 scope。
        let propagated = scope(sample("t", "p"), async {
            match try_current() {
                Ok(ctx) => tokio::spawn(scope(ctx, async { try_current() })).await.ok(),
                Err(_) => None,
            }
        })
        .await;
        // propagated = Some(Ok(ctx))：重绑后子任务取回父快照。
        assert!(
            matches!(propagated, Some(Ok(_))),
            "重绑后子任务应取回父 ctx"
        );
        if let Some(Ok(ctx)) = propagated {
            assert_ctx(&ctx, "t", "p");
        }
    }

    // spawn_blocking 同样不继承 task_local（lib.rs 文档三情形之一）：子闭包 fail-closed。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_blocking_does_not_inherit_ctx() {
        let seen = scope(sample("t", "p"), async {
            tokio::task::spawn_blocking(try_current).await.ok()
        })
        .await;
        assert!(
            matches!(seen, Some(Err(MissingCtx))),
            "spawn_blocking 子闭包不应继承父 ctx"
        );
    }

    // 边界错误消息稳定（覆盖 MissingCtx Display）。
    #[test]
    fn missing_ctx_error_message_is_stable() {
        assert!(MissingCtx.to_string().contains("request context missing"));
    }

    // RequestCtx 是 Clone 的不可变快照；Debug 必须脱敏（绝不泄 tenant/principal payload，F2/ADR §D1）。
    // 注：`AppCtx` 的 principal payload 是 trait object、无 `PartialEq`——clone 一致性经可观测字段断言。
    #[test]
    fn request_ctx_clone_and_debug_redacted() {
        let ctx = sample("SECRET_TENANT", "SECRET_PRINCIPAL");
        let cloned = ctx.clone();
        // clone 保留可观测字段（tenant + principal kind/subject）。
        assert_eq!(cloned.tenant(), ctx.tenant());
        assert_eq!(cloned.principal().kind(), ctx.principal().kind());
        assert!(cloned.principal().matches_subject("SECRET_PRINCIPAL"));
        // Debug 脱敏：类型名出现，payload 不泄露。
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("RequestCtx"), "应出类型名: {dbg}");
        assert!(dbg.contains("redacted"), "应标 redacted: {dbg}");
        assert!(
            !dbg.contains("SECRET"),
            "Debug 不得泄露 tenant/principal payload: {dbg}"
        );
    }
}
