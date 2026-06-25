//! ROUTE-AUTH-FUNNEL-02：`AuthenticatedRoutes::new` 是 `pub(crate)`——外部 crate 无法 mint，唯有 `finalize_auth` 产。
fn main() {
    // 真实 dummy 参数（非 `unimplemented!()`，避免发散引入无关 unreachable warning 污染 stderr golden）：
    // 目标错误仅 `new` 私有（ROUTE-AUTH-FUNNEL-02），与参数值无关。
    let _authed = httpserve::AuthenticatedRoutes::new(axum::Router::new());
}
