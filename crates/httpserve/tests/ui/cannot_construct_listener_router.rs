//! ROUTE-LISTENER-TYPED-01（无 raw-bypass）：`ListenerRouter::new` 是 `pub(crate)`——外部无法直接构造 builder，
//! 只能在 `route_group` register 闭包里收到（仅 typed mount，不可注入任意 router）。
fn main() {
    // 真实 dummy 参数（非 `unimplemented!()`，避免发散引入无关 unreachable warning 污染 stderr golden）：
    // 目标错误仅 `new` 私有（ROUTE-LISTENER-TYPED-01），与参数值无关。
    let _rb = httpserve::ListenerRouter::<httpserve::Admin>::new(axum::Router::new());
}
