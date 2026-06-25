//! ROUTE-AUTH-FUNNEL-01：`UnfinalizedRoutes` 无 public bindable 出口——`into_make_service` 不存在，未认证 router 不可 bind。
fn main() {
    let unfinalized = httpserve::UnfinalizedRoutes::empty();
    let _make = unfinalized.into_make_service();
}
