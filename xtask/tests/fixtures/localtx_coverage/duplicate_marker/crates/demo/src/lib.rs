use generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler(_: httpserve::ContractMarker<generated::http::demo_v1::write::RouteMarker>) {}
fn init() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
#[cfg(test)] mod tests {
 #[test] fn one() { const _: vocab::HttpRouteBinding<generated::http::demo_v1::write::RouteMarker> = generated::http::demo_v1::write::ROUTE; }
 #[tokio::test] async fn two() { const _: vocab::HttpRouteBinding<generated::http::demo_v1::write::RouteMarker> = generated::http::demo_v1::write::ROUTE; }
}
