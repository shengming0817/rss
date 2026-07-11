use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
use ::httpserve::{
    ContractMarker,
    GeneratedPrimaryEndpoint as Endpoint,
};
fn handler(_: ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) -> Result<(), ::httpserve::Error> {
        reg.route_group(|rb| {
            let endpoint = Endpoint::new(WRITE_ROUTE, handler)?;
            Ok(rb.mount(endpoint)?)
        })?;
        Ok(())
    }
}
#[cfg(test)] mod tests {
    #[test] fn covered() {
        const _: ::vocab::HttpRouteBinding<
            ::generated::http::demo_v1::write::RouteMarker,
            ::vocab::http::LocalTx,
        > =
            ::generated::http::demo_v1::write::ROUTE;
    }
}
