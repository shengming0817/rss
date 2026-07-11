pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: ::vocab::HttpRouteBinding<RouteMarker, vocab::http::LocalTx> =
        ::vocab::HttpRouteBinding::new();
    pub const SPEC: super::super::HttpSpec = super::super::HttpSpec {
        local_tx: Some(super::super::LocalTxSpec {}),
    };
}
