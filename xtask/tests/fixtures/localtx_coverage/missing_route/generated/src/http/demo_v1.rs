pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: ::vocab::HttpRouteBinding<RouteMarker, vocab::http::LocalTx> = todo!();
    pub const SPEC: super::HttpSpec = super::HttpSpec { local_tx: Some(super::LocalTxSpec {}) };
}
