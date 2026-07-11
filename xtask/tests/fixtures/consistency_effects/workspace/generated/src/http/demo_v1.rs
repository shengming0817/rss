pub mod safe {
    pub struct RouteMarker;
    pub const ROUTE: ::vocab::HttpRouteBinding<RouteMarker, ::vocab::http::LocalOnly> =
        ::vocab::HttpRouteBinding::new();
}
