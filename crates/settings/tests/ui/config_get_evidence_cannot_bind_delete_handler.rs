//! A handler belonging to settings.config-delete must not bind to settings.config-get evidence.

use generated::http::settings_v4::ROUTE as CONFIG_GET_HTTP_ROUTE;

async fn config_delete_handler(
    _: httpserve::ContractMarker<generated::http::settings_v5::RouteMarker>,
) {
}

fn main() {
    let _ = httpserve::GeneratedPrimaryEndpoint::<(), vocab::http::LocalOnly>::new(
        CONFIG_GET_HTTP_ROUTE,
        config_delete_handler,
    );
}
