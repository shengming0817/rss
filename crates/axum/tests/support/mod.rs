use axum::{
    Json,
    extract::{FromRequest, Request, State},
    response::{IntoResponse, Response},
    routing::MethodFilter,
};
use rss_axum::{ContractMarker, HttpContract};
use rss_contract::{Contract, ContractDescriptor, SafeError, SafeErrorCode};

#[derive(Clone)]
pub struct App(pub u32);
pub struct Echo;
impl Contract for Echo {
    type Request = u32;
    type Response = u32;
    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "test.echo",
        1,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}
impl HttpContract<App> for Echo {
    const METHOD: MethodFilter = MethodFilter::POST;
    const PATH: &'static str = "/echo";
    async fn decode(request: Request, state: &App) -> Result<u32, SafeError> {
        Json::<u32>::from_request(request, state)
            .await
            .map(|Json(v)| v)
            .map_err(|_| SafeError::new(SafeErrorCode::InvalidInput))
    }
    fn encode(value: u32) -> Response {
        Json(value).into_response()
    }
}
pub async fn echo(
    _: ContractMarker<Echo>,
    State(app): State<App>,
    value: u32,
) -> Result<u32, SafeError> {
    Ok(app.0 + value)
}
