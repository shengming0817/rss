use axum::{
    Json, Router,
    extract::{FromRequest, Request, State},
    middleware,
    response::{IntoResponse, Response},
    routing::MethodFilter,
};
use rss_axum::{ContractMarker, Endpoint, HttpContract, RequestBudget, request_control};
use rss_contract::{Contract, ContractDescriptor, SafeError, SafeErrorCode};
use std::time::Duration;

#[derive(Clone)]
struct App {
    increment: u32,
}
struct Add;
impl Contract for Add {
    type Request = u32;
    type Response = u32;
    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "example.add",
        1,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}
impl HttpContract<App> for Add {
    const METHOD: MethodFilter = MethodFilter::POST;
    const PATH: &'static str = "/add";
    async fn decode(request: Request, state: &App) -> Result<u32, SafeError> {
        Json::<u32>::from_request(request, state)
            .await
            .map(|Json(value)| value)
            .map_err(|_| SafeError::new(SafeErrorCode::InvalidInput))
    }
    fn encode(value: u32) -> Response {
        Json(value).into_response()
    }
}
async fn add(_: ContractMarker<Add>, State(app): State<App>, value: u32) -> Result<u32, SafeError> {
    value
        .checked_add(app.increment)
        .ok_or(SafeError::new(SafeErrorCode::InvalidInput))
}
fn main() -> Result<(), rss_axum::RequestBudgetError> {
    let budget = RequestBudget::new(Duration::from_secs(5))?;
    let _router = Endpoint::<Add, App>::new(add)
        .mount(Router::new())
        .with_state::<()>(App { increment: 1 })
        .layer(middleware::from_fn_with_state(budget, request_control));
    Ok(())
}
