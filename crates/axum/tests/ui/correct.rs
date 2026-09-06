#[path = "../support/mod.rs"]
mod support;
use axum::extract::State;
use rss_axum::{ContractMarker, Endpoint};
use rss_contract::SafeError;
use support::{App, Echo};
fn main() { let _router = Endpoint::<Echo, App>::new(support::echo).mount(axum::Router::new()).with_state::<()>(App(1)); }
