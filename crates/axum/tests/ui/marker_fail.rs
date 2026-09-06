#[path = "../support/mod.rs"]
mod support;
use axum::extract::State;
use rss_axum::{ContractMarker, Endpoint};
use rss_contract::SafeError;
use support::{App, Echo};
struct Other;
async fn wrong(_: ContractMarker<Other>, _: State<App>, _: u32) -> Result<u32, SafeError> { Ok(1) }
fn main() { let _ = Endpoint::<Echo, App>::new(wrong); }
