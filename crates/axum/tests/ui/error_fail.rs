#[path = "../support/mod.rs"]
mod support;
use axum::extract::State;
use rss_axum::{ContractMarker, Endpoint};
use rss_contract::SafeError;
use support::{App, Echo};
struct Other;
async fn wrong(_: ContractMarker<Echo>, _: State<App>, _: u32) -> Result<u32, std::io::Error> { Ok(1) }
fn main() { let _ = Endpoint::<Echo, App>::new(wrong); }
