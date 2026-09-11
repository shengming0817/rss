//! Product-side rustls adapter consuming only public RSS APIs.
#[path = "support/tls.rs"]
pub mod support;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), support::Error> {
    tokio::time::timeout(std::time::Duration::from_secs(15), support::smoke()).await?
}
