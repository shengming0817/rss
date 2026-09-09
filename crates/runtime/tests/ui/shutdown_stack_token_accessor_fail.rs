#[path = "../support/mod.rs"]
mod support;
use std::time::Duration;

use rss_runtime::{ShutdownStack, TotalDrainBudget};

fn main() {
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).unwrap();
    let stack = ShutdownStack::try_new(budget, std::sync::Arc::new(support::TokioTimer)).unwrap();
    let _raw_root = stack.root_token();
}
