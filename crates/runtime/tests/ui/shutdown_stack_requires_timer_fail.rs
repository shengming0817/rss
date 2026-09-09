use rss_runtime::{ShutdownStack, TotalDrainBudget};
fn main() {
    let budget = TotalDrainBudget::new(std::time::Duration::from_secs(1)).unwrap();
    let _owner = ShutdownStack::try_new(budget);
}
