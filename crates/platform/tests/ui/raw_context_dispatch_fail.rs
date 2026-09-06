use rss_contract::ContractDescriptor;
use rss_contract::Contract;
use rss_platform::Dispatcher;
use rss_request_context::RequestContextView;

struct Inventory;

impl Contract for Inventory {
    type Request = ();
    type Response = ();
    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "runtime.inventory",
        1,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}

async fn bypass(
    dispatcher: &Dispatcher,
    context: RequestContextView<'_>,
) {
    let _ = dispatcher
        .dispatch::<Inventory>(&Inventory::DESCRIPTOR, (), context)
        .await;
}

fn main() {}
