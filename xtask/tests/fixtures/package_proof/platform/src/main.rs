use release_package::*;
use rss_contract::ContractDescriptor;
use rss_request_context::RequestContextView;

struct Inventory;
impl Contract for Inventory {
    type Request = u32;
    type Response = u32;
    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "runtime.inventory",
        1,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}

struct InventoryHandler;
impl Handler<Inventory> for InventoryHandler {
    fn handle<'a>(
        &'a self,
        request: u32,
        context: RequestContextView<'a>,
    ) -> HandlerFuture<'a, u32> {
        Box::pin(async move {
            let _tenant = context.tenant().map(ToString::to_string);
            let _request_id = context.request_id().as_str();
            let _principal_kind = context.principal().kind();
            let _deadline = context.deadline().instant();
            let _cancelled = context.cancellation().is_cancelled();
            let _row_scope = context.obligations().row_scope();
            Ok(request + 1)
        })
    }
}

fn main() {
    let _handler = InventoryHandler;
    println!(
        "{}",
        serde_json::json!({
            "contract": Inventory::DESCRIPTOR.id(),
            "asyncHandlerImplemented": true,
            "trustedContextReadOnly": true
        })
    );
}
