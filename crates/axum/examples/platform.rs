use rss_contract::{Contract, ContractDescriptor};
use rss_platform::{Handler, HandlerFuture};
struct Add;
impl Contract for Add {
    type Request = u32;
    type Response = u32;
    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "test.add",
        1,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}
struct Identity;
impl Handler<Add> for Identity {
    fn handle<'a>(
        &'a self,
        value: u32,
        _: rss_request_context::RequestContextView<'a>,
    ) -> HandlerFuture<'a, u32> {
        Box::pin(async move { Ok(value) })
    }
}
fn requires_same_contract<H: Handler<Add>>(_: H) {}
fn main() {
    requires_same_contract(Identity);
}
