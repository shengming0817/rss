use vocab::LocalTxBoundary;
use observ::LocalTxObservation;
use std::marker::PhantomData;
use tracing::Span;

struct Route;

fn main() {
    let _ = LocalTxObservation::<Route> {
        domain: "runtime-domain",
        contract_id: "runtime-contract",
        boundary: LocalTxBoundary::SingleDomain,
        span: Span::none(),
        marker: PhantomData,
    };
}
