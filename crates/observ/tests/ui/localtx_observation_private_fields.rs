use observ::LocalTxObservation;

fn main() {
    let _ = LocalTxObservation {
        domain: "runtime-domain",
        contract_id: "runtime-contract",
        boundary: "runtime-boundary",
    };
}
