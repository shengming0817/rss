use generated::http::runtime_v1::inventory::{RuntimeInventoryData, RuntimeInventoryResponse};

fn direct(data: RuntimeInventoryData) {
    let _response = RuntimeInventoryResponse { data };
}

fn main() {}
