use generated::http::runtime_v1::inventory::{
    RuntimeInventoryResponse, RuntimeInventoryResponseEnvelope,
};

fn bypass_projection(response: RuntimeInventoryResponse) {
    let _ = RuntimeInventoryResponseEnvelope::Success(response);
}

fn main() {}
