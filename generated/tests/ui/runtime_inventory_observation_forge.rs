use assembly_schema::runtime_inventory::{RuntimeInventoryObservation, RuntimeInventoryParts};

fn forge(parts: RuntimeInventoryParts) {
    let _ = RuntimeInventoryObservation { parts };
}

fn main() {}
