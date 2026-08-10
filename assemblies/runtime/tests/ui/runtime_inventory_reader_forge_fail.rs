use assembly_schema::runtime_inventory::{RuntimeInventoryParts, RuntimeInventoryReadFailure};
use runtimeexec::inventory::InventoryReader;

fn forge(parts: RuntimeInventoryParts) {
    let reader = InventoryReader::new(move || Ok::<_, RuntimeInventoryReadFailure>(parts.clone()));
    let _ = reader.read();
}

fn main() {}
