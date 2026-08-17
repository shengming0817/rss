use bootstrap::Registry;

fn main() {
    let mut registry = Registry::new();
    let _ = registry.finalize_routes();
}
