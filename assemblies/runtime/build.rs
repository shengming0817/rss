include!("../verify-lock-build.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    emit_bundled_repository_snapshot()
}
