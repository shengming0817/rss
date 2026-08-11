include!("../verify-lock-build.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    verify_bundled_lock()
}
