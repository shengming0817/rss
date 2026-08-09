use platform_application_waist_contract::{ApplicationModule, RuntimeHandle};

fn leak_handle(_: RuntimeHandle<()>) {}
fn leak_module(_: ApplicationModule<()>) {}

fn main() {
    let _ = (leak_handle, leak_module);
}
