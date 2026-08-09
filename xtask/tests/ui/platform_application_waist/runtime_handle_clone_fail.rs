use platform_application_waist_contract::RuntimeHandle;

fn duplicate(handle: RuntimeHandle) -> RuntimeHandle {
    handle.clone()
}

fn main() {
    let _ = duplicate;
}
