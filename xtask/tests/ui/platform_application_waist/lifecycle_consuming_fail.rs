use platform_application_waist_contract::{Application, RuntimeHandle, profile};

async fn repeat_start(application: Application<profile::Core>) {
    let _ = application.start().await;
    let _ = application.start().await;
}

async fn repeat_shutdown(handle: RuntimeHandle) {
    let _ = handle.shutdown().await;
    let _ = handle.shutdown().await;
}

fn main() {
    let _ = (repeat_start, repeat_shutdown);
}
