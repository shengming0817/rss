fn main() {
    let mut stack =
        bootstrap::shutdown::ShutdownStack::new(tokio_util::sync::CancellationToken::new());
    let _forged = runtimeexec::LaunchRegistrar {
        stack: &mut stack,
        listener_count: 0,
    };
}
