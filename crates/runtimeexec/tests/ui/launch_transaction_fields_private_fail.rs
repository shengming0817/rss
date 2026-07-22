fn main() {
    let mut stack =
        bootstrap::shutdown::ShutdownStack::new(tokio_util::sync::CancellationToken::new());
    let _forged = runtimeexec::LaunchTransaction { stack: &mut stack };
}
