fn main() {
    let (start, _) =
        diport::ManagedTask::prepare("raw-future", diport::DEFAULT_SHUTDOWN_TIMEOUT);
    let token = tokio_util::sync::CancellationToken::new();
    let future = async { Ok::<(), diport::ShutdownError>(()) };
    let _task = start.spawn(token, future);
}
