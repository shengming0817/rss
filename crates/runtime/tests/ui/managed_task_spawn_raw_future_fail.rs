fn main() {
    let (start, _) =
        rss_runtime::ManagedTask::prepare("raw-future", rss_runtime::DEFAULT_SHUTDOWN_TIMEOUT);
    let future = async { Ok::<(), rss_runtime::ShutdownError>(()) };
    let _registration = start.into_registration(future);
}
