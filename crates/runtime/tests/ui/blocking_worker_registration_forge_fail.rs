fn main() {
    let _forged = rss_runtime::ManagedBlockingWorkerRegistration {
        name: "forged".to_owned(),
        shutdown_timeout: std::time::Duration::from_secs(1),
        run: None,
    };
}
