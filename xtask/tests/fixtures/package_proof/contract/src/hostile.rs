use release_package::SafeError;

#[derive(Debug)]
struct HostileProviderError;

impl std::fmt::Display for HostileProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("password=hunter2 payload={token}")
    }
}

impl std::error::Error for HostileProviderError {}

fn main() {
    let _: SafeError = HostileProviderError.into();
}
