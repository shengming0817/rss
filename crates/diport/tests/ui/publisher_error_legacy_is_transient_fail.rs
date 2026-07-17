//! #1821 breaking API guard: the retired two-state query must not remain callable.

use diport::PublisherError;

fn main() {
    let error = PublisherError::transient(std::io::Error::other("retryable"));
    let _legacy = error.is_transient();
}
