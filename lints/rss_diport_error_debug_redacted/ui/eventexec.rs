// rss_diport_error_debug_redacted UI fixture（LOCAL_CRATE == "eventexec"）。
#![allow(dead_code, unused)]

struct ConsumerError {
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

// 同名 `RedactedSource` 不是 canonical `diport::redacted::RedactedSource`，必须继续触发。
struct RedactedSource(Box<dyn std::error::Error + Send + Sync + 'static>);

fn main() {}
