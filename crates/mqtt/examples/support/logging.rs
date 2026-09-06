//! Consumer-owned temporary upstream log policy. Never install a logger inside rss-mqtt.
//! Upstream packet diagnostics remain unsafe in 0.34.0; do not override these targets via RUST_LOG.
pub fn filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::new("info,rumqttc=off,rumqttc_core=off")
}
