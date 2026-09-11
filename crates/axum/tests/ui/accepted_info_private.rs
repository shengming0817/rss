fn main() {
    let _ = rss_axum::AcceptedConnectionInfo {
        socket_peer: "127.0.0.1:8080".parse().unwrap(),
        metadata: (),
    };
}
