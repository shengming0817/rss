use rss_platform::TrustedContextMinter;

fn main() {
    let _forged = TrustedContextMinter { seal: 1 };
}
