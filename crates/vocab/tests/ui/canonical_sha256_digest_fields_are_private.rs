use vocab::CanonicalSha256Digest;

fn main() {
    let _ = CanonicalSha256Digest(
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_owned(),
    );
}
