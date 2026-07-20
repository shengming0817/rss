async fn behavior() -> Result<(), ()> {
    Ok(())
}

testkit::provider_conformance_catalog! {
    provider: s3,
    error: (),
    capabilities: {
        identity => { #[tokio::test] identity => behavior },
        conflict => { #[tokio::test] conflict => behavior },
    }
}

fn main() {}
