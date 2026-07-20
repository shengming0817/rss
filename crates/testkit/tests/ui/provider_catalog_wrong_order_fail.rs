async fn behavior() -> Result<(), ()> {
    Ok(())
}

testkit::provider_conformance_catalog! {
    provider: s3,
    error: (),
    capabilities: {
        conflict => { #[tokio::test] conflict => behavior },
        identity => { #[tokio::test] identity => behavior },
        archive_receipt => { #[tokio::test] archive_receipt => behavior },
    }
}

fn main() {}
