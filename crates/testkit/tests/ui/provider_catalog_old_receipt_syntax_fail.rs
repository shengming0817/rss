async fn behavior() -> Result<(), ()> {
    Ok(())
}

testkit::provider_conformance_catalog! {
    provider: s3,
    family: owner::Family,
    error: (),
    capabilities: {
        identity => { #[tokio::test] identity => behavior },
        conflict => { #[tokio::test] conflict => behavior },
        archive_receipt => { #[tokio::test] archive_receipt => behavior },
    }
}

fn main() {}
