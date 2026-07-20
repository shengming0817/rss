async fn wrong_identity() -> Result<u8, ()> {
    Ok(1)
}

async fn behavior() -> Result<(), ()> {
    Ok(())
}

testkit::provider_conformance_catalog! {
    provider: s3,
    error: (),
    capabilities: {
        identity => { #[tokio::test] identity => wrong_identity },
        conflict => { #[tokio::test] conflict => behavior },
        archive_receipt => { #[tokio::test] archive_receipt => behavior },
    }
}

fn main() {}
