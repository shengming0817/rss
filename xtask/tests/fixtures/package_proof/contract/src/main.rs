use release_package::*;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let id = ContractId::parse("runtime.inventory")?;
    let version = ContractVersion::parse("v12")?;
    let digest = SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?;
    let descriptor = ContractDescriptor::from_static_version(
        "runtime.inventory",
        "v12",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let invalid = ContractId::parse("Runtime..inventory").is_err();
    println!(r#"{{"package":"rss-contract","dottedId":{},"version":"{}","digest":{},"descriptor":{},"invalidRejected":{}}}"#,
        descriptor.id() == id.as_str(), descriptor.version(), descriptor.schema_digest() == digest.as_str(),
        version.major() == 12, invalid);
    Ok(())
}
