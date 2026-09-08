use rss_saga::*;
fn main() -> anyhow::Result<()> {
    let identity = Identity::new(
        rss_contract::ContractId::from_static("orders.checkout"),
        rss_contract::ContractVersion::from_static_major(1),
        rss_contract::SchemaDigest::from_static(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ActionGeneration::parse(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )?,
    );
    let definition = Definition::new(
        "orders",
        identity,
        vec![StepSpec::new(
            "reserve",
            "receipt.v1",
            "reserve",
            "release",
            1,
        )?],
    )?;
    anyhow::ensure!(definition.steps().len() == 1, "exact definition lost step");
    anyhow::ensure!(
        ActionGeneration::parse("latest").is_err(),
        "floating generation accepted"
    );
    Ok(())
}
