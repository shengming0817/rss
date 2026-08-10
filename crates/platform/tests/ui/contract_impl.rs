use rss_platform::{Contract, ContractId, ContractVersion, SchemaDigest};

struct Forged;
impl Contract for Forged {
    type Request = ();
    type Response = ();
    const ID: ContractId = ContractId::from_static("forged.contract");
    const VERSION: ContractVersion = ContractVersion::new(1, 0);
    const SCHEMA_DIGEST: SchemaDigest = SchemaDigest::from_static("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    const PERMISSION: &'static str = "forged:permission";
}

fn main() {}
