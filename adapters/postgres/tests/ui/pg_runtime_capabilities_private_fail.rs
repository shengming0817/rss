fn external_crate_cannot_name_runtime_store_capabilities() {
    let _: Option<postgres::pool::VerifiedPgReadStore> = None;
    let _: Option<postgres::pool::VerifiedPgWriteStore> = None;
    let _: Option<postgres::pool::PgRuntimeStores> = None;
}

fn main() {}
