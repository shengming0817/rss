//! Explicit fixture authority shared by real message-provider consumers. Never a production default.
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
const TENANTS: &[&str] = &[
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
    "00000000-0000-0000-0000-000000000003",
    "00000000-0000-0000-0000-000000000004",
    "00000000-0000-0000-0000-000000000005",
    "00000000-0000-0000-0000-000000000006",
    "00000000-0000-0000-0000-000000000007",
    "00000000-0000-0000-0000-000000000008",
    "00000000-0000-0000-0000-000000000071",
    "00000000-0000-0000-0000-000000000072",
    "00000000-0000-0000-0000-000000000073",
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
    "550e8400-e29b-41d4-a716-446655440000",
    "550e8400-e29b-41d4-a716-446655440001",
    "550e8400-e29b-41d4-a716-446655440002",
    "550e8400-e29b-41d4-a716-446655440003",
    "550e8400-e29b-41d4-a716-446655440005",
    "550e8400-e29b-41d4-a716-446655440006",
    "550e8400-e29b-41d4-a716-446655440007",
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "f47ac10b-58cc-4372-a567-0e02b2c3d478",
    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "f47ac10b-58cc-4372-a567-0e02b2c3d480",
];
#[allow(clippy::expect_used)] // reason: fixed test authority, independent of restored database state.
pub fn binding() -> ExecutionBinding {
    ExecutionBinding::new(
        StorageIdentity::new([1; 16], [2; 16]).expect("storage"),
        TENANTS
            .iter()
            .map(|id| {
                (
                    rss_request_context::TenantId::parse(id).expect("tenant"),
                    Epoch::new(1).expect("epoch"),
                )
            })
            .collect(),
    )
    .expect("binding")
}
#[allow(dead_code)] // reason: compile-only consumers do not install a schema.
pub async fn provision(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2) ON CONFLICT DO NOTHING").bind([1u8;16].as_slice()).bind([2u8;16].as_slice()).execute(owner).await?;
    for tenant in TENANTS {
        sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1) ON CONFLICT DO NOTHING").bind(tenant).execute(owner).await?;
    }
    // Only the non-mutating admission function; DR entrypoints remain operator-only.
    sqlx::raw_sql("DO $f$ DECLARE r record; BEGIN FOR r IN SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolname<>current_user LOOP EXECUTE format('GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO %I',r.rolname); END LOOP; END $f$;").execute(owner).await?;
    Ok(())
}
