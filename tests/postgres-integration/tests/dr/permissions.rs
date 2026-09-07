use super::*;

#[allow(clippy::cognitive_complexity)] // reason: table-driven catalog damage/repair and closed-session assertions.
pub async fn check(
    owner: &sqlx::PgPool,
    runtime: &PgConfig,
    operator: &PgConfig,
) -> anyhow::Result<()> {
    let immutable: bool = sqlx::query_scalar("SELECT NOT has_column_privilege('rss_tmsg_relay','rss_transactional_messaging.storage_lineage','target','UPDATE') AND NOT has_column_privilege('rss_tmsg_relay','rss_transactional_messaging.storage_lineage','lineage','UPDATE') AND has_column_privilege('rss_tmsg_relay','rss_transactional_messaging.storage_lineage','singleton','UPDATE')")
        .fetch_one(owner).await?;
    assert!(
        immutable,
        "relay may lock but must not rewrite storage identity"
    );
    let mut lock = owner.begin().await?;
    sqlx::raw_sql("SET LOCAL ROLE rss_tmsg_relay; SELECT * FROM rss_transactional_messaging.storage_lineage FOR SHARE").execute(&mut *lock).await?;
    lock.rollback().await?;
    let cases = [
        (
            true,
            "ALTER TABLE rss_transactional_messaging.dr_plans DROP CONSTRAINT dr_plan_action; ALTER TABLE rss_transactional_messaging.dr_plans ADD CONSTRAINT dr_plan_action CHECK(true)",
            "ALTER TABLE rss_transactional_messaging.dr_plans DROP CONSTRAINT dr_plan_action; ALTER TABLE rss_transactional_messaging.dr_plans ADD CONSTRAINT dr_plan_action CHECK ((((kind <> 'terminate'::text) AND (evidence IS NOT NULL) AND (target_operation IS NULL) AND (target_digest IS NULL)) OR ((kind = 'terminate'::text) AND (evidence IS NULL) AND (target_operation IS NOT NULL) AND (target_digest IS NOT NULL) AND (octet_length(target_digest) = 32))))",
        ),
        (
            true,
            "ALTER TABLE rss_transactional_messaging.dr_members DROP CONSTRAINT dr_member_block_shape; ALTER TABLE rss_transactional_messaging.dr_members ADD CONSTRAINT dr_member_block_shape CHECK(true)",
            "ALTER TABLE rss_transactional_messaging.dr_members DROP CONSTRAINT dr_member_block_shape; ALTER TABLE rss_transactional_messaging.dr_members ADD CONSTRAINT dr_member_block_shape CHECK (((status = 'blocked'::text) = (block_reason IS NOT NULL)))",
        ),
        (
            true,
            "ALTER TABLE rss_transactional_messaging.dr_members DROP CONSTRAINT dr_member_reason; ALTER TABLE rss_transactional_messaging.dr_members ADD CONSTRAINT dr_member_reason CHECK(true)",
            "ALTER TABLE rss_transactional_messaging.dr_members DROP CONSTRAINT dr_member_reason; ALTER TABLE rss_transactional_messaging.dr_members ADD CONSTRAINT dr_member_reason CHECK ((block_reason = ANY (ARRAY['deadline_expired'::text, 'permanent_publish_failure'::text])))",
        ),
        (
            false,
            "GRANT UPDATE(target) ON rss_transactional_messaging.storage_lineage TO rss_tmsg_relay",
            "REVOKE UPDATE(target) ON rss_transactional_messaging.storage_lineage FROM rss_tmsg_relay",
        ),
        (
            true,
            "GRANT UPDATE(lineage) ON rss_transactional_messaging.storage_lineage TO rss_tmsg_relay",
            "REVOKE UPDATE(lineage) ON rss_transactional_messaging.storage_lineage FROM rss_tmsg_relay",
        ),
        (
            true,
            "REVOKE UPDATE(singleton) ON rss_transactional_messaging.storage_lineage FROM rss_tmsg_relay",
            "GRANT UPDATE(singleton) ON rss_transactional_messaging.storage_lineage TO rss_tmsg_relay",
        ),
        (
            false,
            "ALTER TABLE rss_transactional_messaging.storage_lineage DROP CONSTRAINT storage_lineage_singleton_check",
            "ALTER TABLE rss_transactional_messaging.storage_lineage ADD CONSTRAINT storage_lineage_singleton_check CHECK(singleton)",
        ),
        (
            true,
            "GRANT INSERT ON rss_transactional_messaging.inbox TO dr_operator",
            "REVOKE INSERT ON rss_transactional_messaging.inbox FROM dr_operator",
        ),
        (
            true,
            "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint) TO dr_operator",
            "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint) FROM dr_operator",
        ),
        (
            false,
            "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint) TO dr_runtime",
            "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint) FROM dr_runtime",
        ),
        (
            true,
            "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.read_dr(uuid,bytea) FROM dr_operator",
            "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.read_dr(uuid,bytea) TO dr_operator",
        ),
        (
            false,
            "ALTER TABLE rss_transactional_messaging.inbox DISABLE TRIGGER execution_fence",
            "ALTER TABLE rss_transactional_messaging.inbox ENABLE TRIGGER execution_fence",
        ),
        (
            false,
            "DROP TRIGGER execution_fence ON rss_transactional_messaging.inbox; CREATE TRIGGER execution_fence BEFORE INSERT ON rss_transactional_messaging.inbox FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_execution()",
            "DROP TRIGGER execution_fence ON rss_transactional_messaging.inbox; CREATE TRIGGER execution_fence BEFORE INSERT OR UPDATE OR DELETE ON rss_transactional_messaging.inbox FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_execution()",
        ),
        (
            true,
            "ALTER TABLE rss_transactional_messaging.tenant_epoch DROP CONSTRAINT tenant_epoch_epoch_check",
            "ALTER TABLE rss_transactional_messaging.tenant_epoch ADD CONSTRAINT tenant_epoch_epoch_check CHECK(epoch>0)",
        ),
        (
            true,
            "ALTER TABLE rss_transactional_messaging.dr_members NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE rss_transactional_messaging.dr_members FORCE ROW LEVEL SECURITY",
        ),
        (
            true,
            "ALTER POLICY dr_tenant ON rss_transactional_messaging.dr_plans USING(true)",
            "ALTER POLICY dr_tenant ON rss_transactional_messaging.dr_plans USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            false,
            "ALTER FUNCTION rss_transactional_messaging.check_execution() SET search_path=public",
            "ALTER FUNCTION rss_transactional_messaging.check_execution() SET search_path=pg_catalog,rss_transactional_messaging,pg_temp",
        ),
        (
            false,
            "GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() FROM PUBLIC",
        ),
        (
            true,
            "ALTER TABLE rss_transactional_messaging.outbox RENAME claim_epoch TO broken_epoch",
            "ALTER TABLE rss_transactional_messaging.outbox RENAME broken_epoch TO claim_epoch",
        ),
    ];
    for (dr, damage, repair) in cases {
        sqlx::raw_sql(damage).execute(owner).await?;
        let rejected = if dr {
            match Box::pin(PgDrStore::connect(
                operator.clone(),
                Timer::new(),
                binding(1)?,
            ))
            .await
            {
                Ok(store) => {
                    store.close().await;
                    false
                }
                Err(e) => {
                    assert_eq!(e, Error::StorageContract);
                    true
                }
            }
        } else {
            match Box::pin(PgRuntime::connect(
                runtime.clone(),
                Timer::new(),
                binding(1)?,
            ))
            .await
            {
                Ok(store) => {
                    store.close().await;
                    false
                }
                Err(_) => true,
            }
        };
        sqlx::raw_sql(repair).execute(owner).await?;
        assert!(rejected, "probe accepted drift: {damage}");
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE usename IN ('dr_operator','dr_runtime')",
        )
        .fetch_one(owner)
        .await?;
        assert_eq!(active, 0, "failed startup closed its PostgreSQL sessions");
    }
    PgRuntime::connect(runtime.clone(), Timer::new(), binding(1)?)
        .await?
        .close()
        .await;
    PgDrStore::connect(operator.clone(), Timer::new(), binding(1)?)
        .await?
        .close()
        .await;
    Ok(())
}
