//! Admission, replay and physical reclamation share the tenant-serialized Profile write.
use super::*;
use transaction::MutationError;

const FIRST_USE_MS: i64 = 5 * 60 * 1000;
const FUTURE_SKEW_MS: i64 = 30_000;
const RETENTION_MS: i64 = 24 * 60 * 60 * 1000;

struct ReceiptClock(i64);

impl ReceiptClock {
    // A lookup may commit a time floor too. Sample only after obtaining its final lock.
    async fn load(c: &mut PgConnection, tenant: TenantId) -> Result<Self, MutationError> {
        sqlx::query("SELECT value FROM identity_authority.tenant_state WHERE tenant_id=$1::uuid AND kind='receipt_clock' FOR UPDATE")
            .bind(tenant.to_string()).fetch_one(&mut *c).await?;
        Ok(Self(sqlx::query_scalar(
            "SELECT greatest(value, floor(extract(epoch FROM clock_timestamp())*1000)::bigint)
             FROM identity_authority.tenant_state WHERE tenant_id=$1::uuid AND kind='receipt_clock'",
        ).bind(tenant.to_string()).fetch_one(c).await?))
    }

    fn cutoff(&self) -> i64 {
        self.0 - RETENTION_MS
    }

    fn permits_first_use(&self, id: ProfileOperationId) -> Result<bool, MutationError> {
        let age = self.0 - id.unix_millis();
        if age < -FUTURE_SKEW_MS {
            return Err(MutationError::InvalidInput);
        }
        Ok(age < FIRST_USE_MS)
    }

    async fn persist(&self, c: &mut PgConnection, tenant: TenantId) -> Result<(), MutationError> {
        sqlx::query(
            "UPDATE identity_authority.tenant_state SET value=$2
                     WHERE tenant_id=$1::uuid AND kind='receipt_clock' AND value<$2",
        )
        .bind(tenant.to_string())
        .bind(self.0)
        .execute(c)
        .await?;
        Ok(())
    }
}

async fn reclaim(
    c: &mut PgConnection,
    target: AccountKey,
    cutoff: i64,
    reclaimed_through: i64,
) -> Result<i64, MutationError> {
    // Seek beyond the last deleted prefix even when another snapshot pins its index tuples.
    let oldest: Option<i64> = sqlx::query_scalar(include_str!("oldest_receipt.sql"))
        .bind(target.tenant.to_string())
        .bind(target.principal.as_uuid())
        .bind(reclaimed_through)
        .fetch_optional(&mut *c)
        .await?;
    if oldest.is_none_or(|accepted| accepted > cutoff) {
        return Ok(reclaimed_through);
    }
    Ok(sqlx::query_scalar(include_str!("reclaim_receipts.sql"))
        .bind(target.tenant.to_string())
        .bind(target.principal.as_uuid())
        .bind(cutoff)
        .bind(reclaimed_through)
        .fetch_one(c)
        .await?)
}

impl Authority {
    pub async fn update_local_profile(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        change: ProfileChange,
        deadline: OperationDeadline,
    ) -> Result<ProfileReceipt, AuthorityError> {
        self.require_runtime()?;
        let after = change
            .value
            .as_ref()
            .map(LocalProfile::observation)
            .transpose()
            .map_err(|_| AuthorityError::InvalidInput)?
            .unwrap_or_else(Profile::missing);
        if target.tenant != actor.key.tenant || change.expected_revision < 0 {
            return Err(AuthorityError::InvalidInput);
        }
        let digest = rss_identity_core::federation::digest(
            &serde_json::to_string(&change).map_err(|_| AuthorityError::InvalidInput)?,
        );
        let capacity = i64::from(self.profile_receipt_capacity.get());
        let policy = self.policy.clone();
        let instance = self.instance;
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.shortened_to(actor.expires);
        self.conditional_write_sql(actor.binding, budget.remaining(), move |c| Box::pin(async move {
            let loaded = crate::session_storage::recheck_for(c, &actor, crate::session_storage::SessionAccess::ProfileWrite(target)).await?;
            crate::management::authorize(policy.as_ref(), instance, &loaded,
                ManagementOperation::UpdateLocalProfile, Some(target), c).await?;
            if !account_state_locked(c, target).await?.active() {
                return Err(reject().into());
            }
            let clock = ReceiptClock::load(c, target.tenant).await?;
            if Instant::now() >= loaded.expires { return Err(reject().into()); }
            let id = change.operation_id;
            if let Some(row) = sqlx::query(
                include_str!("replay_receipt.sql"),
            ).bind(target.tenant.to_string()).bind(id.as_uuid()).bind(clock.cutoff()).fetch_optional(&mut *c).await? {
                if row.try_get::<Uuid,_>("principal_id")? != target.principal.as_uuid()
                    || row.try_get::<Uuid,_>("actor")? != actor.key.principal.as_uuid()
                    || row.try_get::<Vec<u8>,_>("digest")? != digest {
                    return Err(MutationError::OperationConflict);
                }
                return Ok((Ok(ProfileReceipt { operation_id: id, revision: row.try_get("revision")? }), vec![]));
            }
            if !clock.permits_first_use(id)? {
                // Expiry is observable only after its time floor commits.
                clock.persist(c, target.tenant).await?;
                return Ok((Err(AuthorityError::ProfileOperationExpired), vec![]));
            }
            let (old, reclaimed_through) = load_local_profile(c, target).await?;
            // Each committed revision earns one receipt. The live revisions form a suffix.
            if old.revision >= capacity && sqlx::query_scalar::<_,bool>(include_str!("receipt_capacity.sql"))
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid())
                .bind(old.revision - capacity + 1).bind(clock.cutoff()).fetch_one(&mut *c).await? {
                return Err(MutationError::ProfileReceiptCapacityReached);
            }
            if old.revision != change.expected_revision { return Err(MutationError::RevisionConflict); }
            let revision = old.revision.checked_add(1).ok_or_else(corrupt)?;
            let before = old.value.as_ref().map(LocalProfile::observation).transpose().map_err(|_| corrupt())?;
            let mut changed_fields = changes(before.as_ref(), &after);
            if old.value.as_ref().map(|v| v.max_age_seconds) != change.value.as_ref().map(|v| v.max_age_seconds) {
                changed_fields.push("maxAgeSeconds");
            }
            let value = change.value.map(serde_json::to_value).transpose().map_err(|_| corrupt())?;
            clock.persist(c, target.tenant).await?;
            let reclaimed_through = reclaim(c, target, clock.cutoff(), reclaimed_through).await?;
            sqlx::query("INSERT INTO identity_authority.local_profiles(tenant_id,principal_id,revision,value,reclaimed_through)
                         VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT(tenant_id,principal_id)
                         DO UPDATE SET revision=excluded.revision,value=excluded.value,reclaimed_through=excluded.reclaimed_through")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(revision)
                .bind(value).bind(reclaimed_through).execute(&mut *c).await?;
            sqlx::query("INSERT INTO identity_authority.profile_operations(tenant_id,operation_id,principal_id,actor,digest,revision,accepted_at_ms)
                         VALUES($1::uuid,$2,$3,$4,$5,$6,$7)")
                .bind(target.tenant.to_string()).bind(id.as_uuid()).bind(target.principal.as_uuid())
                .bind(actor.key.principal.as_uuid()).bind(digest.as_slice()).bind(revision).bind(clock.0).execute(c).await?;
            if Instant::now() >= loaded.expires {return Err(reject().into());}
            Ok((Ok(ProfileReceipt { operation_id: id, revision }), vec![event(target, Some(actor.key),
                "local_updated", ProfileSource::IdentityLocal, None, Some(revision), changed_fields)]))
        })).await?
    }

    pub async fn local_profile_receipt(
        &self,
        actor: &AuthenticatedSession,
        target: AccountKey,
        operation: ProfileOperationId,
        deadline: OperationDeadline,
    ) -> Result<Option<ProfileReceipt>, AuthorityError> {
        self.require_runtime()?;
        let reader = Reader::new(actor)?;
        let policy = self.policy.clone();
        let instance = self.instance;
        if target.tenant != reader.key.tenant {
            return Err(AuthorityError::Rejected);
        }
        self.read_sql(actor.binding, deadline, move |c| Box::pin(async move {
            let loaded = reader.recheck_with(c,Some(crate::session_storage::SessionAccess::Inspect)).await?;
            crate::management::authorize(policy.as_ref(), instance, &loaded,
                ManagementOperation::UpdateLocalProfile, Some(target), c).await?;
            let clock = ReceiptClock::load(c, target.tenant).await?;
            if Instant::now() >= loaded.expires { return Err(reject().into()); }
            let revision: Option<i64> = sqlx::query_scalar("SELECT revision FROM identity_authority.profile_operations
                WHERE tenant_id=$1::uuid AND principal_id=$2 AND actor=$3 AND operation_id=$4 AND accepted_at_ms>$5")
                .bind(target.tenant.to_string()).bind(target.principal.as_uuid()).bind(reader.key.principal.as_uuid())
                .bind(operation.as_uuid()).bind(clock.cutoff()).fetch_optional(&mut *c).await?;
            if let Some(revision) = revision {
                return Ok(Ok(Some(ProfileReceipt { operation_id: operation, revision })));
            }
            if clock.permits_first_use(operation)? { return Ok(Ok(None)); }
            clock.persist(c, target.tenant).await?;
            Ok(Err(AuthorityError::ProfileOperationExpired))
        })).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_boundaries_and_uuid_variant_are_exact() {
        let ms = 1_800_000_000_000;
        let uuid = Uuid::new_v7(uuid::Timestamp::from_unix(uuid::NoContext, ms / 1000, 0));
        let id = ProfileOperationId::try_from(uuid).unwrap();
        let ms = ms as i64;
        assert!(
            ReceiptClock(ms - FUTURE_SKEW_MS)
                .permits_first_use(id)
                .unwrap()
        );
        assert!(
            ReceiptClock(ms - FUTURE_SKEW_MS - 1)
                .permits_first_use(id)
                .is_err()
        );
        assert!(
            ReceiptClock(ms + FIRST_USE_MS - 1)
                .permits_first_use(id)
                .unwrap()
        );
        assert!(
            !ReceiptClock(ms + FIRST_USE_MS)
                .permits_first_use(id)
                .unwrap()
        );
        for invalid in [
            Uuid::nil(),
            Uuid::new_v4(),
            Uuid::from_u128(uuid.as_u128() & !(3 << 62)),
        ] {
            assert!(
                serde_json::from_value::<ProfileOperationId>(serde_json::json!(invalid)).is_err()
            );
        }
    }
}
