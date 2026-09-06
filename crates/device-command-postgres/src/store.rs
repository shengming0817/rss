//! Same-transaction companion to transactional messaging; caller owns settlement.
use crate::persistence::*;
use rss_device_command::*;
use rss_transactional_messaging::outbox::{OutboxStore, PendingMessage};
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore, PgTransaction};
use std::sync::Arc;

/// Device commands sharing the supplied transaction with the existing message adapter.
pub struct PgStore<R> {
    outbox: Arc<PgOutboxStore<R>>,
}
impl<R: Send> PgStore<R> {
    /// Validate component storage/role on the caller's configured transaction.
    /// All later transactions must use this same database and runtime role.
    pub async fn new(
        tx: &mut PgTransaction<'_>,
        outbox: Arc<PgOutboxStore<R>>,
    ) -> Result<Self, PgError> {
        outbox.validate_transaction(tx)?;
        let failure: Option<String> = tx
            .with_connection(|c| {
                Box::pin(async move {
                    sqlx::query_scalar(include_str!("probe.sql"))
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        if let Some(raw) = failure {
            let reason = match raw.as_str() {
                "revision" => "revision",
                "runtime_role" => "runtime_role",
                "runtime_acl" => "runtime_acl",
                "rls_policy" => "rls_policy",
                "functions" => "functions",
                _ => "unknown",
            };
            tracing::warn!(
                phase = "probe",
                reason,
                "device command storage contract rejected"
            );
            return Err(error(Error::InvalidSnapshot));
        }
        Ok(Self { outbox })
    }
    async fn mutate(
        &self,
        tx: &mut PgTransaction<'_>,
        s: Scope,
        id: &CommandId,
        event: Event,
        coordinate: Coordinate,
    ) -> Result<Transition, PgError> {
        self.outbox.validate_transaction(tx)?;
        let current = authority(tx, s).await?;
        if coordinate != current {
            return Err(error(Error::Fenced));
        }
        let mut stored = read(tx, s, id).await?.ok_or_else(|| error(Error::Fenced))?;
        let previous = stored.command.version();
        let outcome = stored
            .command
            .transition(event, current, now(tx).await?)
            .map_err(error)?;
        save(tx, &stored.command, previous).await?;
        Ok(Transition {
            outcome,
            command: stored.command,
        })
    }
}
impl<R: Send> Store for PgStore<R> {
    type Transaction<'a> = PgTransaction<'a>;
    type Error = PgError;
    async fn initialize(
        &self,
        tx: &mut Self::Transaction<'_>,
        s: Scope,
        coordinate: Coordinate,
    ) -> Result<(), PgError> {
        self.outbox.validate_transaction(tx)?;
        scope(tx, s)?;
        let t = s.tenant().to_string();
        let d = s.device().as_uuid().to_string();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("SELECT rss_device_command.initialize($1::uuid,$2::uuid,$3,$4)")
                    .bind(t)
                    .bind(d)
                    .bind(coordinate.generation())
                    .bind(coordinate.epoch())
                    .execute(c)
                    .await
                    .map(|_| ())
            })
        })
        .await?;
        if authority(tx, s).await? != coordinate {
            return Err(error(Error::Conflict));
        }
        Ok(())
    }
    async fn advance(
        &self,
        tx: &mut Self::Transaction<'_>,
        s: Scope,
        expected: Coordinate,
        next: Coordinate,
    ) -> Result<(), PgError> {
        if !next.supersedes(expected) {
            return Err(error(Error::InvalidValue));
        }
        self.outbox.validate_transaction(tx)?;
        let current = authority(tx, s).await?;
        if current == next {
            return Ok(());
        } // reason: exact authority update replay cannot produce more effects.
        if current != expected {
            return Err(error(Error::Fenced));
        }
        let t = s.tenant().to_string();
        let d = s.device().as_uuid().to_string();
        let changed: bool = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT rss_device_command.advance($1::uuid,$2::uuid,$3,$4,$5,$6)",
                    )
                    .bind(t)
                    .bind(d)
                    .bind(expected.generation())
                    .bind(expected.epoch())
                    .bind(next.generation())
                    .bind(next.epoch())
                    .fetch_one(c)
                    .await
                })
            })
            .await?;
        if !changed {
            return Err(error(Error::Fenced));
        }
        // Each page is bounded in memory. One enclosing transaction/deadline covers the full authority change.
        loop {
            let rows = page(tx, s, None, 64).await?;
            if rows.is_empty() {
                break;
            }
            for mut row in rows {
                let previous = row.command.version();
                let outcome = row
                    .command
                    .transition(Event::Supersede, next, now(tx).await?)
                    .map_err(error)?;
                if outcome != Outcome::Advanced {
                    return Err(error(Error::InvalidSnapshot));
                }
                save(tx, &row.command, previous).await?;
            }
        }
        Ok(())
    }
    async fn queue(
        &self,
        tx: &mut Self::Transaction<'_>,
        spec: CommandSpec,
        message: PendingMessage<Vec<u8>>,
    ) -> Result<Command, PgError> {
        self.outbox.validate_transaction(tx)?;
        let current = authority(tx, spec.scope()).await?;
        let envelope = message.envelope();
        if envelope.metadata().tenant_id() != spec.scope().tenant() {
            return Err(error(Error::Fenced));
        }
        if let Some(existing) = read(tx, spec.scope(), spec.id()).await? {
            if existing.command.spec() != &spec
                || existing.message_id != *envelope.id()
                || existing.fingerprint != message.fingerprint()
                || existing.domain != *envelope.metadata().domain()
            {
                return Err(error(Error::Conflict));
            }
            // Verify the exact original dispatch even when authority has since advanced.
            self.outbox
                .is_published(
                    tx,
                    &existing.domain,
                    &existing.message_id,
                    existing.fingerprint,
                )
                .await?;
            return Ok(existing.command);
        }
        if current != spec.coordinate() {
            return Err(error(Error::Fenced));
        }
        let command = Command::queue(spec, now(tx).await?).map_err(error)?;
        let r = command.record();
        let s = r.spec.scope();
        let t = s.tenant().to_string();
        let d = s.device().as_uuid().to_string();
        let id = r.spec.id().as_str().to_owned();
        let coord = r.spec.coordinate();
        let digest = r.spec.expected().as_bytes().to_vec();
        let deadline = r.spec.deadline();
        let queued = r.queued_at;
        let message_id = envelope.id().as_str().to_owned();
        let domain = envelope.metadata().domain().as_str().to_owned();
        let fingerprint = message.fingerprint().as_bytes().to_vec();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    "SELECT rss_device_command.enqueue($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                )
                .bind(t)
                .bind(d)
                .bind(id)
                .bind(coord.generation())
                .bind(coord.epoch())
                .bind(digest)
                .bind(deadline)
                .bind(queued)
                .bind(message_id)
                .bind(fingerprint)
                .bind(domain)
                .execute(c)
                .await
                .map(|_| ())
            })
        })
        .await?;
        self.outbox
            .append(tx, message)
            .await
            .map_err(PgError::from)?;
        Ok(command)
    }
    async fn load(
        &self,
        tx: &mut Self::Transaction<'_>,
        s: Scope,
        id: &CommandId,
    ) -> Result<Option<Command>, PgError> {
        self.outbox.validate_transaction(tx)?;
        Ok(read(tx, s, id).await?.map(|r| r.command))
    }
    async fn report(
        &self,
        tx: &mut Self::Transaction<'_>,
        input: &DeviceReport,
    ) -> Result<Transition, PgError> {
        self.outbox.validate_transaction(tx)?;
        let current = authority(tx, input.scope).await?;
        let mut row = read(tx, input.scope, &input.command_id)
            .await?
            .ok_or_else(|| error(Error::Fenced))?;
        let previous = row.command.version();
        let outcome = row
            .command
            .report(input, current, now(tx).await?)
            .map_err(error)?;
        save(tx, &row.command, previous).await?;
        Ok(Transition {
            outcome,
            command: row.command,
        })
    }
    async fn cancel(
        &self,
        tx: &mut Self::Transaction<'_>,
        s: Scope,
        id: &CommandId,
        coordinate: Coordinate,
    ) -> Result<Transition, PgError> {
        self.mutate(tx, s, id, Event::Cancel, coordinate).await
    }
    async fn recover(
        &self,
        tx: &mut Self::Transaction<'_>,
        s: Scope,
        limit: BatchLimit,
        after: Option<&CommandId>,
    ) -> Result<RecoveryPage, PgError> {
        self.outbox.validate_transaction(tx)?;
        let current = authority(tx, s).await?;
        let rows = page(tx, s, after, i64::from(limit.get())).await?;
        let mut commands = Vec::with_capacity(rows.len());
        for mut row in rows {
            let previous = row.command.version();
            let time = now(tx).await?;
            let event = if current != row.command.spec().coordinate() {
                Event::Supersede
            } else if time >= row.command.spec().deadline() {
                Event::Expire
            } else if row.command.status() == Status::Queued
                && self
                    .outbox
                    .is_published(tx, &row.domain, &row.message_id, row.fingerprint)
                    .await?
            {
                Event::Published
            } else {
                Event::Expire
            }; // reason: Expire before the deadline is the reducer's explicit no-op.
            let outcome = row
                .command
                .transition(event, current, now(tx).await?)
                .map_err(error)?;
            if matches!(outcome, Outcome::OutOfOrder | Outcome::Late) {
                return Err(error(Error::InvalidSnapshot));
            }
            save(tx, &row.command, previous).await?;
            commands.push(row.command);
        }
        let after = commands.last().map(|c| c.spec().id().clone());
        Ok(RecoveryPage { commands, after })
    }
}
