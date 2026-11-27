//! Same-transaction companion to transactional messaging; caller owns settlement.
use crate::persistence::*;
use rss_device_command::*;
use rss_transactional_messaging::outbox::OutboxWriter;
use rss_transactional_messaging_postgres::{PgError, PgOutboxWriter, PgTransaction};


/// Device commands sharing the supplied transaction with the existing message adapter.
pub struct PgStore {
    outbox: PgOutboxWriter,
    clock: crate::CommandClock,
    supersede_batch_size: BatchLimit,
}
impl PgStore {
    /// Validate component storage/role on the caller's configured transaction.
    /// All later transactions must use this same database and runtime role.
    /// `supersede_batch_size` bounds each page within one atomic authority transaction.
    /// `callers` declares the complete component caller set, including this runtime's login.
    pub async fn new(
        tx: &mut PgTransaction<'_>,
        outbox: PgOutboxWriter,
        clock: crate::CommandClock,
        callers: &crate::CallerRoles,
        supersede_batch_size: BatchLimit,
    ) -> Result<Self, PgError> {
        outbox.validate_transaction(tx)?;
        crate::probe::validate(tx, callers).await?;
        Ok(Self {
            outbox,
            clock,
            supersede_batch_size,
        })
    }
    /// Read this store's authoritative command time in Unix microseconds.
    /// The transaction must belong to the admitted runtime, even with an integration clock.
    pub async fn now(&self, tx: &mut PgTransaction<'_>) -> Result<i64, PgError> {
        self.outbox.validate_transaction(tx)?;
        self.clock.now(tx).await
    }
    async fn recover_rows<'a>(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Scope,
        current: Coordinate,
        rows: impl Iterator<Item = &'a mut Command>,
    ) -> Result<(), PgError> {
        let active: Vec<_> = rows.filter(|r| !r.status().is_terminal()).collect();
        if active.is_empty() {
            return Ok(());
        }
        let observed = self.now(tx).await?;
        let needs_confirmation = |cmd: &Command| cmd.status() == Status::Queued
            && cmd.spec().coordinate() == current && observed < cmd.spec().deadline()
            && matches!(cmd.record().delivery, Delivery::Outbox(_));
        let requested: Vec<_> = active.iter().filter(|cmd| needs_confirmation(cmd)).filter_map(|cmd| {
            match &cmd.record().delivery {
                Delivery::Outbox(facts) => Some((&facts.domain, &facts.message_id, facts.fingerprint)),
                Delivery::Direct { .. } => None,
            }
        }).collect();
        let mut facts = self
            .outbox
            .publication_states(tx, &requested)
            .await?
            .into_iter();
        // Confirmation may wait on storage across the command deadline.
        let confirmed_at = if facts.len() > 0 {
            self.now(tx).await?
        } else {
            observed
        };
        let mut changes = PageChanges::default();
        for row in active {
            let event = if needs_confirmation(row) {
                let published = facts.next().ok_or_else(|| error(Error::InvalidSnapshot))?;
                if published {
                    Event::Published
                } else {
                    Event::Expire
                }
            } else if current != row.spec().coordinate() {
                Event::Supersede
            } else {
                Event::Expire
            };
            let command = row;
            let previous = command.version();
            let outcome = command
                .transition(event, current, confirmed_at)
                .map_err(error)?;
            if matches!(outcome, Outcome::OutOfOrder | Outcome::Late) {
                return Err(error(Error::InvalidSnapshot));
            }
            changes.push(command, previous);
        }
        changes.save(tx, scope).await
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
        let current = authority(tx, s, false).await?;
        if coordinate != current {
            return Err(error(Error::Fenced));
        }
        let mut command = locked_command(tx, s, id).await?;
        let previous = command.version();
        let outcome = command
            .transition(event, current, self.now(tx).await?)
            .map_err(error)?;
        save(tx, &command, previous).await?;
        Ok(Transition {
            outcome,
            command,
        })
    }
}
impl Store for PgStore {
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
        if authority(tx, s, false).await? != coordinate {
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
        let current = authority(tx, s, true).await?;
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
        crate::supersede::active_commands(tx, s, next, self.supersede_batch_size, &self.clock).await
    }
    async fn queue(
        &self,
        tx: &mut Self::Transaction<'_>,
        spec: CommandSpec,
        delivery: Delivery,
    ) -> Result<Command, PgError> {
        self.outbox.validate_transaction(tx)?;
        let current = authority(tx, spec.scope(), false).await?;
        if let Delivery::Outbox(message) = &delivery
            && message.envelope().metadata().tenant_id() != spec.scope().tenant() {
            return Err(error(Error::Fenced));
        }
        lock_creation(tx, &spec).await?;
        let identity = delivery.identity();
        if let Some(existing) = read(tx,spec.scope(),spec.id()).await? {
            if existing.spec()!= &spec || existing.record().delivery != identity {
                return Err(error(Error::Conflict));
            }
            if let Delivery::Outbox(original) = &identity {
                self.outbox.is_published(tx,&original.domain,&original.message_id,original.fingerprint).await?;
            }
            return Ok(existing);
        }
        if current != spec.coordinate() { return Err(error(Error::Fenced)); }
        let command = Command::queue(spec,identity,self.now(tx).await?).map_err(error)?;
        insert_command(tx,&command).await?;
        if let Delivery::Outbox(message) = delivery {
            self.outbox.append(tx,message).await.map_err(PgError::from)?;
        }
        Ok(command)
    }
    async fn claim_direct(
        &self, tx: &mut Self::Transaction<'_>, s: Scope, id: &CommandId, coordinate: Coordinate, claim: ClaimId
    ) -> Result<DirectClaim,PgError> {
        let transition=self.mutate(tx,s,id,Event::Claim(claim),coordinate).await?;
        if transition.command.status()== Status::Claimed {
            Ok(DirectClaim::Eligible(transition.command))
        } else {
            Ok(DirectClaim::Unavailable(transition.command))
        }
    }
    async fn load(
        &self,
        tx: &mut Self::Transaction<'_>,
        s: Scope,
        id: &CommandId,
    ) -> Result<Option<Command>, PgError> {
        self.outbox.validate_transaction(tx)?;
        read(tx, s, id).await
    }
    async fn report(
        &self,
        tx: &mut Self::Transaction<'_>,
        input: &DeviceReport,
    ) -> Result<Transition, PgError> {
        self.outbox.validate_transaction(tx)?;
        let current = authority(tx, input.scope, false).await?;
        let mut command = locked_command(tx, input.scope, &input.command_id).await?;
        let previous = command.version();
        let outcome = command
            .report(input, current, self.now(tx).await?)
            .map_err(error)?;
        save(tx, &command, previous).await?;
        Ok(Transition {
            outcome,
            command,
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
        let current = authority(tx, s, false).await?;
        let mut rows = active_rows(tx, s, after.map(CommandId::as_str), limit, false)
            .await?
            .into_iter()
            .map(decode)
            .collect::<Result<Vec<_>, _>>()?;
        self.recover_rows(tx, s, current, rows.iter_mut()).await?;
        let commands = rows;
        let after = commands.last().map(|c| c.spec().id().clone());
        Ok(RecoveryPage { commands, after })
    }
    async fn recover_exact(
        &self,
        tx: &mut Self::Transaction<'_>,
        s: Scope,
        ids: ExactCommandIds<'_>,
    ) -> Result<Vec<Option<Command>>, PgError> {
        self.outbox.validate_transaction(tx)?;
        let current = authority(tx, s, false).await?;
        let mut rows = exact_rows(tx, s, ids).await?;
        self.recover_rows(tx, s, current, rows.iter_mut().flatten())
            .await?;
        Ok(rows)
    }
}
