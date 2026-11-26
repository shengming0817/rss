use super::*;
use sqlx::{Postgres, postgres::PgArguments, query::Query};

struct BatchFacts {
    positions: Vec<i64>,
    ids: Vec<String>,
    digests: Vec<[u8; 32]>,
}

impl BatchFacts {
    async fn collect<T: Timer>(
        events: &[impl AsRef<Event>],
        scope: &ProjectionScope,
        mut previous: Option<Position>,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        let n = events.len();
        BatchLimit::new(u32::try_from(n).map_err(|_| Error::new(ErrorKind::InvalidInput))?)?;
        let mut facts = Self {
            positions: Vec::with_capacity(n),
            ids: Vec::with_capacity(n),
            digests: Vec::with_capacity(n),
        };
        for item in events {
            let event = item.as_ref();
            control.check()?;
            if event.source() != scope.source() {
                return Err(Error::new(ErrorKind::ScopeMismatch));
            }
            if previous.is_some_and(|p| event.position() <= p) {
                return Err(Error::new(ErrorKind::OutOfOrder));
            }
            previous = Some(event.position());
            facts.positions.push(event.position().get() as i64);
            facts.ids.push(event.id().to_owned());
            facts.digests.push(event.fingerprint());
            tokio::task::consume_budget().await;
        }
        Ok(facts)
    }

    fn query<'a>(
        &'a self,
        sql: &'static str,
        claim: &'a PgClaim,
        expected: Option<Position>,
    ) -> Query<'a, Postgres, PgArguments> {
        let s = &claim.scope;
        sqlx::query(sql)
            .bind(s.source().tenant().to_string())
            .bind(s.source().source())
            .bind(s.projection())
            .bind(s.generation())
            .bind(claim.epoch)
            .bind(claim.token.to_string())
            .bind(encode_position(expected))
            .bind(self.positions.as_slice())
            .bind(self.ids.as_slice())
            .bind(self.digests.as_slice())
            .bind(claim.definition.as_bytes().as_slice())
    }
}

impl<H: PgEffect + 'static> BatchExecution for PgProjection<H> {
    async fn execute_batch<T: Timer>(
        &self,
        expected: Option<Position>,
        events: Vec<H::Item>,
        control: &Control<'_, T>,
    ) -> Result<Vec<ApplyOutcome>, Error> {
        let facts = BatchFacts::collect(&events, self.scope(), expected, control).await?;
        let claim = self.claim.clone();
        let effect = self.effect.clone();
        self.store
            .controlled_tx(self.scope().source(), control, move |tx| {
                Box::pin(async move {
                    let duplicates: Vec<bool> = facts
                        .query("SELECT rss_projection.lock_batch($1::uuid,$2,$3,$4,$5,$6::uuid,$7,$8,$9,$10,$11)", &claim, expected)
                        .fetch_one(&mut *tx.connection).await.map_err(map_sql)?
                        .try_get(0).map_err(map_sql)?;
                    if duplicates.len() != events.len() {
                        return Err(Error::new(ErrorKind::StorageContract));
                    }
                    let mut outcomes = Vec::with_capacity(events.len());
                    for (event, duplicate) in events.into_iter().zip(duplicates) {
                        outcomes.push(apply_event(tx, &claim, effect.as_ref(), &event, duplicate).await?);
                    }
                    tx.check()?;
                    let settled: Option<bool> = facts.query("SELECT rss_projection.finish_batch($1::uuid,$2,$3,$4,$5,$6::uuid,$7,$8,$9,$10,$11)", &claim, expected)
                        .fetch_one(&mut *tx.connection).await.map_err(map_sql)?.try_get(0).map_err(map_sql)?;
                    if settled != Some(true) {
                        return Err(Error::new(ErrorKind::StorageContract));
                    }
                    Ok(outcomes)
                })
            })
            .await
    }
}
