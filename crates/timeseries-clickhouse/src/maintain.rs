use crate::{
    ChStore, control,
    transaction::{bytes, decode, flatten, now, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
mod prune;
mod recompute;
const DOMAIN: &[u8] = b"rss.timeseries.clickhouse.maintenance.v1";
#[derive(Default, Serialize, Deserialize)]
struct State {
    ordinal: u64,
    fold: Option<recompute::Fold>,
    publish: Option<recompute::Publication>,
    cleanup: Option<prune::Cleanup>,
}
enum Step {
    More(u32),
    Done(u32),
    Blocked(MaintenanceBlock),
}
async fn load(c: &mut PgConnection, r: &MaintenanceRequest) -> Result<(State, bool), Error> {
    let row=sqlx::query("SELECT binding,state,complete FROM rss_ts_ch.plans WHERE tenant_id=$1::text::uuid AND namespace=$2 AND id=$3")
        .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(r.id().as_str()).fetch_optional(c).await.map_err(sql_error)?;
    let Some(row) = row else {
        return Ok((State::default(), false));
    };
    if row.try_get::<Vec<u8>, _>("binding").map_err(sql_error)? != r.binding()?.as_bytes() {
        return Err(Error::Conflict);
    }
    Ok((
        decode(&row.try_get::<Vec<u8>, _>("state").map_err(sql_error)?)?,
        row.try_get("complete").map_err(sql_error)?,
    ))
}
async fn save(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    state: &State,
    complete: bool,
    max_bytes: u32,
) -> Result<(), Error> {
    let data = bytes(state)?;
    if data.len() > max_bytes as usize {
        return Err(Error::BudgetExceeded);
    }
    sqlx::query("INSERT INTO rss_ts_ch.plans(tenant_id,namespace,id,binding,state,complete) VALUES($1::text::uuid,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,namespace,id) DO UPDATE SET state=excluded.state,complete=excluded.complete")
        .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(r.id().as_str()).bind(r.binding()?.as_bytes().as_slice()).bind(data).bind(complete).execute(c).await.map_err(sql_error)?;
    Ok(())
}
async fn simple(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    time: i64,
    max: u32,
) -> Result<Step, Error> {
    match r.action() {
        MaintenanceAction::AdvanceCutoff { selection, before } => {
            if before.micros() == 0 {
                return Ok(Step::Done(0));
            }
            let fs = control::fences(c, r.scope(), max).await?;
            if fs.iter().any(|f| {
                f.kind == "cutoff"
                    && control::covers(&f.selection, selection)
                    && control::covers(selection, &f.selection)
                    && f.window.end() > *before
            }) {
                return Err(Error::Conflict);
            }
            control::put_fence(
                c,
                r,
                "cutoff",
                selection,
                Interval::new(Timestamp::new(0)?, *before)?,
                None,
                max,
            )
            .await?;
        }
        MaintenanceAction::Delete {
            selection,
            window,
            restore_until,
        } => {
            if restore_until.micros() <= time {
                return Err(Error::InvalidInput);
            }
            control::put_fence(
                c,
                r,
                "delete",
                selection,
                *window,
                Some(restore_until.micros()),
                max,
            )
            .await?;
            control::invalidate(c, r.scope(), selection, window.start().micros(), max).await?;
        }
        MaintenanceAction::Restore {
            selection,
            window,
            deletion_fence,
        } => {
            let rows=sqlx::query("UPDATE rss_ts_ch.fences SET restored=true WHERE tenant_id=$1::text::uuid AND namespace=$2 AND id=$3 AND kind='delete' AND selection=$4::text::jsonb AND lo=$5 AND hi=$6 AND NOT restored AND restore_until>$7")
                .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(deletion_fence.as_str()).bind(String::from_utf8(bytes(selection)?).map_err(|_|Error::Invariant)?).bind(window.start().micros()).bind(window.end().micros()).bind(time).execute(&mut *c).await.map_err(sql_error)?.rows_affected();
            if rows != 1 {
                return Err(Error::HistoryExpired);
            }
            control::invalidate(c, r.scope(), selection, window.start().micros(), max).await?;
        }
        MaintenanceAction::CloseStream { stream } => {
            sqlx::query("INSERT INTO rss_ts_ch.streams(tenant_id,namespace,source,generation,closed) VALUES($1::text::uuid,$2,$3,$4,true) ON CONFLICT(tenant_id,namespace,source,generation) DO UPDATE SET closed=true")
                .bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(stream.source().as_str()).bind(stream.generation().as_str()).execute(c).await.map_err(sql_error)?;
        }
        _ => return Err(Error::Invariant),
    }
    Ok(Step::Done(1))
}
impl<C: Clock> ChStore<C> {
    async fn maintenance(
        &self,
        r: &MaintenanceRequest,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Outcome<MaintenanceProgress>, Error> {
        if r.budget().rows > self.limits.max_points || r.budget().buckets > self.limits.max_points {
            return Err(Error::BudgetExceeded);
        }
        let mut tx = self.begin(r.scope(), true, deadline).await?;
        let mut external = false;
        let result = async {
            let (mut state, complete) = load(tx.connection(), r).await?;
            let time = now(tx.connection()).await?;
            let ordinal = after
                .map(|t| {
                    self.key
                        .open::<u64>(DOMAIN, t, r.binding()?, &self.instance, time)
                })
                .transpose()?
                .map(|(_, n)| n);
            if ordinal.is_some_and(|n| n > state.ordinal) {
                return Err(Error::InvalidCursor);
            }
            if complete {
                return Ok(Outcome::Replay(MaintenanceProgress::Complete {
                    processed: 0,
                    fence: r.id().clone(),
                }));
            }
            let expires = time
                .checked_add(self.limits.cursor_micros.get() as i64)
                .ok_or(Error::NumericRange)?;
            if ordinal.is_some_and(|n| n < state.ordinal) {
                return Ok(Outcome::Replay(MaintenanceProgress::More {
                    processed: 0,
                    next: self.key.seal(
                        DOMAIN,
                        r.binding()?,
                        &self.instance,
                        expires,
                        &state.ordinal,
                    )?,
                }));
            }
            if control::pending(tx.connection(), r.scope()).await? {
                return Ok(Outcome::Accepted(MaintenanceProgress::Blocked {
                    reason: MaintenanceBlock::PendingWrite,
                }));
            }
            external = state.publish.is_some() || state.cleanup.is_some();
            let revision = tx.revision;
            let boundary = tx.published;
            let step = match r.action() {
                MaintenanceAction::Recompute { .. } => {
                    recompute::step(
                        self,
                        tx.connection(),
                        r,
                        &mut state,
                        revision,
                        boundary,
                        deadline,
                    )
                    .await?
                }
                MaintenanceAction::Prune { .. } => {
                    prune::step(
                        self,
                        tx.connection(),
                        r,
                        &mut state,
                        boundary,
                        time,
                        deadline,
                    )
                    .await?
                }
                MaintenanceAction::ExpireReceipts { stream, before } => {
                    expire(
                        tx.connection(),
                        stream,
                        *before,
                        r.budget().rows.get(),
                        time,
                    )
                    .await?
                }
                MaintenanceAction::Reclaim { stream } => {
                    prune::reclaim(
                        self,
                        tx.connection(),
                        stream,
                        r.budget().rows.get(),
                        time,
                        deadline,
                    )
                    .await?
                }
                _ => simple(tx.connection(), r, time, self.limits.max_points.get()).await?,
            };
            let complete = matches!(step, Step::Done(_));
            let progress = match step {
                Step::Blocked(reason) => {
                    return Ok(Outcome::Accepted(MaintenanceProgress::Blocked { reason }));
                }
                Step::Done(processed) => MaintenanceProgress::Complete {
                    processed,
                    fence: r.id().clone(),
                },
                Step::More(processed) => {
                    state.ordinal = state.ordinal.checked_add(1).ok_or(Error::NumericRange)?;
                    MaintenanceProgress::More {
                        processed,
                        next: self.key.seal(
                            DOMAIN,
                            r.binding()?,
                            &self.instance,
                            expires,
                            &state.ordinal,
                        )?,
                    }
                }
            };
            save(
                tx.connection(),
                r,
                &state,
                complete,
                self.limits.max_bytes.get(),
            )
            .await?;
            Ok(Outcome::Accepted(progress))
        }
        .await;
        match tx.finish(result, true).await {
            Ok(v) => Ok(flatten(v)),
            Err(_) if external => Ok(Outcome::Unknown),
            Err(e) => Err(e),
        }
    }
}
impl<C: Clock> Maintainer for ChStore<C> {
    async fn step(
        &self,
        r: &Authorized<MaintenanceRequest>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Outcome<MaintenanceProgress>, Error> {
        let _guard = self.operation(r.request().scope(), deadline).await?;
        self.mutation(deadline, self.maintenance(r.request(), after, deadline))
            .await
    }
}
async fn expire(
    c: &mut PgConnection,
    s: &Stream,
    before: Timestamp,
    limit: u32,
    time: i64,
) -> Result<Step, Error> {
    let count=sqlx::query("UPDATE rss_ts_ch.batches SET expired=true WHERE ctid IN (SELECT ctid FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND published AND NOT expired AND received_at<$5 AND replay_until<=$6 ORDER BY received_at LIMIT $7)")
        .bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).bind(before.micros()).bind(time).bind(i64::from(limit)).execute(&mut *c).await.map_err(sql_error)?.rows_affected();
    if count == u64::from(limit) {
        return Ok(Step::More(limit));
    }
    let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM rss_ts_ch.batches WHERE tenant_id=$1::text::uuid AND namespace=$2 AND source=$3 AND generation=$4 AND NOT expired AND received_at<$5)")
        .bind(s.scope().tenant().to_string()).bind(s.scope().namespace().as_str()).bind(s.source().as_str()).bind(s.generation().as_str()).bind(before.micros()).fetch_one(c).await.map_err(sql_error)?;
    Ok(if blocked {
        Step::Blocked(MaintenanceBlock::ReplayGuarantee)
    } else {
        Step::Done(u32::try_from(count).map_err(|_| Error::Invariant)?)
    })
}
