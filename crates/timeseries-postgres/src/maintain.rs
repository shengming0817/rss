use crate::{
    Limits, PgStore,
    lifecycle::{bytes, json, lock, put_fence},
    transaction::{check, db_now, sql_error},
};
use rss_request_context::{Clock, Deadline};
use rss_timeseries::*;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
mod prune;
mod recompute;
const DOMAIN: &[u8] = b"rss.timeseries.maintenance.v2";
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct State {
    ordinal: u64,
    fold: Option<recompute::Fold>,
    raw_limit: Option<i64>,
}
enum Step {
    More(u32),
    Done(u32),
    Blocked(MaintenanceBlock),
}
async fn load(c: &mut PgConnection, r: &MaintenanceRequest) -> Result<(State, bool), Error> {
    let row=sqlx::query("SELECT binding,state,done FROM rss_timeseries.plans WHERE tenant_id=$1::text::uuid AND namespace=$2 AND id=$3").bind(r.scope().tenant().to_string()).bind(r.scope().namespace().as_str()).bind(r.id().as_str()).fetch_optional(c).await.map_err(sql_error)?;
    let Some(row) = row else {
        return Ok((State::default(), false));
    };
    if row.try_get::<Vec<u8>, _>("binding").map_err(sql_error)? != r.binding()?.as_bytes() {
        return Err(Error::Conflict);
    }
    let state = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("state").map_err(sql_error)?)
        .map_err(|_| Error::Invariant)?;
    Ok((state, row.try_get("done").map_err(sql_error)?))
}
async fn save(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    state: &State,
    done: bool,
    limits: &Limits,
) -> Result<(), Error> {
    let data = bytes(state)?;
    if data.len() > limits.max_bytes.get() as usize {
        return Err(Error::BudgetExceeded);
    }
    sqlx::query("SELECT rss_timeseries.put_plan($1::text::uuid,$2,$3,$4,$5,$6)")
        .bind(r.scope().tenant().to_string())
        .bind(r.scope().namespace().as_str())
        .bind(r.id().as_str())
        .bind(r.binding()?.as_bytes().as_slice())
        .bind(data)
        .bind(done)
        .execute(c)
        .await
        .map_err(sql_error)?;
    Ok(())
}
async fn simple(
    c: &mut PgConnection,
    r: &MaintenanceRequest,
    now: i64,
    limits: &Limits,
) -> Result<Step, Error> {
    match r.action() {
        MaintenanceAction::AdvanceCutoff { selection, before } => {
            let fences = crate::lifecycle::fences(c, r.scope(), limits.max_points.get()).await?;
            if fences.iter().any(|f| {
                f.kind == "cutoff"
                    && crate::lifecycle::covers(selection, &f.selection)
                    && crate::lifecycle::covers(&f.selection, selection)
                    && f.window.end() > *before
            }) {
                return Err(Error::Conflict);
            }
            put_fence(
                c,
                r,
                "cutoff",
                selection,
                Interval::new(Timestamp::new(0)?, *before)?,
                None,
            )
            .await?;
        }
        MaintenanceAction::Delete {
            selection,
            window,
            restore_until,
        } => {
            if restore_until.micros() <= now {
                return Err(Error::InvalidInput);
            }
            put_fence(
                c,
                r,
                "delete",
                selection,
                *window,
                Some(restore_until.micros()),
            )
            .await?;
        }
        MaintenanceAction::Restore {
            selection,
            window,
            deletion_fence,
        } => {
            sqlx::query(
                "SELECT rss_timeseries.restore_fence($1::text::uuid,$2,$3,$4::text::jsonb,$5,$6)",
            )
            .bind(r.scope().tenant().to_string())
            .bind(r.scope().namespace().as_str())
            .bind(deletion_fence.as_str())
            .bind(json(selection)?)
            .bind(window.start().micros())
            .bind(window.end().micros())
            .execute(c)
            .await
            .map_err(sql_error)?;
        }
        MaintenanceAction::CloseStream { stream } => {
            sqlx::query("SELECT rss_timeseries.close_stream($1::text::uuid,$2,$3,$4)")
                .bind(r.scope().tenant().to_string())
                .bind(r.scope().namespace().as_str())
                .bind(stream.source().as_str())
                .bind(stream.generation().as_str())
                .execute(c)
                .await
                .map_err(sql_error)?;
        }
        _ => return Err(Error::Invariant),
    }
    Ok(Step::Done(1))
}
impl<C: Clock> Maintainer for PgStore<C> {
    async fn step(
        &self,
        request: &Authorized<MaintenanceRequest>,
        after: Option<&Continuation>,
        deadline: Deadline,
    ) -> Result<Outcome<MaintenanceProgress>, Error> {
        let r = request.request().clone();
        if r.max_items() > self.limits.max_points {
            return Err(Error::BudgetExceeded);
        }
        let key = self.key.clone();
        let instance = self.instance.clone();
        let limits = self.limits.clone();
        let token = after.cloned();
        let out = self
            .transaction(r.scope().tenant(), deadline, true, move |c, clock| {
                Box::pin(async move {
                    let revision = lock(c, r.scope()).await?;
                    let now = db_now(c).await?;
                    let (mut state, done) = load(c, &r).await?;
                    let binding = r.binding()?;
                    let expires = now
                        .checked_add(
                            i64::try_from(limits.cursor_micros.get())
                                .map_err(|_| Error::NumericRange)?,
                        )
                        .ok_or(Error::NumericRange)?;
                    let ordinal = token
                        .as_ref()
                        .map(|t| key.open::<u64>(DOMAIN, t, binding, &instance, now))
                        .transpose()?
                        .map(|(_, v)| v);
                    if ordinal.is_some_and(|o| o > state.ordinal) {
                        return Err(Error::InvalidCursor);
                    }
                    if done {
                        return Ok(Outcome::Replay(MaintenanceProgress::Complete {
                            processed: 0,
                            fence: r.id().clone(),
                        }));
                    }
                    if ordinal.is_some_and(|o| o < state.ordinal) {
                        return Ok(Outcome::Replay(MaintenanceProgress::More {
                            processed: 0,
                            next: key.seal(DOMAIN, binding, &instance, expires, &state.ordinal)?,
                        }));
                    }
                    let result = match r.action() {
                        MaintenanceAction::Recompute { spec, window } => {
                            recompute::step(c, &r, spec, *window, &mut state, revision, &limits)
                                .await?
                        }
                        MaintenanceAction::Prune { .. } => {
                            prune::step(c, &r, &mut state, now, &limits).await?
                        }
                        MaintenanceAction::ExpireReceipts { stream, before } => {
                            prune::expire(c, &r, stream, *before, now).await?
                        }
                        MaintenanceAction::Reclaim { stream } => {
                            prune::reclaim(c, &r, stream, now).await?
                        }
                        _ => simple(c, &r, now, &limits).await?,
                    };
                    check(clock, deadline)?;
                    let done = matches!(result, Step::Done(_));
                    if !matches!(result, Step::Blocked(_)) {
                        state.ordinal = state.ordinal.checked_add(1).ok_or(Error::NumericRange)?;
                    }
                    save(c, &r, &state, done, &limits).await?;
                    let progress = match result {
                        Step::Done(processed) => MaintenanceProgress::Complete {
                            processed,
                            fence: r.id().clone(),
                        },
                        Step::More(processed) => MaintenanceProgress::More {
                            processed,
                            next: key.seal(DOMAIN, binding, &instance, expires, &state.ordinal)?,
                        },
                        Step::Blocked(reason) => MaintenanceProgress::Blocked { reason },
                    };
                    Ok(Outcome::Accepted(progress))
                })
            })
            .await?;
        Ok(crate::definition::flatten(out))
    }
}
