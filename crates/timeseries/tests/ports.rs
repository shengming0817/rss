//! A rejecting adapter proves implementability of the public ports. It deliberately
//! supplies no memory persistence and no fake successful durable result.
use rss_request_context::{Deadline, TenantId};
use rss_timeseries::*;
use std::num::NonZeroU64;
use std::{
    future::Future,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

struct Rejecting {
    guarantees: Guarantees,
}
impl DefinitionStore for Rejecting {
    async fn read(
        &self,
        _: &Authorized<DefinitionId>,
        _: Deadline,
    ) -> Result<Lookup<DefinitionRecord>, Error> {
        Err(Error::Unsupported)
    }
    async fn change(
        &self,
        _: &Authorized<DefinitionMutation>,
        _: Deadline,
    ) -> Result<Outcome<DefinitionRecord>, Error> {
        Err(Error::Unsupported)
    }
}
impl Writer for Rejecting {
    fn guarantees(&self) -> &Guarantees {
        &self.guarantees
    }
    async fn write(&self, _: &Authorized<Batch>, _: Deadline) -> Result<Outcome<Receipt>, Error> {
        Err(Error::Unsupported)
    }
    async fn receipt(
        &self,
        _: &Authorized<ReceiptQuery>,
        _: Deadline,
    ) -> Result<Lookup<ReceiptStatus>, Error> {
        Err(Error::Unsupported)
    }
}
impl Reader for Rejecting {
    async fn query(
        &self,
        _: &Authorized<Query>,
        _: Option<&Continuation>,
        _: Deadline,
    ) -> Result<Page, Error> {
        Err(Error::Unsupported)
    }
    async fn aggregate(
        &self,
        _: &Authorized<AggregateQuery>,
        _: Option<&Continuation>,
        _: Deadline,
    ) -> Result<AggregatePage, Error> {
        Err(Error::Unsupported)
    }
}
impl Maintainer for Rejecting {
    async fn step(
        &self,
        _: &Authorized<MaintenanceRequest>,
        _: Option<&Continuation>,
        _: Deadline,
    ) -> Result<Outcome<MaintenanceProgress>, Error> {
        Err(Error::Unsupported)
    }
}
struct Operator;
impl Authority for Operator {
    fn authorize(&self, _: Access<'_>) -> Result<(), Error> {
        // Test product policy: this in-process operator owns every fixture request.
        Ok(())
    }
}
fn reject<T>(future: impl Future<Output = Result<T, Error>>) -> anyhow::Result<()> {
    match std::pin::pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Err(Error::Unsupported)) => Ok(()),
        _ => anyhow::bail!("rejecting adapter changed behavior"),
    }
}
#[test]
#[allow(clippy::disallowed_methods)] // A local deadline fixture, never a production clock fallback.
fn independent_adapter_implements_all_ports_without_a_runtime() -> anyhow::Result<()> {
    let one = NonZeroU64::new(1).ok_or_else(|| anyhow::anyhow!("fixture"))?;
    let store = Rejecting {
        guarantees: Guarantees {
            atomicity: Atomicity::AtomicBatch,
            replay_micros: one,
        },
    };
    let scope = Scope::new(
        TenantId::parse("11111111-1111-4111-8111-111111111111")?,
        Id::new("custom")?,
    );
    let definition = Definition::new(DefinitionSpec {
        scope: scope.clone(),
        key: Id::new("new.custom.boolean")?,
        version: 1,
        unit: Id::new("1")?,
        metric: Metric::Bool,
        dimensions: DimensionRules {
            allowed: Default::default(),
            required: Default::default(),
            max_count: 0,
            max_value_bytes: 1,
            max_total_bytes: 1,
        },
    })?;
    let identity = DefinitionId {
        scope: scope.clone(),
        key: definition.spec().key.clone(),
        version: one,
    };
    let deadline = Deadline::at(Instant::now() + Duration::from_secs(1));
    reject(store.read(
        &Authorized::<DefinitionId>::verify(&Operator, identity.clone())?,
        deadline,
    ))?;
    reject(store.change(
        &Authorized::<DefinitionMutation>::verify(
            &Operator,
            DefinitionMutation::Register {
                definition: definition.clone(),
                expected_latest: None,
            },
        )?,
        deadline,
    ))?;
    reject(store.change(
        &Authorized::<DefinitionMutation>::verify(
            &Operator,
            DefinitionMutation::Retire {
                id: identity,
                expected: definition.digest()?,
            },
        )?,
        deadline,
    ))?;
    let stream = Stream::new(scope, Id::new("source")?, Id::new("generation")?);
    let series = Series::new(
        definition,
        Id::new("subject")?,
        Id::new("resource")?,
        Default::default(),
    )?;
    let sample = Sample::new(SampleInput {
        stream: stream.clone(),
        series: series.clone(),
        id: Id::new("sample")?,
        sequence: 0,
        observed_at: Timestamp::new(1)?,
        interval: None,
        reading: Reading::Valid(Value::Bool(true)),
    })?;
    let batch = Batch::new(stream.clone(), Id::new("batch")?, vec![sample])?;
    let receipt_query = ReceiptQuery {
        stream: stream.clone(),
        batch_id: batch.id().clone(),
        digest: batch.digest()?,
    };
    reject(store.write(&Authorized::<Batch>::verify(&Operator, batch)?, deadline))?;
    reject(store.receipt(
        &Authorized::<ReceiptQuery>::verify(&Operator, receipt_query)?,
        deadline,
    ))?;
    assert_eq!(store.guarantees().atomicity, Atomicity::AtomicBatch);
    let n = std::num::NonZeroU32::new(1).ok_or_else(|| anyhow::anyhow!("fixture"))?;
    let query = Query::new(
        Selection::Exact { stream, series },
        Interval::new(Timestamp::new(0)?, Timestamp::new(10)?)?,
        QueryBudget {
            max_series: n,
            max_points: n,
        },
        QueryMode::History,
    )?;
    reject(store.query(
        &Authorized::<Query>::verify(&Operator, query.clone())?,
        None,
        deadline,
    ))?;
    let aggregate = AggregateQuery::new(
        query.clone(),
        AggregateOp::Coverage,
        one,
        CoveragePolicy::HoldLast(one),
    )?;
    assert_eq!(aggregate.resolution_micros(), one);
    aggregate.binding()?;
    reject(store.aggregate(
        &Authorized::<AggregateQuery>::verify(&Operator, aggregate)?,
        None,
        deadline,
    ))?;
    let maintenance = MaintenanceRequest::new(
        Id::new("plan")?,
        query.selection().clone(),
        query.window(),
        MaintenanceAction::Recompute,
        n,
    )?;
    reject(store.step(
        &Authorized::<MaintenanceRequest>::verify(&Operator, maintenance)?,
        None,
        deadline,
    ))?;
    Ok(())
}
