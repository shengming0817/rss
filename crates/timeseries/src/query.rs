use crate::{
    Digest, Error, Id, Interval, Metric, NumberKind, Sample, Scope, Series, Stream, Temporality,
    Timestamp, digest,
};
use rss_contract::PageCursor;
use serde::Serialize;
use std::collections::BTreeSet;
use std::num::{NonZeroU32, NonZeroU64};

/// Resource filters never cross tenants/namespaces. Results retain each source,
/// generation and definition version; an empty key set selects all resource keys.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "selection", rename_all = "camelCase")]
pub enum Selection {
    Exact {
        stream: Stream,
        series: Series,
    },
    Resource {
        scope: Scope,
        subject: Id,
        resource: Id,
        keys: BTreeSet<Id>,
    },
}
impl Selection {
    pub fn scope(&self) -> &Scope {
        match self {
            Self::Exact { stream, .. } => stream.scope(),
            Self::Resource { scope, .. } => scope,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Exact { stream, series }
                if stream.scope() != &series.definition().spec().scope =>
            {
                Err(Error::InvalidInput)
            }
            Self::Resource { keys, .. } if keys.len() > 64 => Err(Error::BudgetExceeded),
            _ => Ok(()),
        }
    }
    pub fn matches(&self, sample: &Sample) -> bool {
        let input = sample.input();
        match self {
            Self::Exact { stream, series } => stream == &input.stream && series == &input.series,
            Self::Resource {
                scope,
                subject,
                resource,
                keys,
            } => {
                scope == input.stream.scope()
                    && subject == input.series.subject()
                    && resource == input.series.resource()
                    && (keys.is_empty() || keys.contains(&input.series.definition().spec().key))
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum QueryMode {
    History,
    Latest,
}

/// A mandatory positive work/output budget; providers must also bound scanned work
/// using the operation deadline and their supported execution configuration.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryBudget {
    pub max_series: NonZeroU32,
    pub max_points: NonZeroU32,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Query {
    selection: Selection,
    window: Interval,
    budget: QueryBudget,
    mode: QueryMode,
}
impl Query {
    pub fn new(
        selection: Selection,
        window: Interval,
        budget: QueryBudget,
        mode: QueryMode,
    ) -> Result<Self, Error> {
        selection.validate()?;
        if window.width_micros() == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            selection,
            window,
            budget,
            mode,
        })
    }
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }
    pub const fn window(&self) -> Interval {
        self.window
    }
    pub const fn budget(&self) -> QueryBudget {
        self.budget
    }
    pub const fn mode(&self) -> QueryMode {
        self.mode
    }
    pub fn binding(&self) -> Result<Digest, Error> {
        digest(b"query", self)
    }
    pub fn matches(&self, sample: &Sample) -> bool {
        self.selection.matches(sample)
            && sample.input().observed_at >= self.window.start()
            && sample.input().observed_at < self.window.end()
    }
    pub fn validate_page(&self, rows: &[ObservedSample]) -> Result<(), Error> {
        if rows.len() > self.budget.max_points.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        let mut series = BTreeSet::new();
        let mut previous = None;
        for row in rows {
            if !self.matches(&row.sample) {
                return Err(Error::Invariant);
            }
            let input = row.sample.input();
            let key = (
                input.series.digest()?.as_bytes().to_owned(),
                input.stream.source(),
                input.stream.generation(),
            );
            let fresh = series.insert(key);
            if matches!(self.mode, QueryMode::Latest) && !fresh {
                return Err(Error::Invariant);
            }
            let order = (key, input.observed_at, input.sequence, &input.id);
            if previous.as_ref().is_some_and(|old| old >= &order) {
                return Err(Error::Invariant);
            }
            previous = Some(order);
        }
        if series.len() > self.budget.max_series.get() as usize {
            return Err(Error::BudgetExceeded);
        }
        Ok(())
    }
}

/// Binding is core-checked; payload integrity, snapshot validity and expiry are
/// provider-checked. Construction does not authenticate a user-supplied cursor.
#[derive(Clone, Debug)]
pub struct Continuation {
    binding: Digest,
    token: PageCursor,
}
impl Continuation {
    pub const fn new(binding: Digest, token: PageCursor) -> Self {
        Self { binding, token }
    }
    pub fn verify(&self, binding: Digest) -> Result<&PageCursor, Error> {
        if self.binding != binding {
            return Err(Error::InvalidCursor);
        }
        Ok(&self.token)
    }
}
/// Trusted provider output; receipt time is outside producer sample content.
#[derive(Clone, Debug)]
pub struct ObservedSample {
    pub sample: Sample,
    pub received_at: Timestamp,
}
#[derive(Clone, Debug)]
pub struct Page {
    pub rows: Vec<ObservedSample>,
    pub next: Option<Continuation>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AggregateOp {
    Min,
    Max,
    Sum,
    Count,
    Mean,
    Increase,
    Rate,
    Timeline,
    Transitions,
    Coverage,
}
impl AggregateOp {
    pub fn validate(self, metric: &Metric) -> Result<(), Error> {
        let valid = match metric {
            Metric::Gauge { .. } => matches!(
                self,
                Self::Min | Self::Max | Self::Sum | Self::Count | Self::Mean
            ),
            Metric::Counter {
                temporality: Temporality::Cumulative,
                ..
            } => matches!(self, Self::Increase | Self::Rate),
            Metric::Counter {
                temporality: Temporality::Delta,
                ..
            } => matches!(self, Self::Sum | Self::Rate),
            Metric::Bool | Metric::State { .. } => {
                matches!(self, Self::Timeline | Self::Transitions | Self::Coverage)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }
}
/// An explicit product policy. Point observations alone never prove duration.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "coverage", content = "maxHoldMicros", rename_all = "camelCase")]
pub enum CoveragePolicy {
    ObservedOnly,
    HoldLast(NonZeroU64),
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateQuery {
    query: Query,
    operation: AggregateOp,
    resolution_micros: NonZeroU64,
    coverage: CoveragePolicy,
}
impl AggregateQuery {
    /// Aggregation is exact-series only: no implicit cross-source/version mixing.
    pub fn new(
        query: Query,
        operation: AggregateOp,
        resolution_micros: NonZeroU64,
        coverage: CoveragePolicy,
    ) -> Result<Self, Error> {
        let Selection::Exact { series, .. } = query.selection() else {
            return Err(Error::Unsupported);
        };
        if !matches!(query.mode(), QueryMode::History) {
            return Err(Error::InvalidInput);
        }
        operation.validate(&series.definition().spec().metric)?;
        let state = matches!(
            series.definition().spec().metric,
            Metric::Bool | Metric::State { .. }
        );
        if (!state && matches!(coverage, CoveragePolicy::HoldLast(_)))
            || (matches!(operation, AggregateOp::Coverage)
                && matches!(coverage, CoveragePolicy::ObservedOnly))
        {
            return Err(Error::InvalidInput);
        }
        if resolution_micros.get() > query.window().width_micros() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            query,
            operation,
            resolution_micros,
            coverage,
        })
    }
    pub const fn query(&self) -> &Query {
        &self.query
    }
    pub const fn operation(&self) -> AggregateOp {
        self.operation
    }
    pub const fn resolution_micros(&self) -> NonZeroU64 {
        self.resolution_micros
    }
    pub const fn coverage(&self) -> CoveragePolicy {
        self.coverage
    }
    pub fn binding(&self) -> Result<Digest, Error> {
        digest(b"aggregate", self)
    }
}

/// Exact sufficient statistic. A mean is `sum/count`, not an average of means.
#[derive(Clone, Copy, PartialEq)]
pub enum Sum {
    I128(i128),
    U128(u128),
    F64(crate::FiniteF64),
}
impl Sum {
    pub fn zero(kind: NumberKind) -> Result<Self, Error> {
        Ok(match kind {
            NumberKind::I64 => Self::I128(0),
            NumberKind::U64 => Self::U128(0),
            NumberKind::F64 => Self::F64(crate::FiniteF64::new(0.0)?),
        })
    }
    pub fn checked_add(self, other: Self) -> Result<Self, Error> {
        match (self, other) {
            (Self::I128(a), Self::I128(b)) => {
                a.checked_add(b).map(Self::I128).ok_or(Error::NumericRange)
            }
            (Self::U128(a), Self::U128(b)) => {
                a.checked_add(b).map(Self::U128).ok_or(Error::NumericRange)
            }
            (Self::F64(a), Self::F64(b)) => {
                Ok(Self::F64(crate::FiniteF64::new(a.get() + b.get())?))
            }
            _ => Err(Error::InvalidInput),
        }
    }
}
#[derive(Clone, Debug)]
pub enum AggregateValue {
    Number(crate::Number),
    Sum(Sum),
    Count(u64),
    Mean {
        sum: Sum,
        count: NonZeroU64,
    },
    Rate {
        increase: Sum,
        duration_micros: NonZeroU64,
    },
    StateSegments(Vec<StateSegment>),
    Transitions(Vec<Transition>),
    StateCoverage(Vec<StateDuration>),
    /// No valid observations, not a zero result.
    Missing,
}
#[derive(Clone, Debug)]
pub struct StateSegment {
    pub value: StateValue,
    pub window: Interval,
}
#[derive(Clone, Debug)]
pub struct Transition {
    pub at: Timestamp,
    pub from: StateValue,
    pub to: StateValue,
}
#[derive(Clone, Debug)]
pub struct StateDuration {
    pub value: StateValue,
    pub micros: u64,
}
#[derive(Clone, Copy, Debug)]
pub enum Completeness {
    Complete,
    Gaps,
    Overlap,
    ResetBoundary,
}
#[derive(Clone, Debug)]
pub struct AggregateBucket {
    pub window: Interval,
    pub value: AggregateValue,
    pub valid_samples: u64,
    pub covered_micros: u64,
    pub completeness: Completeness,
}
/// Provider output must respect the request's point/series budget including nested
/// timeline segments/transitions. A watermark never proves future data cannot arrive.
#[derive(Clone, Debug)]
pub struct AggregatePage {
    pub buckets: Vec<AggregateBucket>,
    pub resolution_micros: NonZeroU64,
    pub refreshed_through: Option<Timestamp>,
    pub next: Option<Continuation>,
}

impl std::fmt::Debug for Sum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sum([redacted])")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub enum StateValue {
    Bool(bool),
    State(Id),
}
impl std::fmt::Debug for StateValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StateValue([redacted])")
    }
}
