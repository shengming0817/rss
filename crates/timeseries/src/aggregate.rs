//! Shared arithmetic and sufficient statistics; providers own scanning and persistence.
// ref: timescale/timescaledb-toolkit crates/stats-agg/src/stats1d.rs@1.21.0
use crate::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, num::NonZeroU64};
mod numeric;
mod ordered;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "Spec", into = "Spec")]
pub struct SummarySpec(Spec);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Spec {
    stream: Stream,
    series: Series,
    resolution: NonZeroU64,
    coverage: CoveragePolicy,
    max_gap: Option<NonZeroU64>,
}
impl TryFrom<Spec> for SummarySpec {
    type Error = Error;
    fn try_from(value: Spec) -> Result<Self, Error> {
        let s = Self(value);
        s.validate()?;
        Ok(s)
    }
}
impl From<SummarySpec> for Spec {
    fn from(v: SummarySpec) -> Self {
        v.0
    }
}
impl SummarySpec {
    pub fn new(
        stream: Stream,
        series: Series,
        resolution: NonZeroU64,
        coverage: CoveragePolicy,
        max_gap: Option<NonZeroU64>,
    ) -> Result<Self, Error> {
        Self::try_from(Spec {
            stream,
            series,
            resolution,
            coverage,
            max_gap,
        })
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.selection().validate()?;
        if self.0.resolution.get() > i64::MAX as u64 {
            return Err(Error::NumericRange);
        }
        let counter = matches!(
            self.0.series.definition().spec().metric,
            Metric::Counter { .. }
        );
        let state = matches!(
            self.0.series.definition().spec().metric,
            Metric::Bool | Metric::State { .. }
        );
        if counter != self.0.max_gap.is_some()
            || (!state && self.0.coverage != CoveragePolicy::ObservedOnly)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    pub const fn stream(&self) -> &Stream {
        &self.0.stream
    }
    pub const fn series(&self) -> &Series {
        &self.0.series
    }
    pub const fn resolution_micros(&self) -> NonZeroU64 {
        self.0.resolution
    }
    pub const fn coverage(&self) -> CoveragePolicy {
        self.0.coverage
    }
    pub const fn max_gap(&self) -> Option<NonZeroU64> {
        self.0.max_gap
    }
    pub fn selection(&self) -> Selection {
        Selection::Exact {
            stream: self.0.stream.clone(),
            series: self.0.series.clone(),
        }
    }
    pub fn binding(&self) -> Result<Digest, Error> {
        digest(b"summary-spec", self)
    }
    /// Policy identity excludes resolution: only aligned compatible summaries may roll up.
    pub fn semantics(&self) -> Result<Digest, Error> {
        digest(
            b"summary-semantics",
            &(
                &self.0.stream,
                &self.0.series,
                self.0.coverage,
                self.0.max_gap,
            ),
        )
    }
    pub fn bucket(&self, at: Timestamp) -> Result<Interval, Error> {
        let r = self.0.resolution.get() as i64;
        let start = at.micros() / r * r;
        Interval::new(
            Timestamp::new(start)?,
            Timestamp::new(start.saturating_add(r))?,
        )
    }
    pub fn lookback(&self) -> u64 {
        match self.coverage() {
            CoveragePolicy::HoldLast(n) => n.get(),
            CoveragePolicy::ObservedOnly => self.max_gap().map_or(0, NonZeroU64::get),
        }
    }
}

/// Serialized provider-owned summary format. No producer identity is derived from it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Summary {
    pub window: Interval,
    semantics: Digest,
    valid: u64,
    defects: BTreeSet<Completeness>,
    data: Statistics,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum Statistics {
    Numeric(numeric::Numeric),
    Counter {
        kind: NumberKind,
        contributions: Vec<ordered::Contribution>,
    },
    State {
        segments: Vec<StateSegment>,
        transitions: Vec<Transition>,
    },
}
/// Exact integer Gauge statistics reconstructed by a trusted provider. This verifies
/// structural/numeric consistency, not the provider's durable publication claim.
#[derive(Clone, Debug)]
pub struct GaugeStatistics {
    pub sum: Sum,
    pub count: u64,
    pub min: Option<Number>,
    pub max: Option<Number>,
    pub gaps: bool,
}
impl Summary {
    pub fn from_integer_gauge(
        spec: &SummarySpec,
        window: Interval,
        stats: GaugeStatistics,
    ) -> Result<Self, Error> {
        spec.validate()?;
        let Metric::Gauge { number } = spec.series().definition().spec().metric else {
            return Err(Error::Unsupported);
        };
        if window.width_micros() == 0 {
            return Err(Error::InvalidInput);
        }
        let data = Statistics::Numeric(numeric::Numeric::from_integer_statistics(number, &stats)?);
        let mut defects = BTreeSet::new();
        if stats.gaps {
            defects.insert(Completeness::Gaps);
        }
        Ok(Self {
            window,
            semantics: spec.semantics()?,
            valid: stats.count,
            defects,
            data,
        })
    }

    /// Input is unique and ordered by the canonical observation tuple. It may include
    /// one predecessor for Counter/state boundary semantics. Providers enforce scan budgets.
    pub fn compute(
        spec: &SummarySpec,
        window: Interval,
        samples: &[Sample],
        max_items: usize,
    ) -> Result<Self, Error> {
        if samples.len() > max_items || window.width_micros() == 0 {
            return Err(Error::BudgetExceeded);
        }
        let selection = spec.selection();
        let mut previous = None;
        let mut ids = BTreeSet::new();
        for sample in samples {
            if !selection.matches(sample) {
                return Err(Error::InvalidInput);
            }
            let i = sample.input();
            let key = (i.observed_at, i.sequence, &i.id);
            if previous.is_some_and(|p| p >= key) || !ids.insert(&i.id) {
                return Err(Error::Conflict);
            }
            previous = Some(key);
        }
        let mut builder = SummaryBuilder::new(spec.clone(), window)?;
        for sample in samples {
            builder.push(sample.clone(), max_items)?;
        }
        builder.finish(max_items)
    }
    fn check_size(&self, max: usize) -> Result<(), Error> {
        let n = match &self.data {
            Statistics::Numeric(_) => 1,
            Statistics::Counter { contributions, .. } => contributions.len(),
            Statistics::State {
                segments,
                transitions,
            } => segments.len().saturating_add(transitions.len()),
        };
        if n > max {
            Err(Error::BudgetExceeded)
        } else {
            Ok(())
        }
    }
    /// Exact ordered union. No averaging means, proportional splitting or policy coercion.
    pub fn merge(mut self, other: Self, max_items: usize) -> Result<Self, Error> {
        if self.window.end() != other.window.start() || self.semantics != other.semantics {
            return Err(Error::InvalidInput);
        }
        self.window = Interval::new(self.window.start(), other.window.end())?;
        self.valid = self
            .valid
            .checked_add(other.valid)
            .ok_or(Error::NumericRange)?;
        self.defects.extend(other.defects);
        match (&mut self.data, other.data) {
            (Statistics::Numeric(a), Statistics::Numeric(b)) => a.merge(b)?,
            (
                Statistics::Counter {
                    kind: a,
                    contributions: x,
                },
                Statistics::Counter {
                    kind: b,
                    contributions: y,
                },
            ) if *a == b => x.extend(y),
            (
                Statistics::State {
                    segments: a,
                    transitions: x,
                },
                Statistics::State {
                    segments: b,
                    transitions: y,
                },
            ) => {
                a.extend(b);
                x.extend(y);
            }
            _ => return Err(Error::InvalidInput),
        }
        self.check_size(max_items)?;
        Ok(self)
    }
    pub fn project(&self, operation: AggregateOp) -> Result<AggregateBucket, Error> {
        let mut defects = self.defects.clone();
        let (value, covered) = match &self.data {
            Statistics::Numeric(n) => (n.project(operation)?, 0),
            Statistics::Counter {
                kind,
                contributions,
            } => ordered::project_counter(
                *kind,
                contributions,
                self.window,
                operation,
                &mut defects,
            )?,
            Statistics::State {
                segments,
                transitions,
            } => ordered::project_state(segments, transitions, operation)?,
        };
        if !matches!(self.data, Statistics::Numeric(_)) && covered < self.window.width_micros() {
            defects.insert(Completeness::Gaps);
        }
        Ok(AggregateBucket {
            window: self.window,
            value,
            valid_samples: self.valid,
            covered_micros: covered,
            completeness: defects,
        })
    }
}
fn inside(at: Timestamp, w: Interval) -> bool {
    at >= w.start() && at < w.end()
}

/// Resumable bounded fold. Only two source observations are retained as boundary
/// anchors; Gauge accumulation is constant-space regardless of input count.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SummaryBuilder {
    spec: SummarySpec,
    summary: Summary,
    previous: Option<Sample>,
    pending: Option<Sample>,
}
impl SummaryBuilder {
    pub fn new(spec: SummarySpec, window: Interval) -> Result<Self, Error> {
        spec.validate()?;
        if window.width_micros() == 0 {
            return Err(Error::InvalidInput);
        }
        let data = match spec.series().definition().spec().metric {
            Metric::Gauge { number } => {
                Statistics::Numeric(numeric::Numeric::compute(number, window, &[])?)
            }
            Metric::Counter { number, .. } => Statistics::Counter {
                kind: number,
                contributions: Vec::new(),
            },
            Metric::Bool | Metric::State { .. } => Statistics::State {
                segments: Vec::new(),
                transitions: Vec::new(),
            },
        };
        let summary = Summary {
            window,
            semantics: spec.semantics()?,
            valid: 0,
            defects: BTreeSet::new(),
            data,
        };
        Ok(Self {
            spec,
            summary,
            previous: None,
            pending: None,
        })
    }
    pub fn push(&mut self, sample: Sample, max_items: usize) -> Result<(), Error> {
        if !self.spec.selection().matches(&sample) {
            return Err(Error::InvalidInput);
        }
        if let Some(p) = &self.pending {
            if !sample.latest_cmp(p)?.is_gt() {
                return Err(Error::Conflict);
            }
            let ordered = matches!(
                self.spec.series().definition().spec().metric,
                Metric::Counter {
                    temporality: Temporality::Cumulative,
                    ..
                } | Metric::Bool
                    | Metric::State { .. }
            );
            if ordered && p.input().observed_at == sample.input().observed_at {
                self.pending = Some(sample);
                return Ok(());
            }
        }
        self.flush(Some(&sample))?;
        self.pending = Some(sample);
        self.summary.check_size(max_items)
    }
    fn flush(&mut self, next: Option<&Sample>) -> Result<(), Error> {
        let Some(p) = self.pending.take() else {
            return Ok(());
        };
        let w = self.summary.window;
        let at = p.input().observed_at;
        if inside(at, w) {
            if matches!(p.input().reading, Reading::Valid(_)) {
                self.summary.valid = self
                    .summary
                    .valid
                    .checked_add(1)
                    .ok_or(Error::NumericRange)?;
            } else {
                self.summary.defects.insert(Completeness::Gaps);
            }
        }
        match &mut self.summary.data {
            Statistics::Numeric(n) => {
                if inside(at, w)
                    && let Reading::Valid(Value::Number(v)) = p.input().reading
                {
                    n.add(v)?;
                }
            }
            Statistics::Counter { contributions, .. } => {
                if inside(at, w) {
                    let mut input = Vec::new();
                    if let Some(prev) = &self.previous {
                        input.push(prev.clone());
                    }
                    input.push(p.clone());
                    let Metric::Counter { temporality, .. } =
                        self.spec.series().definition().spec().metric
                    else {
                        return Err(Error::Invariant);
                    };
                    let only = if temporality == Temporality::Delta {
                        &input[input.len() - 1..]
                    } else {
                        input.as_slice()
                    };
                    contributions.extend(ordered::counter(
                        &self.spec,
                        w,
                        only,
                        temporality,
                        &mut self.summary.defects,
                    )?);
                }
            }
            Statistics::State {
                segments,
                transitions,
            } => {
                let (segment, transition) =
                    ordered::state_piece(&self.spec, w, self.previous.as_ref(), &p, next)?;
                if let Some(s) = segment {
                    segments.push(s);
                }
                if let Some(t) = transition {
                    transitions.push(t);
                }
            }
        }
        self.previous = Some(p);
        Ok(())
    }
    /// Explicit unavailable time cuts temporal continuity without inventing a producer sample.
    pub fn interrupt(&mut self, at: Timestamp) -> Result<(), Error> {
        let full = self.summary.window;
        self.summary.window = Interval::new(full.start(), at.max(full.start()).min(full.end()))?;
        self.flush(None)?;
        self.summary.window = full;
        self.previous = None;
        self.summary.defects.insert(Completeness::Gaps);
        Ok(())
    }
    pub fn last_observed_at(&self) -> Option<Timestamp> {
        self.pending
            .as_ref()
            .or(self.previous.as_ref())
            .map(|s| s.input().observed_at)
    }
    pub fn finish(mut self, max_items: usize) -> Result<Summary, Error> {
        self.flush(None)?;
        self.summary.check_size(max_items)?;
        Ok(self.summary)
    }
}
