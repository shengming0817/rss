use crate::control::Fence;
use rss_timeseries::{Id, Sample, Selection, Series, Stream, Timestamp};
use std::{
    collections::{BTreeSet, HashMap},
    hash::{Hash, Hasher},
};

#[derive(Default)]
struct Windows(Vec<(Timestamp, Timestamp)>);
impl Windows {
    // The database orders all fences by start, including each selector's subsequence.
    fn push(&mut self, start: Timestamp, end: Timestamp) {
        if let Some(last) = self.0.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            self.0.push((start, end));
        }
    }
}

// Hash the nominal definition identity and dimensions. Eq checks the entire borrowed
// Series, including the definition snapshot when two keys land in the same bucket.
#[derive(PartialEq, Eq)]
struct ExactSeries<'a>(&'a Series);
impl Hash for ExactSeries<'_> {
    fn hash<H: Hasher>(&self, h: &mut H) {
        let s = self.0;
        (
            s.subject(),
            s.resource(),
            &s.definition().spec().key,
            s.definition().spec().version,
            s.dimensions(),
        )
            .hash(h);
    }
}

type Resource<'a> = (&'a Id, &'a Id);
type Span = (Timestamp, Timestamp);

struct Requested<'a> {
    all: Span,
    keys: HashMap<&'a Id, Span>,
}
impl<'a> Requested<'a> {
    // Probe the smaller side; a single requested metric must not expand every
    // multi-key fence into up to 64 new window entries.
    fn matching_keys(&self, keys: &'a BTreeSet<Id>, mut visit: impl FnMut(&'a Id, Span)) {
        if self.keys.len() <= keys.len() {
            for (&key, &span) in &self.keys {
                if keys.contains(key) {
                    visit(key, span);
                }
            }
        } else {
            for key in keys {
                if let Some(&span) = self.keys.get(key) {
                    visit(key, span);
                }
            }
        }
    }
}

#[derive(Default)]
pub(super) struct AdmissionFences<'a> {
    exact: HashMap<ExactSeries<'a>, Windows>,
    resource: HashMap<(Resource<'a>, Option<&'a Id>), Windows>,
}

impl<'a> AdmissionFences<'a> {
    pub(super) fn from_ordered(
        stream: &Stream,
        fences: &'a [Fence],
        new_samples: impl Iterator<Item = &'a Sample>,
    ) -> Option<Self> {
        let mut requested = HashMap::new();
        for sample in new_samples {
            let input = sample.input();
            let at = input.observed_at;
            let s = &input.series;
            let r = requested
                .entry((s.subject(), s.resource()))
                .or_insert_with(|| Requested {
                    all: (at, at),
                    keys: HashMap::new(),
                });
            r.all = (r.all.0.min(at), r.all.1.max(at));
            let span = r.keys.entry(&s.definition().spec().key).or_insert((at, at));
            *span = (span.0.min(at), span.1.max(at));
        }
        let mut index = Self::default();
        for fence in fences {
            let start = fence.window.start();
            let end = fence.window.end();
            let overlaps = |(first, last): Span| start <= last && first < end;
            match &fence.selection {
                Selection::Exact {
                    stream: target,
                    series,
                } if target == stream => {
                    let relevant = requested
                        .get(&(series.subject(), series.resource()))
                        .and_then(|r| r.keys.get(&series.definition().spec().key))
                        .is_some_and(|&span| overlaps(span));
                    if relevant {
                        index
                            .exact
                            .entry(ExactSeries(series))
                            .or_default()
                            .push(start, end);
                    }
                }
                Selection::Resource {
                    scope,
                    subject,
                    resource,
                    keys,
                } if scope == stream.scope() => {
                    let pair = (subject, resource);
                    let Some(r) = requested.get(&pair) else {
                        continue;
                    };
                    if !overlaps(r.all) {
                        continue;
                    }
                    if keys.is_empty() {
                        index
                            .resource
                            .entry((pair, None))
                            .or_default()
                            .push(start, end);
                    } else {
                        r.matching_keys(keys, |key, span| {
                            if overlaps(span) {
                                index
                                    .resource
                                    .entry((pair, Some(key)))
                                    .or_default()
                                    .push(start, end);
                            }
                        });
                    }
                }
                _ => {}
            }
        }
        (!index.resource.is_empty() || !index.exact.is_empty()).then_some(index)
    }

    pub(super) fn matches(&self, sample: &Sample) -> bool {
        #[cfg(feature = "integration")]
        let start = crate::measurement::cpu_start();
        let s = &sample.input().series;
        let at = sample.input().observed_at;
        #[cfg(feature = "integration")]
        let mut comparisons = 0;
        #[allow(
            unused_mut,
            reason = "Only the integration build counts examined endpoints."
        )]
        let mut covers = |windows: Option<&Windows>| {
            windows.is_some_and(|w| {
                let i = w.0.partition_point(|&(_, end)| {
                    #[cfg(feature = "integration")]
                    {
                        comparisons += 1;
                    }
                    end <= at
                });
                w.0.get(i).is_some_and(|&(lo, _)| {
                    #[cfg(feature = "integration")]
                    {
                        comparisons += 1;
                    }
                    lo <= at
                })
            })
        };
        let pair = (s.subject(), s.resource());
        let found = (!self.resource.is_empty()
            && (covers(self.resource.get(&(pair, None)))
                || covers(self.resource.get(&(pair, Some(&s.definition().spec().key))))))
            || (!self.exact.is_empty() && covers(self.exact.get(&ExactSeries(s))));
        #[cfg(feature = "integration")]
        crate::measurement::record(|m| {
            m.window_endpoint_checks += comparisons;
            m.match_cpu += crate::measurement::elapsed(start);
        });
        found
    }
}
