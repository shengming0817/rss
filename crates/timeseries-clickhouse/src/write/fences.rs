use crate::{control::Fence, transaction::bytes};
use rss_timeseries::{Error, Id, Sample, Selection, Stream, Timestamp};
use std::collections::HashMap;

#[derive(Default)]
struct Windows(Vec<(Timestamp, Timestamp)>);

impl Windows {
    // control::fences supplies nondecreasing starts, also within each selector.
    fn push(&mut self, start: Timestamp, end: Timestamp) {
        if let Some(last) = self.0.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            return;
        }
        self.0.push((start, end));
    }
}

type ResourceKey<'a> = (&'a Id, &'a Id, Option<&'a Id>);

#[derive(Default)]
pub(super) struct AdmissionFences<'a> {
    // Typed canonical bytes include the full definition snapshot and dimensions.
    exact: HashMap<Vec<u8>, Windows>,
    resources: HashMap<ResourceKey<'a>, Windows>,
}

impl<'a> AdmissionFences<'a> {
    pub(super) fn from_ordered(stream: &Stream, fences: &'a [Fence]) -> Result<Self, Error> {
        let mut index = Self::default();
        for fence in fences {
            let start = fence.window.start();
            let end = fence.window.end();
            match &fence.selection {
                Selection::Exact {
                    stream: target,
                    series,
                } if target == stream => {
                    index
                        .exact
                        .entry(bytes(series)?)
                        .or_default()
                        .push(start, end);
                }
                Selection::Resource {
                    scope,
                    subject,
                    resource,
                    keys,
                } if scope == stream.scope() => {
                    if keys.is_empty() {
                        index
                            .resources
                            .entry((subject, resource, None))
                            .or_default()
                            .push(start, end);
                    } else {
                        for key in keys {
                            index
                                .resources
                                .entry((subject, resource, Some(key)))
                                .or_default()
                                .push(start, end);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(index)
    }

    pub(super) fn matches(&self, sample: &Sample) -> Result<bool, Error> {
        let input = sample.input();
        let series = &input.series;
        let at = input.observed_at;
        #[cfg(feature = "integration")]
        let mut comparisons = 0;
        #[allow(
            unused_mut,
            reason = "Integration measurements count comparisons in the closure."
        )]
        let mut covers = |windows: Option<&Windows>| {
            windows.is_some_and(|windows| {
                let i = windows.0.partition_point(|&(_, end)| {
                    #[cfg(feature = "integration")]
                    {
                        comparisons += 1;
                    }
                    end <= at
                });
                windows.0.get(i).is_some_and(|&(start, _)| {
                    #[cfg(feature = "integration")]
                    {
                        comparisons += 1;
                    }
                    start <= at
                })
            })
        };
        let resource = (series.subject(), series.resource());
        let found = covers(self.resources.get(&(resource.0, resource.1, None)))
            || covers(self.resources.get(&(
                resource.0,
                resource.1,
                Some(&series.definition().spec().key),
            )))
            || (!self.exact.is_empty() && covers(self.exact.get(&bytes(series)?)));
        #[cfg(feature = "integration")]
        crate::measurement::record(|m| m.window_endpoint_checks += comparisons);
        Ok(found)
    }
}
