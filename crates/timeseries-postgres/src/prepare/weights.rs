//! Minimum charge in each occupied binary range of FIFO ticket numbers.
//! A subtree can be skipped as soon as its minimum exceeds the available bytes.
use std::collections::HashMap;

const LEAVES: u128 = 1 << u64::BITS;
#[derive(Default)]
pub(super) struct Weights(HashMap<u128, u32>);

impl Weights {
    pub(super) fn set(&mut self, id: u64, mut minimum: Option<u32>) {
        let mut node = LEAVES + u128::from(id);
        loop {
            if self.0.get(&node).copied() == minimum {
                break;
            }
            if let Some(weight) = minimum {
                self.0.insert(node, weight);
            } else {
                self.0.remove(&node);
            }
            if node == 1 {
                break;
            }
            // Only ancestors of this ticket can have changed. Including the
            // sibling accounts for both insertion and removal of the minimum.
            minimum = minimum
                .into_iter()
                .chain(self.0.get(&(node ^ 1)).copied())
                .min();
            node /= 2;
        }
    }

    pub(super) fn first(&self, bytes: u32) -> Option<u64> {
        if *self.0.get(&1)? > bytes {
            return None;
        }
        let mut node = 1;
        while node < LEAVES {
            node *= 2;
            if self.0.get(&node).is_none_or(|&weight| weight > bytes) {
                node += 1;
            }
        }
        u64::try_from(node - LEAVES).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn sparse_tickets_select_the_first_fit_through_cancellations() {
        let mut index = Weights::default();
        let mut ordered = BTreeMap::new();
        for id in (0..256).chain([1 << 40, u64::MAX]) {
            let weight = (id % 19) as u32 + 1;
            index.set(id, Some(weight));
            ordered.insert(id, weight);
        }
        for id in (0..256)
            .step_by(2)
            .chain((1..256).step_by(2))
            .chain([1 << 40, u64::MAX])
        {
            for bytes in 0..=20 {
                assert_eq!(
                    index.first(bytes),
                    ordered
                        .iter()
                        .find(|(_, w)| **w <= bytes)
                        .map(|(&id, _)| id)
                );
            }
            index.set(id, None);
            ordered.remove(&id);
        }
        assert!(index.0.is_empty());
    }
}
