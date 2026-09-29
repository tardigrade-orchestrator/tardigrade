//! Reported capacity becomes usable capacity.
//!
//! The separation at issue is between what is observed and what is desired:
//! **reported is `actual`, usable is `desired`.** Only the node can count its
//! cores; only an operator can say how much of them the cluster may take —
//! that hangs on what else runs on the machine, on maintenance windows, on
//! contracts.
//!
//! What stands here is the **pure function** in between: report + policy → the
//! two numbers that go into the log. It computes and decides nothing; who
//! applies it and when a log entry arises from it is a decision for the
//! leader to make.
//!
//! # What this function expressly is **not**
//!
//! An input of the planner. `placement::plan` gets exclusively numbers from
//! the replicated state. A report is eventual and in a different state on
//! every node — were the planner to compute with it, a new leader would come
//! to a different result from the old one, and exactly the determinism the
//! scheduler relies on would be gone.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::placement::Resources;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub subtract: u64,
    pub percent: u32,
    #[serde(default)]
    pub cap: Option<u64>,
    #[serde(default)]
    pub reserve: u64,
}

impl Rule {
    #[must_use]
    pub fn apply(&self, reported: u64) -> u64 {
        let ours = u128::from(reported.saturating_sub(self.subtract));
        let share = ours * u128::from(self.percent) / 100;
        let capped = match self.cap {
            Some(cap) => share.min(u128::from(cap)),
            None => share,
        };

        u64::try_from(capped).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapacityPolicy(BTreeMap<String, Rule>);

impl CapacityPolicy {
    #[must_use]
    pub fn with(mut self, resource: &str, rule: Rule) -> Self {
        self.0.insert(resource.to_owned(), rule);
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn entries(&self) -> Vec<(&str, &Rule)> {
        self.0
            .iter()
            .map(|(name, rule)| (name.as_str(), rule))
            .collect()
    }

    #[must_use]
    pub fn rule(&self, resource: &str) -> Option<&Rule> {
        self.0.get(resource)
    }

    #[must_use]
    pub fn apply(&self, reported: &Resources) -> (Resources, Resources) {
        let mut capacity = Resources::default();
        let mut reserved = Resources::default();

        for (name, amount) in reported.entries() {
            let Some(rule) = self.0.get(name) else {
                continue;
            };
            let usable = rule.apply(amount);
            capacity = capacity.with(name, usable);

            // The reserve is clamped at the usable amount: putting more aside
            // than there is would yield a node that accepts nothing — and that
            // is `cordon` and not a reserve.
            if rule.reserve > 0 {
                reserved = reserved.with(name, rule.reserve.min(usable));
            }
        }

        (capacity, reserved)
    }
}
