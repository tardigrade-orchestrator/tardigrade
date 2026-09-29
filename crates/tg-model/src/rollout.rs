//! Which generation of a declaration shall run (ADR-0071).
//!
//! ADR-0070 decided that a changed declaration ends **no** running container:
//! it takes effect at the next start. This number is the decree that triggers
//! the start — the node restarts an instance whose bundle carries a lower
//! generation.
//!
//! # Why a number and not a shout
//!
//! The same form as with the key generations (ADR-0055) and for the same
//! reason: "restart now" would get lost if the node does not hear it, and then
//! one would need a catch-up protocol for something that needs none. Whoever
//! was away reads the number on return (ADR-0042).
//!
//! # Why there are two levels
//!
//! The instance level is the **surge control**. There is no health gate per
//! workload (ADR-0015 knows liveness/readiness for the orchestrator's
//! processes, not for workloads), so the system cannot check whether the first
//! restart went well — and must therefore not choose the order itself. An
//! operator rolls themselves, instance by instance.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generations {
    #[serde(default)]
    pub all: u64,
    #[serde(default)]
    pub instances: BTreeMap<u32, u64>,
}

impl Generations {
    #[must_use]
    pub fn wanted(&self, instance: u32) -> u64 {
        self.all
            .max(self.instances.get(&instance).copied().unwrap_or(0))
    }

    #[must_use]
    pub fn at(&self, instance: Option<u32>) -> u64 {
        match instance {
            Some(instance) => self.wanted(instance),
            None => self.all,
        }
    }

    pub fn set(&mut self, instance: Option<u32>, generation: u64) {
        match instance {
            Some(instance) => {
                self.instances.insert(instance, generation);
            }
            None => self.all = generation,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.all == 0 && self.instances.is_empty()
    }
}
