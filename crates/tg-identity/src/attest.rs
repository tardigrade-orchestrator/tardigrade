//! Workload attestation: who asks, and may they (ADR-0006).
//!
//! Two questions, and both must be answered with yes:
//!
//! 1. **Which container asks?** The agent reads the asking process's cgroup path
//!    (`/proc/<pid>/cgroup`) and finds in it the container identifier `tg-runtime`
//!    has assigned since phase 2 (`tg-<workload>`). Since ADR-0053 the PID comes
//!    from the counterpart's **handle** (`SO_PEERPIDFD`) and not from a number
//!    remembered at the `accept`: a number the kernel can reassign, a handle holds
//!    the process fast.
//! 2. **May this node mint for it?** Only if the workload is assigned to this node.
//!    ADR-0006 calls that authority binding: "limited blast radius on node
//!    compromise". Without the second question a compromised node could assume the
//!    identity of **every** workload in the cluster.
//!
//! The first question is here a pure function over the cgroup file's content --
//! that is why it is checkable without a running container. That the content comes
//! from the process that really hangs on the socket is the agent's job and is
//! checked there.

use std::collections::BTreeMap;

use tg_model::names::CONTAINER_PREFIX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    container_id: String,
}

impl Attestation {
    #[must_use]
    pub fn from_socket(container_id: &str) -> Option<Self> {
        if !container_id.starts_with(CONTAINER_PREFIX) {
            return None;
        }
        if !is_plausible_workload(container_id.strip_prefix(CONTAINER_PREFIX)?) {
            return None;
        }

        Some(Self {
            container_id: container_id.to_owned(),
        })
    }

    #[must_use]
    pub fn container_id(&self) -> &str {
        &self.container_id
    }

    #[must_use]
    pub fn resolve<'a>(&self, assigned: &'a BTreeMap<String, String>) -> Option<&'a str> {
        assigned.get(&self.container_id).map(String::as_str)
    }
}

fn is_plausible_workload(name: &str) -> bool {
    tg_model::names::is_plausible(name)
}
