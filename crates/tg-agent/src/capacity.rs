//! What this node **has** in resources (ADR-0049).
//!
//! An observation, not a decision. What of it is usable is said by a policy in
//! the log; here stands only what the machine offers.
//!
//! # What is reported, and why only that
//!
//! Cores and memory — the two numbers that can be read off a Linux system
//! without foreign code and without guessing. In addition the **devices** from
//! the CDI inventory (ADR-0143 determination 5, builds ADR-0028).
//!
//! Here it stood that a `device` expressly did not belong to them: *"what an
//! accelerator is and how many of them there are is known only to a CDI spec,
//! and that is deferred."* The second half no longer holds — the spec reading has
//! existed since ADR-0143 —, and the first was exactly right: the number is
//! **read and not guessed**. If no device stands in a spec, none stands in the
//! report either.
//!
//! If a number cannot be read off, it is missing from the report. Inventing it
//! would mean reporting to the cluster a capacity that does not exist — and the
//! policy would turn that into a number in the log.

use std::collections::BTreeMap;

use tg_model::placement::Resources;

#[must_use]
pub(crate) fn observe(devices: &BTreeMap<String, u64>) -> Resources {
    let mut resources = Resources::default();

    if let Some(millicores) = cpu_millicores() {
        resources = resources.with(Resources::CPU_MILLICORES, millicores);
    }
    if let Some(bytes) = memory_bytes() {
        resources = resources.with(Resources::MEMORY_BYTES, bytes);
    }
    for (name, count) in devices {
        resources = resources.with(name, *count);
    }

    resources
}

fn cpu_millicores() -> Option<u64> {
    let cores = std::thread::available_parallelism().ok()?.get();

    u64::try_from(cores).ok()?.checked_mul(1000)
}

fn memory_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;

    for line in meminfo.lines() {
        let Some(rest) = line.strip_prefix("MemTotal:") else {
            continue;
        };
        // The line reads "MemTotal:       16311764 kB". The unit is checked and
        // not assumed: a kernel version that wrote bytes would otherwise yield a
        // node with a thousand times as much.
        let mut fields = rest.split_whitespace();
        let amount: u64 = fields.next()?.parse().ok()?;
        if fields.next()? != "kB" {
            return None;
        }
        return amount.checked_mul(1024);
    }

    None
}
