//! A single writer's active role (ADR-0066).
//!
//! ADR-0064 binds the **container lifecycle** to the active-role lease:
//! without it instance 0 does not start up, and at expiry the reconciler ends
//! it. Two gaps stay open in the process, and this module closes them:
//!
//! - A **warm standby** must run in order to be warm (ADR-0010) -- it is
//!   therefore exempt from the lease (ADR-0064, determination 8) and thereby
//!   talks although it does not hold the role.
//! - A primary that **stops slowly** talks on. ADR-0010 names precisely this
//!   case as the one fencing exists for.
//!
//! The sidecar answers both **locally**: it sits on the same machine as the
//! holder, has the same clock and the same setting. For the case it is about
//! -- a detached, **honest** node -- no propagation over the wire is needed
//! for it (ADR-0066, determination 5).
//!
//! # Fail-closed, not fail-static
//!
//! A missing or unreadable file means **no active role**. ADR-0019 protects
//! existing *permitted* traffic from a control-plane loss; a role that does
//! not arise at all without quorum must not arise from a read error. The same
//! direction as with the egress port (ADR-0041).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveRole {
    Active {
        epoch: u64,
    },
    Passive,
}

impl ActiveRole {
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roles(BTreeMap<String, Lease>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lease {
    epoch: u64,
    expires_at: u64,
}

impl Roles {
    #[must_use]
    pub fn from_text(text: &str) -> Self {
        let mut out = BTreeMap::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let (Some(name), Some(epoch), Some(expires_at), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let (Ok(epoch), Ok(expires_at)) = (epoch.parse(), expires_at.parse()) else {
                continue;
            };
            out.insert(name.to_owned(), Lease { epoch, expires_at });
        }

        Self(out)
    }

    #[must_use]
    pub fn role_of(&self, workload: &str, now: u64) -> ActiveRole {
        match self.0.get(workload) {
            Some(lease) if now < lease.expires_at => ActiveRole::Active { epoch: lease.epoch },
            _ => ActiveRole::Passive,
        }
    }

    #[must_use]
    pub fn expires_at(&self, workload: &str) -> Option<u64> {
        self.0.get(workload).map(|lease| lease.expires_at)
    }
}

#[derive(Debug, Clone)]
pub struct SharedRoles {
    inner: Arc<RwLock<Roles>>,
    version: Arc<tokio::sync::watch::Sender<u64>>,
}

impl SharedRoles {
    #[must_use]
    pub fn new(roles: Roles) -> Self {
        Self {
            inner: Arc::new(RwLock::new(roles)),
            version: Arc::new(tokio::sync::watch::Sender::new(0)),
        }
    }

    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.version.subscribe()
    }

    #[must_use]
    pub fn role_of(&self, workload: &str, now: u64) -> ActiveRole {
        self.inner
            .read()
            .map_or(ActiveRole::Passive, |roles| roles.role_of(workload, now))
    }

    #[must_use]
    pub fn expires_at(&self, workload: &str) -> Option<u64> {
        self.inner
            .read()
            .ok()
            .and_then(|roles| roles.expires_at(workload))
    }

    pub fn replace(&self, roles: Roles) {
        if let Ok(mut slot) = self.inner.write() {
            *slot = roles;
        }
        self.version.send_modify(|version| *version += 1);
    }
}

#[must_use]
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

#[derive(Debug, Clone)]
pub struct Gate {
    workload: String,
    roles: SharedRoles,
}

impl Gate {
    #[must_use]
    pub fn new(workload: String, roles: SharedRoles) -> Self {
        Self { workload, roles }
    }

    #[must_use]
    pub fn roles(&self) -> &SharedRoles {
        &self.roles
    }

    #[must_use]
    pub fn is_active(&self, now: u64) -> bool {
        self.roles.role_of(&self.workload, now).is_active()
    }

    #[must_use]
    pub fn expires_at(&self) -> Option<u64> {
        self.roles.expires_at(&self.workload)
    }

    #[must_use]
    pub fn remaining(&self) -> Option<std::time::Duration> {
        self.roles.expires_at(&self.workload).map(|expires_at| {
            std::time::Duration::from_millis(expires_at.saturating_sub(now_millis()))
        })
    }

    pub async fn until_lost(&self) {
        let mut version = self.roles.subscribe();
        loop {
            let now = now_millis();
            let Some(expires_at) = self.roles.expires_at(&self.workload) else {
                return;
            };
            let Some(remaining) = expires_at.checked_sub(now) else {
                return;
            };

            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_millis(remaining)) => {}
                changed = version.changed() => {
                    if changed.is_err() {
                        // Nobody holds the sender any more -- the state can
                        // no longer change, so the deadline alone decides.
                        tokio::time::sleep(std::time::Duration::from_millis(remaining)).await;
                        return;
                    }
                }
            }
        }
    }
}

pub async fn guarded<F: std::future::Future<Output = ()>>(gate: Option<&Gate>, work: F) {
    let Some(gate) = gate else {
        work.await;
        return;
    };

    tokio::select! {
        () = work => {}
        () = gate.until_lost() => {
            tracing::warn!("the connection is torn down: the active role has expired (ADR-0066)");
        }
    }
}

const FLOOR: std::time::Duration = std::time::Duration::from_secs(1);

#[must_use]
pub fn next_read(
    remaining: Option<std::time::Duration>,
    ordinary: std::time::Duration,
) -> std::time::Duration {
    let Some(remaining) = remaining else {
        return FLOOR;
    };

    (remaining / 2).clamp(FLOOR, ordinary)
}

pub async fn reload(gate: Gate, path: Option<std::path::PathBuf>, ordinary: std::time::Duration) {
    let Some(path) = path else {
        return;
    };

    // **Immediately**, not only after the first sleep: a metric that appears
    // only in the error case is not distinguishable from a missing one.
    report(&gate);

    loop {
        // **Back before the expiry** -- the deadline stands in the file, and
        // this crate does not know the lease duration (`next_read`).
        let remaining = gate.remaining();
        tokio::time::sleep(next_read(remaining, ordinary)).await;

        let roles = match std::fs::read_to_string(&path) {
            Ok(text) => Roles::from_text(&text),
            Err(err) => {
                tracing::warn!(error = %err, path = %path.display(), "the active role is unreadable");
                Roles::default()
            }
        };
        gate.roles().replace(roles);
        report(&gate);
    }
}

pub fn report(gate: &Gate) {
    let seconds = gate.expires_at().unwrap_or(0) / 1_000;
    // A Prometheus metric **is** an `f64`; it would become imprecise beyond
    // 2^53 seconds, that is, in 285 million years. The same `allow` as with
    // the SVID beside it.
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!(tg_telemetry::names::PROXY_ROLE_EXPIRES_AT).set(seconds as f64);
}
