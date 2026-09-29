//! Liveness and readiness (ADR-0015) — and why they are **not** the same.
//!
//! This is the place in this phase with the greatest potential for damage, and
//! it looks harmless. An orchestrator that restarts a process because a probe
//! is red does so on **every** node at once when the cause is cluster-wide.
//! Hence a rule stands here that follows from ADR-0019 and must not be
//! violated:
//!
//! > **Quorum loss makes a node not-ready, not dead.**
//!
//! A `tgd` without quorum cannot decide new placements — it is rightly **not
//! ready**. It is, however, fully **alive**: its running workloads keep
//! running, its agent works from the local cache, its sidecars enforce from the
//! policy cache. Whoever hung liveness on the quorum would get a cluster-wide
//! restart out of a partition — exactly the fail-closed that ADR-0019
//! excludes.
//!
//! From that follows the division:
//!
//! - **Liveness** is a statement about the **process**: are its loops still
//!   running? It knows no cluster states. Red means "restart me", and that may
//!   only be true if a restart really helps.
//! - **Readiness** is a statement about the **task**: can this process right
//!   now do what it is there for? Red means "send me nothing", not "kill me".
//!
//! Liveness is therefore a **watchdog** and not a collection of flags: a loop
//! that stands still does not report — it also does not report that it is
//! unwell. A flag somebody would have to set would stay green precisely when
//! nobody is left to set it.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    pub ready: bool,
    pub detail: String,
}

impl Readiness {
    #[must_use]
    pub fn up() -> Self {
        Self {
            ready: true,
            detail: String::new(),
        }
    }

    #[must_use]
    pub fn down(detail: impl Into<String>) -> Self {
        Self {
            ready: false,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone)]
struct Watch {
    tolerance: Duration,
    last: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct Health {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Default)]
struct Inner {
    ready: BTreeMap<&'static str, Readiness>,
    watches: BTreeMap<&'static str, Watch>,
    refresh: BTreeMap<&'static str, Box<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The refreshes are closures and have no representation; their
        // **names** are the information that matters.
        out.debug_struct("Inner")
            .field("ready", &self.ready)
            .field("watches", &self.watches)
            .field("refresh", &self.refresh.keys().collect::<Vec<_>>())
            .finish()
    }
}

pub fn report_protocol(health: &Health, fields: u32) {
    let value = f64::from(fields);
    metrics::gauge!(crate::names::PROTOCOL_FIELDS).set(value);
    health.on_scrape(crate::names::PROTOCOL_FIELDS, move || {
        metrics::gauge!(crate::names::PROTOCOL_FIELDS).set(value);
    });
}

impl Health {
    pub fn on_scrape(&self, name: &'static str, refresh: impl Fn() + Send + Sync + 'static) {
        // The same reading as this file's other accesses: a poisoned lock does
        // not take the registration instead of taking the caller with it
        // (ADR-0019).
        // `insert` **replaces**: a second call under the same name supersedes
        // the first. `supervise` rests on that when a task dies.
        if let Ok(mut inner) = self.inner.write() {
            inner.refresh.insert(name, Box::new(refresh));
        }
    }

    pub fn refresh(&self) {
        if let Ok(inner) = self.inner.read() {
            for refresh in inner.refresh.values() {
                refresh();
            }
        }
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, name: &'static str, state: Readiness) {
        if let Ok(mut inner) = self.inner.write() {
            inner.ready.insert(name, state);
        }
    }

    pub fn watch(&self, name: &'static str, tolerance: Duration, now: Duration) {
        if let Ok(mut inner) = self.inner.write() {
            inner.watches.insert(
                name,
                Watch {
                    tolerance,
                    last: now,
                },
            );
        }
    }

    pub fn beat(&self, name: &'static str, now: Duration) {
        if let Ok(mut inner) = self.inner.write()
            && let Some(watch) = inner.watches.get_mut(name)
        {
            watch.last = now;
        }
    }

    #[must_use]
    pub fn liveness(&self, now: Duration) -> Probe {
        let Ok(inner) = self.inner.read() else {
            // A poisoned lock means a writer has panicked. That is exactly the
            // case in which a restart helps.
            return Probe {
                ok: false,
                lines: vec![("health".to_owned(), "lock poisoned".to_owned())],
            };
        };

        let mut lines = Vec::new();
        let mut ok = true;

        for (name, watch) in &inner.watches {
            let idle = now.saturating_sub(watch.last);
            if idle > watch.tolerance {
                ok = false;
                lines.push((
                    (*name).to_owned(),
                    format!(
                        "{}s without a sign of life, tolerated are {}s",
                        idle.as_secs(),
                        watch.tolerance.as_secs()
                    ),
                ));
            } else {
                lines.push(((*name).to_owned(), format!("{}s", idle.as_secs())));
            }
        }

        Probe { ok, lines }
    }

    #[must_use]
    pub fn readiness(&self) -> Probe {
        let Ok(inner) = self.inner.read() else {
            return Probe {
                ok: false,
                lines: vec![("health".to_owned(), "lock poisoned".to_owned())],
            };
        };

        // A process without registered sub-tasks is **not** ready. It has
        // reported nothing, and "reported nothing" is no assurance.
        let mut ok = !inner.ready.is_empty();
        let mut lines = Vec::new();

        for (name, state) in &inner.ready {
            if !state.ready {
                ok = false;
            }
            lines.push((
                (*name).to_owned(),
                if state.ready {
                    "ready".to_owned()
                } else if state.detail.is_empty() {
                    "not ready".to_owned()
                } else {
                    format!("not ready: {}", state.detail)
                },
            ));
        }

        if lines.is_empty() {
            lines.push(("health".to_owned(), "nothing registered".to_owned()));
        }

        Probe { ok, lines }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub ok: bool,
    pub lines: Vec<(String, String)>,
}

impl Probe {
    #[must_use]
    pub fn body(&self) -> String {
        let mut out = String::from(if self.ok { "ok\n" } else { "not ok\n" });
        for (name, detail) in &self.lines {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(detail);
            out.push('\n');
        }
        out
    }
}

const RESTART_FLOOR: std::time::Duration = std::time::Duration::from_secs(1);

const RESTART_CEILING: std::time::Duration = std::time::Duration::from_mins(1);

const RESTART_SETTLED: std::time::Duration = std::time::Duration::from_mins(5);

#[must_use]
pub fn supervise<F>(health: &Health, name: &'static str, make: F) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> tokio::task::JoinHandle<()> + Send + 'static,
{
    // **The first start runs here, not in the watcher.** Otherwise `TASK_ALIVE`
    // would stand only once the watcher first gets its turn — and on a busy
    // runtime that would be a window in which the task runs and the metric is
    // missing. Measured on a test that never left exactly this window.
    let mut task = make();
    alive(health, name);

    let health = health.clone();
    tokio::spawn(async move {
        let mut backoff = RESTART_FLOOR;

        loop {
            let started = tokio::time::Instant::now();
            let outcome = task.await;
            let ran = started.elapsed();

            let reason = match &outcome {
                Ok(()) => "the task returned".to_owned(),
                Err(err) if err.is_panic() => "the task panicked".to_owned(),
                Err(err) => format!("the task was aborted: {err}"),
            };
            dead(&health, name, reason.clone());

            // **A return is a decision of the task**, not a failure — and
            // aborting happens from within, during shutdown (ADR-0116,
            // determination 1).
            let Err(err) = outcome else {
                tracing::error!(task = name, %reason, "task ended, it will not be restarted");
                return;
            };
            if !err.is_panic() {
                tracing::info!(task = name, %reason, "task aborted");
                return;
            }

            // **Only after a while does it count as settled** — otherwise a
            // restart that panics again at once would count as a success, and
            // the backoff would stay at one second forever.
            if ran >= RESTART_SETTLED {
                backoff = RESTART_FLOOR;
            }
            tracing::error!(
                task = name,
                %reason,
                ran_secs = ran.as_secs(),
                in_secs = backoff.as_secs(),
                "task panicked, it will be restarted"
            );

            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RESTART_CEILING);

            metrics::counter!(crate::names::TASK_RESTARTS, "task" => name).increment(1);
            task = make();
            alive(&health, name);
        }
    })
}

fn alive(health: &Health, name: &'static str) {
    health.set(name, Readiness::up());
    metrics::gauge!(crate::names::TASK_ALIVE, "task" => name).set(1.0);
    health.on_scrape(name, move || {
        metrics::gauge!(crate::names::TASK_ALIVE, "task" => name).set(1.0);
    });
}

fn dead(health: &Health, name: &'static str, reason: String) {
    health.on_scrape(name, move || {
        metrics::gauge!(crate::names::TASK_ALIVE, "task" => name).set(0.0);
    });
    metrics::gauge!(crate::names::TASK_ALIVE, "task" => name).set(0.0);
    health.set(name, Readiness::down(reason));
}
