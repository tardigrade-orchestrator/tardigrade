//! Thread-per-core for the data plane (ADR-0022).
//!
//! ADR-0022 fixes: "tokio in the thread-per-core model (one current-thread
//! runtime per core, pinned) for `tg-proxy`. The control plane stays tokio
//! multi-thread." And it leaves one point open: "fix the sharding strategy
//! (connections <-> cores)."
//!
//! # The determination: `SO_REUSEPORT`, one listener per shard
//!
//! Every shard opens **its own** socket on the same address. The kernel
//! distributes incoming connections over the accept queues; a connection
//! thereby lands on exactly one shard and stays there -- together with its TLS
//! state, its buffers and its guard.
//!
//! The alternative would be an acceptor that passes connections on to shards.
//! It costs one handover per connection and makes the acceptor the bottleneck
//! -- precisely the serialization thread-per-core sets out against.
//! `SO_REUSEPORT` costs nothing and needs no coordinator.
//!
//! The price, so that nobody has to look for it: the distribution is the
//! kernel's (a hash over the four-tuple), not a load balancer's. One shard can
//! get more than another. With many short connections that averages out; with
//! few long ones it does not. For a sidecar that carries **one** workload's
//! connections the second case is the more likely -- and that is why a number
//! stands here that one can set smaller.
//!
//! # The pinning: a setting, not a default
//!
//! ADR-0022 said "pinned" as part of the decision. It was never built, and the
//! reason stood here for years: without the benchmark the same ADR demands, it
//! would be a setting one makes because it stands in a document.
//!
//! **The benchmark is built** (`cargo xtask bench`), and it showed no tail
//! difference -- not for the pinning either, which in one of six sets even had
//! the worst p99.9. **ADR-0114 determination 3** turns that into an express
//! setting per node with default **off**, in ADR-0091's construction.
//!
//! Two reasons stand against the default and one for the setting:
//!
//! - **Whoever is the only one nailed down loses.** A pinned shard on an
//!   occupied core cannot move aside, an unpinned one can.
//! - **The sidecar's neighbour is its own workload** -- it shares machine and
//!   namespace with it (ADR-0059).
//! - **But whoever has partitioned their node CPUs** (`cpuset.cpus` for the
//!   sidecar; `cpu.max` stays out per ADR-0086) wants precisely this
//!   behaviour, and then it is right.
//!
//! Pinning therefore happens over the set [`allowed_cores`] delivers -- what
//! the cgroup **concedes** to this process --, not over
//! `available_parallelism`: a number does not say which cores are permitted.

use std::io;
use std::net::SocketAddr;

#[must_use]
pub fn available_shards() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

#[must_use]
pub fn allowed_cores() -> Vec<usize> {
    let Ok(set) = rustix::thread::sched_getaffinity(None) else {
        tracing::warn!("the affinity mask is not readable -- core 0 applies");
        return vec![0];
    };

    let cores: Vec<usize> = (0..rustix::thread::CpuSet::MAX_CPU)
        .filter(|cpu| set.is_set(*cpu))
        .collect();

    if cores.is_empty() {
        tracing::warn!("an empty affinity mask -- core 0 applies");
        return vec![0];
    }

    cores
}

fn pin_to_allowed(shard: usize) {
    let cores = allowed_cores();
    // `allowed_cores` never returns an empty list.
    let core = cores[shard % cores.len()];

    let mut set = rustix::thread::CpuSet::new();
    set.set(core);
    match rustix::thread::sched_setaffinity(None, &set) {
        Ok(()) => tracing::debug!(shard, core, "the shard is pinned"),
        Err(err) => tracing::warn!(shard, core, error = %err, "the shard is not pinned"),
    }
}

pub fn reuseport_listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    // Both options, and they do different things: `reuse_address` permits
    // binding onto a port in TIME_WAIT, `reuse_port` permits **several**
    // listening sockets. Only the second carries the sharding.
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    Ok(socket.into())
}

pub struct Shards {
    count: usize,
    on_start: Option<Box<dyn Fn(usize) + Send + Sync>>,
}

impl std::fmt::Debug for Shards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shards")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl Shards {
    #[must_use]
    pub fn all_cores() -> Self {
        Self {
            count: available_shards(),
            on_start: None,
        }
    }

    #[must_use]
    pub fn exactly(count: usize) -> Self {
        Self {
            count: count.max(1),
            on_start: None,
        }
    }

    #[must_use]
    pub fn on_start(mut self, hook: impl Fn(usize) + Send + Sync + 'static) -> Self {
        self.on_start = Some(Box::new(hook));

        self
    }

    #[must_use]
    pub fn pinned(self, pinned: bool) -> Self {
        if pinned {
            self.on_start(pin_to_allowed)
        } else {
            self
        }
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    pub fn run<F, Fut>(self, make: F) -> io::Result<()>
    where
        F: Fn(usize) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()>,
    {
        let make = std::sync::Arc::new(make);
        let hook = self.on_start.map(std::sync::Arc::new);
        let mut threads = Vec::with_capacity(self.count);

        for shard in 0..self.count {
            let make = std::sync::Arc::clone(&make);
            let hook = hook.clone();

            threads.push(
                std::thread::Builder::new()
                    .name(format!("tg-proxy-{shard}"))
                    .spawn(move || {
                        if let Some(hook) = hook {
                            hook(shard);
                        }

                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build();
                        match runtime {
                            Ok(runtime) => runtime.block_on(make(shard)),
                            Err(err) => {
                                tracing::error!(shard, error = %err, "a shard without a runtime");
                            }
                        }
                    })?,
            );
        }

        for thread in threads {
            // A shard that panics does not tear the process down with it --
            // the rest carry on. That is the same attitude as in ADR-0019: a
            // partial outage is no total outage.
            //
            // **What carries this assurance is the release profile**
            // (ADR-0082): with `panic = "abort"` -- the default from phase 0's
            // scaffolding -- the sentence was plainly false in the shipped
            // binary, and the guard against it lies in `tg-syscall`.
            let _ = thread.join();
        }

        Ok(())
    }
}
