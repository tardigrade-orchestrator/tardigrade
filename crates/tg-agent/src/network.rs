//! The node network: bridge, addresses, resolver (ADR-0012, ADR-0013,
//! ADR-0039).
//!
//! Here `tg-net` is touched by a process for the first time. Until 9c it was
//! built and checked but started by nothing — the same gap `tg-identity` and
//! `tg-proxy` had after phase 8.
//!
//! # Everything hangs on the ordinal
//!
//! Without it there is no node subnet, without a subnet no bridge address, and
//! without that no resolver. It comes from consensus (ADR-0039) and lies after
//! the renewal beside the rest of the identity material.
//!
//! If it is missing, **the agent does not guess**. Two nodes with the same
//! subnet would be an error one would notice only at the traffic, and a guessed
//! subnet would be exactly that. It says that it lacks the number and leaves the
//! network standing.
//!
//! # Why the failure is not fatal
//!
//! A node without a network can mint, rotate and keep running containers all the
//! same (ADR-0019). That is why this is fail-soft here, like the socket in
//! `start_identity`: it reports, and the agent works on.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tg_defs::Probe;
use tg_net::discovery::{Domain, Endpoint, Health, Registry};
use tg_net::ipam::{ClusterNet, LeaseTable, Leases, Mtu, NodeSubnet};
use tg_net::resolver::{self, Forwarding, Resolver};
use tg_runtime::network::{Attachment, Wiring};
use tg_store::{ActualStatus, Projection};

const LEASES: &str = "network/leases.json";

pub(crate) struct Network {
    cluster: ClusterNet,
    subnet: NodeSubnet,
    domain: Domain,
    leases: Mutex<Leases>,
    data_dir: PathBuf,
    mtu: Mtu,
    resolv_conf: String,
    resolver: Arc<Resolver>,
    egress: PathBuf,
    userns: Option<tg_runtime::userns::Mapping>,
    mesh_udp: PathBuf,
    remote: PathBuf,
    tasks: Vec<Factory>,
}

type Factory = Box<dyn Fn() -> tokio::task::JoinHandle<()> + Send + Sync>;

impl std::fmt::Debug for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("subnet", &self.subnet.net().to_string())
            .finish_non_exhaustive()
    }
}

impl Network {
    fn netns_rules(&self, quic: &[u16]) -> tg_net::rules::NetnsRules {
        // The exception hangs on the sidecar's identifier (ADR-0060,
        // determination 2) -- but on the one the **kernel** sees. Under a user
        // namespace that is not the identifier in the container but its image
        // (ADR-0091, determination 5): whoever took the container identifier here
        // would free nobody, and the sidecar would redirect its own call outwards
        // back onto itself.
        let uid = self
            .userns
            .and_then(|mapping| mapping.host_uid(tg_model::mesh::SIDECAR_UID))
            .unwrap_or(tg_model::mesh::SIDECAR_UID);

        tg_net::rules::NetnsRules::new(&self.cluster, &self.subnet, uid)
            .with_egress(tg_net::rules::SIDECAR_EGRESS)
            .with_quic(quic)
    }

    pub(crate) fn supervise(&mut self, health: &tg_telemetry::probes::Health) {
        let names = [crate::TASK_RESOLVER_UDP, crate::TASK_RESOLVER_TCP];
        for (make, name) in std::mem::take(&mut self.tasks).into_iter().zip(names) {
            let _watcher = tg_telemetry::probes::supervise(health, name, make);
        }
    }

    pub(crate) fn gateway(&self) -> Ipv4Addr {
        self.subnet.gateway()
    }

    pub(crate) fn subnet(&self) -> &NodeSubnet {
        &self.subnet
    }

    pub(crate) fn ensure_rules(&self) {
        // The type is not named: `nftables` is a dependency of `tg-net`, and it
        // shall stay one.
        let rendered = tg_net::rules::HostRules::new(&self.cluster, &self.subnet).render();

        let listed = tg_net::nft::list_table(tg_net::rules::FAMILY, tg_net::rules::TABLE)
            .unwrap_or_default();
        if tg_net::rules::is_applied(&rendered, &listed) {
            return;
        }

        // `warn!`: the rule set belongs to us, and that somebody removed it is
        // an event and no normal state. An operator shall be able to look for the
        // cause -- we only restore.
        tracing::warn!(
            table = tg_net::rules::TABLE,
            "the node's rule set has deviated -- it is being set anew"
        );
        apply_host_rules(&self.cluster, &self.subnet);
    }

    pub(crate) fn refresh(&self, projection: &Projection) {
        let actual = projection.actual_states();
        // The readiness (ADR-0080), as a **second axis** beside the actual
        // state. An instance is resolved only when it runs **and** its declared
        // probe has answered.
        let unready = projection.unready();

        let endpoints = self
            .held()
            .entries()
            .into_iter()
            .map(|lease| Endpoint {
                // **Per instance**, not per name: the address belongs to an
                // instance, so its health must come from it too. Until the
                // projection distinguished instances, a downed instance took all
                // its siblings out of the resolution with it -- or a running one
                // held them all in.
                health: {
                    let key = (lease.workload.clone(), lease.instance);
                    health_of(actual.get(&key), unready.contains(&key))
                },
                workload: lease.workload,
                instance: lease.instance,
                address: lease.address,
            })
            .collect();

        // **The endpoints of foreign workloads** (ADR-0073). They come from the
        // slice that `session::apply` wrote into a file -- the only way on which
        // this node learns an address it did not hand out itself (phase 9a).
        //
        // From the **file** and not over a handle into the resolver: it survives
        // a restart, and if the session stays away, the last known state still
        // applies (ADR-0019).
        let mut endpoints: Vec<Endpoint> = endpoints;
        endpoints.extend(remote_endpoints(&self.remote));

        self.resolver
            .update(Registry::new(self.domain.clone(), endpoints));

        // The forwarding list comes from **the same** file the sidecar reads
        // (ADR-0041, determination 6/7). A second source would be a second
        // opportunity for resolver and enforcement to drift apart -- and then a
        // name the sidecar refuses would resolve, or the other way round.
        //
        // If the file is missing or unreadable, **nothing** is forwarded. That is
        // the same fail-closed grip as with the sidecar's egress port: a boundary
        // outwards that never existed without a permission.
        let hosts = std::fs::read_to_string(&self.egress)
            .ok()
            .and_then(|text| egress_hosts(&text))
            .unwrap_or_default();
        self.resolver.forward_to(Forwarding::new(hosts));
    }

    pub(crate) fn forwarded_names(&self) -> usize {
        self.resolver.forwarded_names()
    }

    pub(crate) fn zone(&self) -> &str {
        self.domain.as_str()
    }

    pub(crate) fn endpoints(&self) -> Vec<tg_store::session::ReportedEndpoint> {
        self.held()
            .entries()
            .into_iter()
            .map(|lease| (lease.workload, lease.instance, lease.address))
            .collect()
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Leases> {
        self.leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Wiring for Network {
    fn attach(&self, workload: &str, instance: u32) -> Result<Attachment, String> {
        // **The namespace is named like the instance's container.** A namespace
        // of its own beside it would be a second derivation from the same pair of
        // name and number -- and two derivations are two opportunities to drift
        // apart. When the sidecar moves in with it (phase 9b), it is the namespace
        // of **its** workload, not of itself.
        let netns = tg_runtime::bundle::container_id(workload, instance);

        // The address first, for the name of the veth pair follows from it
        // (phase 9a). Handing it out is idempotent: the same instance gets the
        // same one again.
        let address = {
            let mut leases = self.held();
            let address = leases
                .lease(workload, instance)
                .map_err(|err| err.to_string())?;
            // Persisted **before** anything happens at the kernel: an address
            // that stands in the kernel and not on the disk the agent would hand
            // out a second time after a restart.
            persist(&self.data_dir, &leases)?;
            address
        };

        let path = tg_net::link::ensure_instance(&netns, address, &self.subnet, self.mtu.get())
            .map_err(|err| err.to_string())?;

        // **The baseline lies at once** (ADR-0093, determination 1). Until here
        // the rule set stayed out entirely until the sidecar started -- and those
        // were two holes: a workload **without** `<mesh>` never got one, and one
        // **with** talked unfiltered between its own start and its sidecar's (the
        // sidecar declares `after` on it).
        //
        // The **redirect** still comes only with the sidecar (`enforce`, ADR-0060
        // determination 3): a redirect without a listener would look like a
        // network problem. For the filters that does not apply -- when the
        // baseline discards anyway, there is nothing to lose.
        //
        // Fail-soft like `enforce`: a node without a rule set is no broken node
        // (ADR-0019). It is said, for without a baseline the instance talks
        // unfiltered, and that is a security statement.
        // **Without QUIC ports**: the baseline carries no redirect (ADR-0093),
        // and without a listener none may lie there either (ADR-0094,
        // determination 4).
        match tg_net::rules::to_json(&self.netns_rules(&[]).render_baseline())
            .map_err(|err| err.to_string())
            .and_then(|json| tg_net::nft::apply_in(&netns, &json).map_err(|err| err.to_string()))
        {
            Ok(()) => tracing::debug!(netns, "the baseline stands"),
            Err(message) => tracing::error!(
                netns,
                error = %message,
                "no baseline -- the instance talks unfiltered (ADR-0093)"
            ),
        }

        Ok(Attachment {
            netns: path,
            resolv_conf: Some(self.resolv_conf.clone()),
        })
    }

    fn enforce(&self, netns: &str, workload: &str) {
        let quic = egress_quic_ports(
            &std::fs::read_to_string(&self.egress).unwrap_or_default(),
            workload,
        );
        let Resolved::Targets(udp) = resolve_udp(&egress_udp_targets(
            &std::fs::read_to_string(&self.egress).unwrap_or_default(),
            workload,
        )) else {
            // **The rule set stays as it is** (ADR-0019). The price stands
            // here: a name that permanently does not resolve freezes this
            // workload's remaining changes too -- the QUIC ports included. A
            // ledger per name would be the refinement.
            return;
        };
        // **The peers from the same file the sidecar reads** (ADR-0142,
        // determination 8). The local port carries which peer was meant.
        let mesh_udp = mesh_udp_rules(
            &std::fs::read_to_string(&self.mesh_udp).unwrap_or_default(),
            workload,
        );
        let rules = self
            .netns_rules(&quic)
            .with_udp(&udp)
            .with_mesh_udp(&mesh_udp);
        let rendered = rules.render();

        // **Asked, not set** -- the same computation as with the node's rule
        // set: asking is about six times cheaper than applying, and an apply
        // clears the table away and builds it anew. Since the redirect follows the
        // allowlist (ADR-0094, determination 3), this runs at **every** pass here;
        // setting at every one would turn a quiet namespace into one whose
        // firewall moves every ten seconds.
        //
        // Unreadable means deviation -- the safe direction.
        if let Ok(listed) =
            tg_net::nft::list_table_in(netns, tg_net::rules::FAMILY, tg_net::rules::TABLE)
            && tg_net::rules::is_applied(&rendered, &listed)
        {
            return;
        }

        let outcome = tg_net::rules::to_json(&rendered)
            .map_err(|err| err.to_string())
            .and_then(|json| tg_net::nft::apply_in(netns, &json).map_err(|err| err.to_string()));

        match outcome {
            Ok(()) => tracing::info!(
                netns,
                quic = quic.len(),
                "the redirect stands -- no way past the sidecar"
            ),
            // Fail-soft: a node without a rule set is no broken node (ADR-0019).
            // It is said all the same -- without a redirect the workload talks
            // past the sidecar, and that is a security statement.
            Err(message) => tracing::error!(
                netns,
                %message,
                "no redirect -- the workload reaches the mesh without its sidecar"
            ),
        }
    }

    fn ensure_baseline(&self, netns: &str) {
        // **Without QUIC ports**: the baseline carries no redirect (ADR-0093),
        // and without a listener none may lie there either (ADR-0094,
        // determination 4).
        let rendered = self.netns_rules(&[]).render_baseline();

        // Asked, not set -- as with `enforce` and for the same reason.
        if let Ok(listed) =
            tg_net::nft::list_table_in(netns, tg_net::rules::FAMILY, tg_net::rules::TABLE)
            && tg_net::rules::is_applied(&rendered, &listed)
        {
            return;
        }

        match tg_net::rules::to_json(&rendered)
            .map_err(|err| err.to_string())
            .and_then(|json| tg_net::nft::apply_in(netns, &json).map_err(|err| err.to_string()))
        {
            Ok(()) => tracing::info!(netns, "the baseline was restored"),
            Err(message) => tracing::error!(
                netns,
                error = %message,
                "no baseline -- the instance talks unfiltered (ADR-0093)"
            ),
        }
    }

    fn probe(&self, container: &str, probe: Probe<'_>) -> Result<(), String> {
        // **The same function the test rig calls** (ADR-0080): two versions
        // would be two opportunities to make them strict differently -- and then
        // a test would check a copy instead of the thing.
        //
        // Which of the two is decided by the **declaration** and no setting of
        // the node (ADR-0102, determination 2): with a path a `GET`, without one
        // a connection attempt. A switch per node would turn the same definition
        // on two nodes into two different probes.
        match probe.path {
            Some(path) => tg_net::probe::get_in(container, probe.port, path),
            None => tg_net::probe::connect_in(container, probe.port),
        }
    }

    fn leased(&self) -> Vec<String> {
        let Ok(leases) = self.leases.lock() else {
            // A poisoned lock means a writer panicked. Reporting nothing is the
            // safe direction here: the clearer then clears nothing away instead
            // of guessing on half a view.
            return Vec::new();
        };

        // **Forwards, never backwards** (ADR-0065): the identifier arises from
        // name and number with the same function that handed it out. From
        // `tg-api-3` it could not be said whether instance 3 of `api` or instance
        // 0 of a workload named `api-3` is meant.
        leases
            .entries()
            .into_iter()
            .map(|lease| tg_runtime::bundle::container_id(&lease.workload, lease.instance))
            .collect()
    }

    fn release(&self, container: &str) {
        let lease = lease_of(&self.held(), container);

        if let Err(err) =
            tg_net::link::release_instance(container, lease.as_ref().map(|lease| lease.address))
        {
            tracing::warn!(container, error = %err, "the network was not fully cleared away");
        }

        let Some(lease) = lease else {
            return;
        };

        let mut leases = self.held();
        leases.release(&lease.workload, lease.instance);
        if let Err(message) = persist(&self.data_dir, &leases) {
            // The address is free in the kernel and still occupied on the disk.
            // That costs an address, not the correctness -- and it is said
            // instead of kept quiet.
            tracing::warn!(container, %message, "the address ledger was not written");
        }
    }
}

fn lease_of(leases: &Leases, container: &str) -> Option<tg_net::ipam::Lease> {
    leases.entries().into_iter().find(|lease| {
        tg_runtime::bundle::container_id(&lease.workload, lease.instance) == container
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ZoneAdvice {
    Fits,
    Shortens {
        longest: usize,
    },
    None,
}

fn zone_advice(domain: &Domain) -> ZoneAdvice {
    match domain.longest_workload_name() {
        Some(longest) if longest < tg_model::mesh::MAX_NAME => ZoneAdvice::Shortens { longest },
        Some(_) => ZoneAdvice::Fits,
        Option::None => ZoneAdvice::None,
    }
}

fn resolv_conf(gateway: Ipv4Addr, domain: &Domain) -> String {
    format!(
        "# tardigrade -- node-local resolver (ADR-0013)\n\
         nameserver {gateway}\n\
         search {domain}\n"
    )
}

const fn health_of(actual: Option<&ActualStatus>, unready: bool) -> Health {
    match actual {
        Some(ActualStatus::Running) if !unready => Health::Healthy,
        _ => Health::Unhealthy,
    }
}

fn remote_endpoints(path: &std::path::Path) -> Vec<Endpoint> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(reported) = serde_json::from_str::<Vec<tg_store::session::RemoteEndpoint>>(&raw) else {
        tracing::warn!(path = %path.display(), "the endpoints are unreadable");
        return Vec::new();
    };

    reported
        .into_iter()
        .map(|endpoint| Endpoint {
            workload: endpoint.workload,
            instance: endpoint.instance,
            address: endpoint.address,
            health: if endpoint.healthy {
                Health::Healthy
            } else {
                Health::Unhealthy
            },
        })
        .collect()
}

fn egress_quic_ports(text: &str, workload: &str) -> Vec<u16> {
    let mut out: Vec<u16> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (owner, _host, port, transport) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next(),
            );

            // Without a fourth word the line means `tcp` (ADR-0092) -- a fixed
            // egress port stands there, no listener of its own.
            (owner == workload && transport == Some("quic"))
                .then(|| port.parse().ok())
                .flatten()
        })
        .collect();
    out.sort_unstable();
    out.dedup();

    out
}

fn egress_udp_targets(text: &str, workload: &str) -> Vec<(String, u16)> {
    let mut out: Vec<(String, u16)> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (owner, host, port, transport) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next(),
            );

            // Without a fourth word the line means `tcp` (ADR-0092) -- and
            // **nothing is guessed** (determination 6): whoever writes `udp` has
            // demanded the coarser enforcement.
            (owner == workload && transport == Some("udp"))
                .then(|| port.parse().ok().map(|port| (host.to_owned(), port)))
                .flatten()
        })
        .collect();
    out.sort_unstable();
    out.dedup();

    out
}

const RESOLVE_WITHIN: std::time::Duration = std::time::Duration::from_secs(2);

enum Resolved {
    Targets(Vec<(std::net::Ipv4Addr, u16)>),
    Unresolved,
}

fn resolve_udp(targets: &[(String, u16)]) -> Resolved {
    let mut out = Vec::new();

    for (host, port) in targets {
        let (host, port) = (host.clone(), *port);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::net::ToSocketAddrs as _;
            let _ = tx.send((host.clone(), port, (host.as_str(), port).to_socket_addrs()));
        });

        let Ok((host, port, looked_up)) = rx.recv_timeout(RESOLVE_WITHIN) else {
            tracing::warn!("UDP target not resolved: time bound -- the rule set stays as it is");
            return Resolved::Unresolved;
        };
        let Ok(addresses) = looked_up else {
            tracing::warn!(%host, port, "UDP target not resolved -- the rule set stays");
            return Resolved::Unresolved;
        };

        let mut found = false;
        for address in addresses {
            if let std::net::IpAddr::V4(v4) = address.ip() {
                out.push((v4, port));
                found = true;
            }
        }
        if !found {
            tracing::warn!(%host, port, "the UDP target has no IPv4 address (ADR-0012)");
        }
    }

    Resolved::Targets(out)
}

fn egress_hosts(text: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for line in text.lines() {
        // Comments and blank lines as in the sidecar (`tg_proxy::options`).
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let mut fields = line.split_whitespace();
        let (Some(_owner), Some(host), Some(port), transport, None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            tracing::warn!(
                line,
                "the egress line is not readable, nothing is forwarded"
            );
            return None;
        };

        if port.parse::<u16>().is_err() {
            tracing::warn!(line, "egress line without a port, nothing is forwarded");
            return None;
        }

        // **An unknown transport is an error, no default** -- exactly as in the
        // sidecar (ADR-0092). Silently pulling it to `tcp` would turn a line the
        // sidecar does not understand into a forwarding.
        if let Some(word) = transport
            && tg_model::egress::Transport::parse(word).is_none()
        {
            tracing::warn!(
                line,
                "egress line with an unknown transport, nothing is forwarded"
            );
            return None;
        }

        out.push(host.to_owned());
    }
    out.sort();
    out.dedup();
    Some(out)
}

pub(crate) fn start(
    data_dir: &Path,
    upstream: Option<SocketAddr>,
    cluster: &ClusterNet,
    domain: &str,
    workloads: &[String],
    userns: Option<tg_runtime::userns::Mapping>,
) -> Result<Network, String> {
    let Some(ordinal) = crate::identity::ordinal(data_dir) else {
        return Err(format!(
            "no ordinal in {} -- without it there is no node subnet (ADR-0039), \
             and it is not guessed",
            crate::identity::dir(data_dir)
                .join(tg_identity::layout::ORDINAL)
                .display()
        ));
    };

    let subnet = cluster.subnet(ordinal).map_err(|err| err.to_string())?;
    let domain = Domain::new(domain).map_err(|err| err.to_string())?;

    // **What this zone still carries** -- said now, not as NXDOMAIN on every
    // query. The zone is checked for itself; only `<name>.<zone>` breaks the 253
    // from RFC 1035, and then the resolver answers NXDOMAIN for **everything** --
    // which looks like "the service does not exist".
    //
    // Fail-soft and no abort (ADR-0019): the node network still carries bridge,
    // addresses and rule set, and a container reaches its neighbours over the
    // address. What is missing is the resolution.
    match zone_advice(&domain) {
        ZoneAdvice::Shortens { longest } => tracing::warn!(
            zone = %domain.as_str(),
            longest_name = longest,
            facet = tg_model::mesh::MAX_NAME,
            "in this zone only a workload name of at most {longest} characters \
             resolves; longer ones yield a query over 253 bytes and thereby \
             NXDOMAIN (RFC 1035). Remedy: a shorter zone or shorter names"
        ),
        ZoneAdvice::None => tracing::error!(
            zone = %domain.as_str(),
            "this zone leaves room for no name -- **nothing** resolves \
             (RFC 1035)"
        ),
        ZoneAdvice::Fits => {}
    }
    let mtu = Mtu::for_overlay(1500).map_err(|err| err.to_string())?;

    tg_net::link::ensure_bridge(&subnet, mtu.get()).map_err(|err| err.to_string())?;
    apply_host_rules(cluster, &subnet);

    let mut leases = restore(data_dir, &subnet)?;
    for workload in workloads {
        leases
            .lease(workload, 0)
            .map_err(|err| format!("no address for '{workload}': {err}"))?;
    }
    persist(data_dir, &leases)?;

    let resolver = Arc::new(Resolver::new(Registry::new(domain.clone(), Vec::new())));
    let listen = SocketAddr::from((subnet.gateway(), resolver::PORT));

    let udp = std::net::UdpSocket::bind(listen)
        .map_err(|err| format!("the resolver on {listen} (UDP): {err}"))?;
    let tcp = std::net::TcpListener::bind(listen)
        .map_err(|err| format!("the resolver on {listen} (TCP): {err}"))?;
    udp.set_nonblocking(true).map_err(|err| err.to_string())?;
    tcp.set_nonblocking(true).map_err(|err| err.to_string())?;

    // **Shared instead of consumed** (ADR-0116): the watcher sets a panicked
    // task up again, and it gets the same socket. Binding anew would be a window
    // in which this address's port is free -- and every container of this node
    // knows it (ADR-0013).
    let udp = Arc::new(tokio::net::UdpSocket::from_std(udp).map_err(|err| err.to_string())?);
    let tcp = Arc::new(tokio::net::TcpListener::from_std(tcp).map_err(|err| err.to_string())?);

    // **A `let _ =` stood here, and that was the place at which the service's
    // death disappeared.** Both loops returned an `io::Result<()>` and ended at
    // the first failure; the error was discarded. A single `EMFILE` thereby took
    // name resolution (ADR-0013) from every container of this node, for the
    // lifetime of the agent, without a word in the log. The empty `match` nails
    // down that this outcome no longer exists.
    //
    // **Factories instead of handles** (ADR-0116, determination 2): the watcher
    // starts them itself and again. The binding stays **here** -- a resolver that
    // does not get its address is a startup error and shall be loud; a restart
    // behind the watcher means the panic, not the configuration.
    let serve_udp = {
        let resolver = Arc::clone(&resolver);
        let socket = Arc::clone(&udp);
        move || {
            let resolver = Arc::clone(&resolver);
            let socket = Arc::clone(&socket);
            tokio::spawn(
                async move { match resolver::serve_udp(resolver, socket, upstream).await {} },
            )
        }
    };
    let serve_tcp = {
        let resolver = Arc::clone(&resolver);
        let listener = Arc::clone(&tcp);
        move || {
            let resolver = Arc::clone(&resolver);
            let listener = Arc::clone(&listener);
            tokio::spawn(
                async move { match resolver::serve_tcp(resolver, listener, upstream).await {} },
            )
        }
    };
    let tasks: Vec<Factory> = vec![Box::new(serve_udp), Box::new(serve_tcp)];

    // **From `Paths`**: `session::apply` writes the same files from the slice
    // (ADR-0040), and two sources would let the reader point at a path nobody
    // ever writes.
    let paths = crate::session::Paths::new(data_dir);
    let network = Network {
        resolv_conf: resolv_conf(subnet.gateway(), &domain),
        cluster: cluster.clone(),
        subnet,
        domain,
        leases: Mutex::new(leases),
        data_dir: data_dir.to_path_buf(),
        mtu,
        resolver,
        egress: paths.egress(),
        mesh_udp: paths.mesh_udp(),
        userns,
        remote: paths.endpoints(),
        tasks,
    };

    // The names stand in the resolution **at once**, all as not healthy. Without
    // that the resolver answered NXDOMAIN until the first reconcile pass -- "the
    // name does not exist" --, although it does. A client that asks in this gap
    // cached the negative result, and the short deadline from ADR-0013 would not
    // bite at all, because it is meant only for NODATA.
    network.refresh(&Projection::new());

    Ok(network)
}

fn apply_host_rules(cluster: &ClusterNet, subnet: &NodeSubnet) {
    let rules = tg_net::rules::HostRules::new(cluster, subnet);

    let outcome = tg_net::rules::to_json(&rules.render())
        .map_err(|err| err.to_string())
        .and_then(|json| tg_net::nft::apply(&json).map_err(|err| err.to_string()));

    match outcome {
        Ok(()) => tracing::info!(
            table = tg_net::rules::TABLE,
            rules = rules.forward_statements().len(),
            "the node's rule set stands"
        ),
        Err(message) => tracing::warn!(
            %message,
            "no rule set for the node -- no masquerading outwards, and the \
             bridge is not shielded from outside"
        ),
    }
}

fn restore(data_dir: &Path, subnet: &NodeSubnet) -> Result<Leases, String> {
    let path = data_dir.join(LEASES);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Ok(Leases::new(subnet.clone()));
    };
    let Ok(table) = serde_json::from_str::<LeaseTable>(&raw) else {
        return Err(format!("{} is unreadable", path.display()));
    };

    match Leases::restore(subnet.clone(), table) {
        Ok(leases) => Ok(leases),
        Err(err) => {
            tracing::warn!(
                error = %err,
                "address ledger discarded -- this node presumably has a new \
                 ordinal (ADR-0039)"
            );
            Ok(Leases::new(subnet.clone()))
        }
    }
}

fn persist(data_dir: &Path, leases: &Leases) -> Result<(), String> {
    let path = data_dir.join(LEASES);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }

    let text = serde_json::to_string(&leases.snapshot()).map_err(|err| err.to_string())?;

    // **Atomic, like the rest of the tree.** `fs::write` truncates first and
    // then writes; an abort in between leaves half a file -- and `restore`
    // refuses that hard, because a discarded ledger would hand out addresses anew
    // that running containers still hold. The node would then no longer reach the
    // network until somebody removes the file.
    let temp = path.with_extension("json.new");
    std::fs::write(&temp, text).map_err(|err| format!("{}: {err}", temp.display()))?;
    std::fs::rename(&temp, &path).map_err(|err| format!("{}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{lease_of, resolv_conf};
    use std::net::Ipv4Addr;
    use tg_net::discovery::Domain;
    use tg_net::ipam::{ClusterNet, Leases};

    fn leases() -> Leases {
        let cluster = ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24).expect("valid");
        Leases::new(cluster.subnet(1).expect("valid"))
    }

    #[test]
    fn a_container_id_finds_its_lease() {
        let mut leases = leases();
        let address = leases.lease("api", 3).expect("enough room");

        let found = lease_of(&leases, "tg-api-3").expect("found");

        assert_eq!(found.workload, "api");
        assert_eq!(found.instance, 3);
        assert_eq!(found.address, address);
    }

    #[test]
    fn two_workloads_can_derive_the_same_container_id() {
        let mut only_the_second = leases();
        let address = only_the_second.lease("api-3", 0).expect("enough room");

        let found = lease_of(&only_the_second, "tg-api-3").expect("found");

        assert_eq!(found.workload, "api-3");
        assert_eq!(found.instance, 0);
        assert_eq!(found.address, address);
    }

    #[test]
    fn an_unknown_container_has_no_lease() {
        let mut leases = leases();
        leases.lease("api", 0).expect("enough room");

        assert!(lease_of(&leases, "tg-ledger").is_none());
        // And instance 0 is called `tg-api`, not `tg-api-0` -- the spelling from
        // `container_id` applies here too.
        assert!(lease_of(&leases, "tg-api-0").is_none());
    }

    #[test]
    fn the_resolv_conf_names_the_resolver_and_the_zone() {
        let text = resolv_conf(
            Ipv4Addr::new(10, 42, 1, 1),
            &Domain::new("tardigrade.internal").expect("zone"),
        );

        assert!(text.contains("nameserver 10.42.1.1"), "{text}");
        assert!(text.contains("search tardigrade.internal"), "{text}");
    }

    #[test]
    fn an_unreadable_inventory_is_refused_not_discarded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let subnet = ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24)
            .expect("valid")
            .subnet(1)
            .expect("valid");

        std::fs::create_dir_all(dir.path().join("network")).expect("directory");
        std::fs::write(dir.path().join(super::LEASES), "{\"leases\":[{\"work")
            .expect("half a file");

        let err = super::restore(dir.path(), &subnet).expect_err("half a ledger is a finding");
        assert!(err.contains("unreadable"), "{err}");
    }

    #[test]
    fn a_missing_inventory_is_simply_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let subnet = ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24)
            .expect("valid")
            .subnet(1)
            .expect("valid");

        let leases = super::restore(dir.path(), &subnet).expect("no ledger is no error");
        assert!(leases.entries().is_empty());
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::health_of;
    use tg_net::discovery::Health;
    use tg_store::projection::ActualStatus;

    #[test]
    fn running_and_ready_resolves() {
        assert_eq!(
            health_of(Some(&ActualStatus::Running), false),
            Health::Healthy
        );
    }

    #[test]
    fn running_but_unready_does_not_resolve() {
        assert_eq!(
            health_of(Some(&ActualStatus::Running), true),
            Health::Unhealthy
        );
    }

    #[test]
    fn what_does_not_run_never_resolves() {
        for status in [
            ActualStatus::Stopped,
            ActualStatus::Failed,
            ActualStatus::Unknown,
        ] {
            assert_eq!(
                health_of(Some(&status), false),
                Health::Unhealthy,
                "{status:?}"
            );
            assert_eq!(
                health_of(Some(&status), true),
                Health::Unhealthy,
                "{status:?}"
            );
        }
        assert_eq!(health_of(None, false), Health::Unhealthy, "never seen");
    }
}

#[cfg(test)]
mod quic_tests {
    use super::egress_quic_ports;

    #[test]
    fn only_the_own_quic_ports_become_a_redirect() {
        let text = "\
api      s3.example.com   443  quic
api      logs.example.com 8443 quic
api      backup.example   443  quic
api      api.partner      9443 tcp
api      old.example      7443
foreign  secret.example   443  quic
";

        assert_eq!(egress_quic_ports(text, "api"), vec![443, 8443]);
    }

    #[test]
    fn a_workload_without_a_quic_permission_gets_no_redirect() {
        let text = "api s3.example.com 443 tcp\nforeign s3.example.com 443 quic\n";

        assert!(egress_quic_ports(text, "api").is_empty());
        assert!(egress_quic_ports("", "api").is_empty());
    }

    #[test]
    fn a_broken_line_does_not_take_the_sound_ones() {
        let text = "api broken\napi s3.example.com notanumber quic\napi ok.example 443 quic\n";

        assert_eq!(egress_quic_ports(text, "api"), vec![443]);
    }
}

#[cfg(test)]
mod udp_tests {
    use super::egress_udp_targets;

    #[test]
    fn only_the_udp_lines_of_this_workload_count() {
        let text = "api ntp.test 123 udp\n\
                    api s3.test 443 quic\n\
                    api old.test 443\n\
                    foreign syslog.test 514 udp\n";

        assert_eq!(
            egress_udp_targets(text, "api"),
            vec![("ntp.test".to_owned(), 123)]
        );
    }

    #[test]
    fn a_line_without_a_transport_opens_no_udp() {
        assert!(egress_udp_targets("api ntp.test 123\n", "api").is_empty());
        assert!(egress_udp_targets("", "api").is_empty());
    }

    #[test]
    fn repeated_targets_collapse() {
        let text = "api b.test 514 udp\napi a.test 123 udp\napi b.test 514 udp\n";

        assert_eq!(
            egress_udp_targets(text, "api"),
            vec![("a.test".to_owned(), 123), ("b.test".to_owned(), 514)]
        );
    }
}

#[cfg(test)]
mod forwarding_agrees {
    use super::egress_hosts;

    fn sidecar_accepts(text: &str, workload: &str) -> bool {
        tg_proxy::options::egress_from_text(text, workload).is_ok()
    }

    #[test]
    fn what_the_sidecar_refuses_is_not_forwarded() {
        for line in [
            "api broken.test\n",
            "api x.test abc\n",
            "api y.test 443 quic-v2\n",
            "api z.test 443 tcp extra\n",
        ] {
            assert!(
                !sidecar_accepts(line, "api"),
                "the sidecar accepts '{line}' -- then this test checks something else"
            );
            assert_eq!(
                egress_hosts(line),
                None,
                "the resolver forwards what the sidecar refuses: {line}"
            );
        }
    }

    #[test]
    fn a_comment_forwards_nothing() {
        let text = "# api secret.test 443\n";
        assert!(sidecar_accepts(text, "api"));
        assert_eq!(egress_hosts(text), Some(Vec::new()));
    }

    #[test]
    fn what_the_sidecar_accepts_is_forwarded() {
        let text = "api s3.test 443 quic\nforeign db.test 5432\n";
        assert!(sidecar_accepts(text, "api"));
        assert_eq!(
            egress_hosts(text),
            Some(vec!["db.test".to_owned(), "s3.test".to_owned()]),
            "the resolver serves all workloads of the node"
        );
    }
}

#[cfg(test)]
mod zone_tests {
    use super::{ZoneAdvice, zone_advice};
    use tg_net::discovery::Domain;

    fn zone(total: usize) -> Domain {
        let mut bytes = vec![b'z'; total];
        let mut at = 63;
        while at < total - 1 {
            bytes[at] = b'.';
            at += 64;
        }
        let raw = String::from_utf8(bytes).expect("ASCII");
        assert_eq!(
            raw.len(),
            total,
            "the fixture does not have the wanted length"
        );
        Domain::new(&raw).expect("zone")
    }

    #[test]
    fn a_zone_says_how_much_room_it_leaves() {
        let short = Domain::new("tardigrade.internal").expect("zone");
        assert_eq!(zone_advice(&short), ZoneAdvice::Fits);

        // 253 - 63 - 1 = 189: from here less than a whole label is left.
        let tight = zone(190);
        assert_eq!(
            zone_advice(&tight),
            ZoneAdvice::Shortens { longest: 62 },
            "253 - 190 - 1 = 62"
        );

        // And the edge: exactly one character is left.
        let last = zone(251);
        assert_eq!(zone_advice(&last), ZoneAdvice::Shortens { longest: 1 });

        // 252 leaves nothing over -- **nothing** resolves.
        let full = zone(252);
        assert_eq!(zone_advice(&full), ZoneAdvice::None);
    }
    #[test]
    fn the_resolver_and_the_search_list_share_one_zone() {
        let source = include_str!("network.rs");
        let prod = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);

        assert_eq!(
            prod.matches("Domain::new(").count(),
            1,
            "there is more than one zone in the node network -- then a bare name \
             no longer resolves on every node, and ADR-0106 is to be decided anew"
        );
        for consumer in [
            "resolv_conf(subnet.gateway(), &domain)",
            "Registry::new(domain",
        ] {
            assert!(
                prod.contains(consumer),
                "'{consumer}' no longer gets the zone -- the same question"
            );
        }
    }
}

fn mesh_udp_rules(text: &str, workload: &str) -> Vec<(std::net::Ipv4Addr, u16)> {
    let mut out: Vec<(std::net::Ipv4Addr, u16)> = text
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut fields = line.split_whitespace();
            let (owner, _peer, endpoint, local) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );

            if owner != workload {
                return None;
            }

            // The address without the port: that is the sidecars' **fixed**
            // listening port and does not stand in the rule -- what is redirected
            // is by destination address, and where the sidecar then connects is
            // its business.
            let address = endpoint.split(':').next()?.parse().ok()?;

            Some((address, local.parse().ok()?))
        })
        .collect();
    out.sort_unstable();
    out.dedup();

    out
}

#[cfg(test)]
mod mesh_udp_tests {
    use super::mesh_udp_rules;

    #[test]
    fn only_our_own_peers_become_rules() {
        let text = "\
# comment
api      ledger 10.42.1.5:15007 15100
api      audit  10.42.2.7:15007 15101
api-test ledger 10.42.9.9:15007 15100
batch    ledger 10.42.3.3:15007 15100
";

        assert_eq!(
            mesh_udp_rules(text, "api"),
            vec![
                ("10.42.1.5".parse().expect("address"), 15100),
                ("10.42.2.7".parse().expect("address"), 15101),
            ]
        );
    }

    #[test]
    fn the_rule_carries_the_address_not_the_peers_port() {
        let rules = mesh_udp_rules("api ledger 10.42.1.5:15007 15100", "api");

        assert_eq!(rules, vec![("10.42.1.5".parse().expect("address"), 15100)]);
    }

    #[test]
    fn a_broken_line_costs_its_line_and_not_the_file() {
        let text = "\
api ledger 10.42.1.5:15007 15100
api broken
api audit  no-address 15101
api dritte 10.42.2.7:15007 15102
";

        assert_eq!(
            mesh_udp_rules(text, "api"),
            vec![
                ("10.42.1.5".parse().expect("address"), 15100),
                ("10.42.2.7".parse().expect("address"), 15102),
            ]
        );
    }

    #[test]
    fn without_a_file_there_are_no_rules() {
        assert!(mesh_udp_rules("", "api").is_empty());
    }
}
