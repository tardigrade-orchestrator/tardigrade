//! The node-agent binary.
//!
//! ADR-0019. On its node the agent is **locally authoritative**: it reads the
//! desired state from the persisted cache and reconciles it — without a control
//! plane, without a network (apart from the image pull).
//!
//! Phase 4 turns that into a **level-triggered continuous loop** (ADR-0010):
//! every pass compares actual with desired and reconciles the difference,
//! without an event queue. Every action runs through the autonomy boundary —
//! without a quorum things are kept and restarted, but nothing is placed and
//! nothing mutated cluster-wide.
//!
//! A single pass (`--once`) is kept: it is the proof for the acceptance
//! criterion from phase 2 that a restart reconstructs the state from the local
//! cache alone.

#![forbid(unsafe_code)]
// **No panic-capable call in the production path** (ADR-0082): since then a
// panic costs its task and not the node -- and that is a state an operator sees
// only at a metric. `not(test)`, because the unit tests in `src` need them; the
// guard lies in `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

mod capacity;
mod cluster;
mod devices;
mod endpoints;
mod identity;
mod join;
mod network;
mod registries;
mod rotate;
mod secrets;
mod session;
mod sockets;
mod underlay;

use std::path::PathBuf;
use std::process::ExitCode;

use std::time::Duration;

use tg_identity::TrustDomain;
use tg_model::Quorum;
use tg_model::mesh::SidecarSpec;
use tg_runtime::oci::{DEFAULT_RUNTIMES, OciRuntime};
use tg_runtime::state::DesiredState;
use tg_runtime::{NodePaths, reconcile};
use tg_store::{ActualStatus, Projection};
use tg_telemetry::args::Args as TelemetryArgs;
use tg_telemetry::probes::{Health, Readiness};

const USAGE: &str = "\
tg-agent — the node agent for Tardigrade

Calls:
  tg-agent                  reconcile loop against the local cache
  tg-agent --once           exactly one pass, then exit
  tg-agent help|-h|--help   this overview

Options:
  --data-dir <path>         data directory (default: /var/lib/tardigrade)
  --interval <seconds>      distance between passes (default: 10)
  --keep-snapshots <n>      how many snapshot generations stay per volume
                            (ADR-0099, default: 3; 0 means all). The
                            **retention period** is thereby not set -- it
                            couples to ADR-0020 like every other retention
                            question.
  --no-quorum               treat the control plane as unreachable
  --userns-base <number>    put containers into a user namespace (ADR-0091):
                            identifier 0 in the container becomes <number> on
                            the node. Demands a runtime that can enter a netns
                            over a path from inside the user namespace --
                            measured, crun can and youki cannot. Without the
                            setting uid 0 in the container is uid 0 on the node
  --no-seccomp              leave the seccomp profile out (ADR-0090). Only for
                            a workload that legitimately needs a blocked call
                            -- it then applies to **all** containers of this
                            node, and the start reports it (ADR-0010).
                            Measured, that changes nothing today: every action
                            this agent checks is autonomous
  --trust-domain <name>     trust domain of the SVIDs (default: cluster.local)
  --cluster-cidr <cidr>     address space of all containers (default:
                            10.42.0.0/16)
  --node-prefix <n>         prefix length per node (default: 24)
  --dns-domain <name>       zone of the resolver (default: tardigrade.internal)
  --dns-forward <address>   upstream for permitted egress names (ADR-0041);
                            without the setting nothing is forwarded
  --underlay-endpoint <address>
                            this node's externally reachable UDP endpoint, e.g.
                            10.0.0.7:51820. With this setting the agent
                            announces its WireGuard underlay at every renewal
                            (ADR-0039/0042); without it, it announces nothing.
  --proxy-image <ref>       image of the sidecar (ADR-0007). Without this
                            setting no sidecars are derived and no identities
                            delegated (ADR-0036).
  --cdi-dir <path>          where the CDI specifications lie (ADR-0143, builds
                            ADR-0028). Repeatable; without a setting /etc/cdi
                            and /var/run/cdi apply. That none exists is no
                            error -- a node without an accelerator is the
                            normal case. What is read is JSON; a refused spec
                            is reported at startup.
  --pin-sidecar-shards      pin the sidecars' shards to fixed cores (ADR-0114).
                            Default off: measured, it brings no tail advantage,
                            and whoever is the only one nailed down can no
                            longer move aside from an occupied core. Right on a
                            node that has partitioned its CPUs for the sidecars
                            (`cpuset.cpus`); pinning then happens over the
                            cores the cgroup grants.
  --no-identity             do not open the workload API socket
  --node <name>             name of this node (default: first label of the
                            hostname, lower-cased; without a hostname `node`)
  --control-plane <address> SPIFFE server, e.g. http://127.0.0.1:7001. With
                            this setting the agent fetches its agent
                            intermediate itself and renews it every three hours
                            (ADR-0006/0037); without it, it reads what lies
                            under <data-dir>/identity/.
  --node-session <address>  node session of the control plane, e.g.
                            http://127.0.0.1:7003 (ADR-0040). Without it the
                            node gets **no slice**: no workloads, no edges, no
                            active-role lease. Since ADR-0043 it lies on a port
                            of its own and cannot be guessed from
                            --control-plane -- that would mean inventing a port
                            number.
                            **Repeatable**: after a leader change the agent
                            moves on to the next entry (ADR-0077). Name all
                            nodes.

";

const USAGE_TAIL: &str = "
Identity (ADR-0006, ADR-0037):
  The agent mints locally from an agent intermediate under
  <data-dir>/identity/. With --control-plane it fetches it itself: the first
  time against the invitation in <data-dir>/identity/join-token, afterwards
  over the node key, which arises locally and never leaves the node. Without
  the setting it reads what an operator put in place. If both are missing, it
  runs on without a socket -- a node without identity material is no error case
  but one that has not yet been admitted into the trust domain.
";

fn usage() -> String {
    format!("{USAGE}{}{USAGE_TAIL}", TelemetryArgs::USAGE)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // The helper lies in `tg_telemetry::args`, where the shared part of the
    // overview lies too: which spellings ask for it belongs in one place and not
    // in three binaries.
    if tg_telemetry::args::wants_help(&args) {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }

    // `Options::from` and the two following messages stay `eprintln!`: they
    // arise **before** the subscriber, and a `tracing` event without a subscriber
    // is silently discarded -- a caller with a wrong argument would then get no
    // answer at all. The places in `Valued::take` belong to them.
    let options = Options::from(&args);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("tg-agent: the tokio runtime cannot be started: {err}");
            return ExitCode::FAILURE;
        }
    };

    // As in `tgd`: the holder survives the run so that buffered spans still go
    // out at the end.
    let telemetry = match tg_telemetry::init::init(
        &options.telemetry.to_options(
            "tg-agent",
            tg_telemetry::init::Reporter::Node(options.node.clone()),
        ),
        tg_telemetry::init::Reactor::In(runtime.handle()),
    ) {
        Ok(telemetry) => Some(telemetry),
        Err(err) => {
            // Fail-soft, as everywhere in the agent (ADR-0019): a node without
            // telemetry is a poorly observable node, not a halted one. The
            // endpoint then gives out nothing.
            eprintln!("tg-agent: the telemetry did not come up: {err}");
            None
        }
    };
    let scrape: tg_telemetry::serve::Scrape = telemetry.as_ref().map_or_else(
        || std::sync::Arc::new(String::new) as tg_telemetry::serve::Scrape,
        tg_telemetry::init::Telemetry::scrape,
    );

    match runtime.block_on(serve(&options, scrape)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!(%message, "tg-agent ended");
            ExitCode::FAILURE
        }
    }
}

// **Why the lint gives way here:** every field is set by name -- in
// `Self::default()` and in the evaluation by flag --, never positionally. The
// confusion `struct_excessive_bools` stands against is not buildable here; a
// `Switches` type would shift the same names one level deeper.
#[allow(
    clippy::struct_excessive_bools,
    reason = "a bag of command-line options: every field is set **by name** \
              (`Self::default()` and the evaluation by flag), never positionally \
              -- the confusion the lint stands against is not buildable here. \
              Bundling them into a `Switches` type would shift the names one \
              level deeper and nothing else"
)]
struct Options {
    data_dir: PathBuf,
    once: bool,
    no_seccomp: bool,
    userns: Option<tg_runtime::userns::Mapping>,
    interval: Duration,
    keep_snapshots: usize,
    quorum: Quorum,
    trust_domain: String,
    cluster_cidr: String,
    node_prefix: u8,
    dns_domain: String,
    dns_forward: Option<std::net::SocketAddr>,
    proxy_image: Option<String>,
    cdi_dirs: Vec<std::path::PathBuf>,
    pin_sidecar_shards: bool,
    identity: bool,
    node: String,
    control_plane: Vec<String>,
    node_session: Vec<String>,
    telemetry: TelemetryArgs,
    underlay_endpoint: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(tg_runtime::DEFAULT_DATA_DIR),
            once: false,
            // **The default is the profile** (ADR-0017: default-on).
            no_seccomp: false,
            // **And the default is no user namespace** -- not out of conviction
            // but because the default runtime cannot do it with our network model
            // (ADR-0091, determination 3).
            userns: None,
            interval: Duration::from_secs(10),
            keep_snapshots: 3,
            quorum: Quorum::Available,
            trust_domain: String::from(tg_identity::DEFAULT_TRUST_DOMAIN),
            // ADR-0012 does not fix the address space and ADR-0039 does not take
            // it into the log. As long as it is a setting, two nodes with
            // different values compute different subnets.
            cluster_cidr: String::from("10.42.0.0/16"),
            node_prefix: 24,
            dns_domain: String::from("tardigrade.internal"),
            dns_forward: None,
            proxy_image: None,
            cdi_dirs: Vec::new(),
            // **Default off** (ADR-0114, determination 3) -- the same stance as
            // with the user namespace above: the measurement does not carry
            // generally.
            pin_sidecar_shards: false,
            identity: true,
            // The first label of the hostname, lower-cased: since ADR-0043 the
            // name becomes a SPIFFE identifier, and an FQDN is none.
            //
            // What is read is the **kernel** and not `$HOSTNAME`. The shell sets
            // the variable, and measured, a service under systemd does **not**
            // get it -- then all nodes would fall back to `node`, and that is a
            // name two machines share.
            node: tg_syscall::hostname()
                .as_deref()
                .and_then(tg_identity::cluster::node_name_from_hostname)
                .unwrap_or_else(|| "node".to_owned()),
            control_plane: Vec::new(),
            node_session: Vec::new(),
            telemetry: TelemetryArgs::with_port(7102),
            underlay_endpoint: None,
        }
    }
}

struct Valued<'a> {
    data_dir: &'a mut PathBuf,
    interval: &'a mut Duration,
    cluster_cidr: &'a mut String,
    node_prefix: &'a mut u8,
    underlay_endpoint: &'a mut Option<String>,
    dns_domain: &'a mut String,
    dns_forward: &'a mut Option<std::net::SocketAddr>,
    trust_domain: &'a mut String,
    proxy_image: &'a mut Option<String>,
    cdi_dirs: &'a mut Vec<std::path::PathBuf>,
    node: &'a mut String,
    node_session: &'a mut Vec<String>,
    control_plane: &'a mut Vec<String>,
    userns: &'a mut Option<tg_runtime::userns::Mapping>,
    keep_snapshots: &'a mut usize,
}

impl Valued<'_> {
    const NAMES: &'static [&'static str] = &[
        "--data-dir",
        "--interval",
        "--keep-snapshots",
        "--cluster-cidr",
        "--node-prefix",
        "--underlay-endpoint",
        "--dns-domain",
        "--dns-forward",
        "--trust-domain",
        "--proxy-image",
        "--cdi-dir",
        "--node",
        "--node-session",
        "--control-plane",
        "--userns-base",
    ];

    fn knows(flag: &str) -> bool {
        Self::NAMES.contains(&flag)
    }

    fn take(&mut self, flag: &str, value: &String) {
        match flag {
            // **Checked, not taken over** (ADR-0091, determination 1): a range
            // beginning at 1000 would give the container's `root` the identifier
            // of an existing user.
            "--userns-base" => match value
                .parse::<u32>()
                .map_err(|err| err.to_string())
                .and_then(|base| {
                    tg_runtime::userns::Mapping::new(base).map_err(|err| err.to_string())
                }) {
                Ok(mapping) => *self.userns = Some(mapping),
                Err(why) => eprintln!("tg-agent: --userns-base '{value}' unbrauchbar: {why}"),
            },
            "--data-dir" => *self.data_dir = PathBuf::from(value),
            "--keep-snapshots" => match value.parse::<usize>() {
                Ok(keep) => *self.keep_snapshots = keep,
                // Said, not kept quiet -- as with `--interval`.
                Err(_) => eprintln!(
                    "tg-agent: --keep-snapshots '{value}' is no number, it stays at {}",
                    self.keep_snapshots
                ),
            },
            "--interval" => match value.parse::<u64>() {
                // **Zero is no interval.** Without a due fence threshold
                // `nap_for` returns the interval, and with one it clamps to a
                // floor that is itself `min(1 s, interval)` -- so zero at zero.
                // The reconciliation would then run without a pause: one `state`
                // call of the runtime per instance and round, plus report and
                // projection. A typo would be a denial of service against one's
                // own node.
                Ok(0) => eprintln!(
                    "tg-agent: --interval 0 would be a reconciliation without a pause, it stays at {}s",
                    self.interval.as_secs()
                ),
                Ok(secs) => *self.interval = Duration::from_secs(secs),
                // Said, not kept quiet -- as with `--node-prefix`. A silently
                // ignored value costs the hour in which somebody looks for why
                // their interval does not apply.
                Err(_) => eprintln!(
                    "tg-agent: --interval '{value}' is no number, it stays at {}s",
                    self.interval.as_secs()
                ),
            },
            "--cluster-cidr" => self.cluster_cidr.clone_from(value),
            "--node-prefix" => match value.parse() {
                Ok(parsed) => *self.node_prefix = parsed,
                // An unreadable number stays at the default; the building of the
                // network then reports by itself, because the subnet does not fit
                // the rest of the cluster.
                Err(_) => eprintln!(
                    "tg-agent: --node-prefix '{value}' is no number, it stays at /{}",
                    self.node_prefix
                ),
            },
            "--underlay-endpoint" => *self.underlay_endpoint = Some(value.clone()),
            "--dns-domain" => self.dns_domain.clone_from(value),
            "--dns-forward" => match value.parse() {
                Ok(addr) => *self.dns_forward = Some(addr),
                // Fail-soft like the rest of this evaluation: without forwarding
                // it stays at the `REFUSED` from phase 9c. A guessed upstream
                // would be worse than none.
                Err(err) => eprintln!("tg-agent: --dns-forward '{value}': {err}"),
            },
            "--trust-domain" => self.trust_domain.clone_from(value),
            "--proxy-image" => *self.proxy_image = Some(value.clone()),
            "--cdi-dir" => self.cdi_dirs.push(std::path::PathBuf::from(value)),
            "--node" => self.node.clone_from(value),
            // **Appended, not replaced** (ADR-0077): all nodes of the control
            // plane shall be named, like `--peer` with `tgd`.
            "--node-session" => self.node_session.push(value.clone()),
            _ => self.control_plane.push(value.clone()),
        }
    }
}

impl Options {
    fn from(args: &[String]) -> Self {
        let Self {
            mut data_dir,
            mut once,
            mut interval,
            mut keep_snapshots,
            mut quorum,
            mut trust_domain,
            mut cluster_cidr,
            mut node_prefix,
            mut dns_domain,
            mut dns_forward,
            mut proxy_image,
            mut cdi_dirs,
            mut pin_sidecar_shards,
            mut identity,
            mut node,
            mut control_plane,
            mut node_session,
            mut telemetry,
            mut underlay_endpoint,
            mut no_seccomp,
            mut userns,
        } = Self::default();
        let mut iter = args.iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--once" => once = true,
                "--no-quorum" => quorum = Quorum::Unavailable,
                "--no-seccomp" => no_seccomp = true,
                "--no-identity" => identity = false,
                "--pin-sidecar-shards" => pin_sidecar_shards = true,
                // All settings with the same shape: one word, one value.
                // Written individually the if-then envelope stood at each of them
                // with the actual assignment in between -- and the list grows with
                // every ADR.
                flag if Valued::knows(flag) => {
                    if let Some(value) = iter.next() {
                        Valued {
                            data_dir: &mut data_dir,
                            interval: &mut interval,
                            cluster_cidr: &mut cluster_cidr,
                            node_prefix: &mut node_prefix,
                            underlay_endpoint: &mut underlay_endpoint,
                            dns_domain: &mut dns_domain,
                            dns_forward: &mut dns_forward,
                            trust_domain: &mut trust_domain,
                            proxy_image: &mut proxy_image,
                            cdi_dirs: &mut cdi_dirs,
                            node: &mut node,
                            node_session: &mut node_session,
                            control_plane: &mut control_plane,
                            userns: &mut userns,
                            keep_snapshots: &mut keep_snapshots,
                        }
                        .take(flag, value);
                    }
                }
                other => {
                    // Fail-soft like the rest of this evaluation (ADR-0019:
                    // better to run than to halt). An unusable telemetry setting
                    // costs observability, not a node.
                    let mut next = || -> Result<String, String> {
                        iter.next()
                            .cloned()
                            .ok_or_else(|| format!("{other} needs a value"))
                    };
                    if let Err(err) = telemetry.take(other, &mut next) {
                        eprintln!("tg-agent: {err}");
                    }
                }
            }
        }

        Self {
            data_dir,
            once,
            no_seccomp,
            userns,
            interval,
            keep_snapshots,
            quorum,
            trust_domain,
            cluster_cidr,
            node_prefix,
            dns_domain,
            dns_forward,
            proxy_image,
            cdi_dirs,
            pin_sidecar_shards,
            identity,
            node,
            control_plane,
            node_session,
            telemetry,
            underlay_endpoint,
        }
    }
}

const WATCH_RECONCILE: &str = "reconcile";

const TASK_IDENTITY: &str = "identity-refresh";
const TASK_SESSION: &str = "cluster-session";
pub(crate) const TASK_RESOLVER_UDP: &str = "resolver-udp";
pub(crate) const TASK_RESOLVER_TCP: &str = "resolver-tcp";

fn unix_now() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

fn start_telemetry(options: &Options, scrape: tg_telemetry::serve::Scrape) -> Health {
    let health = Health::new();
    health.set(WATCH_RECONCILE, Readiness::down("no pass yet"));
    // **The issuer's deadline is repeated in the scrape** (ADR-0088). It changes
    // only at minting and takeover -- in operation at most every three hours, and
    // on a failed renewal not at all any more. With the gauge expiry precisely
    // then the time series whose alarm reports an expiring issuer would
    // disappear.
    health.on_scrape(
        tg_telemetry::names::INTERMEDIATE_EXPIRES_AT,
        tg_identity::agent::refresh_expiry,
    );
    // **And the snapshot metrics** (ADR-0099, determination 8), for the same
    // reason: a snapshot arises rarely -- a gauge that is set only at creation
    // expires after 15 minutes, and with it the rule that reports a **missing**
    // snapshot.
    let data_dir = options.data_dir.clone();
    health.on_scrape(tg_telemetry::names::VOLUME_SNAPSHOTS, move || {
        tg_runtime::volume::report_snapshots(&data_dir);
    });

    // **And the data key's fingerprint** (ADR-0100). `tgd` reports the same
    // name; only both together answer the question that matters at a rotation:
    // **does every node carry the new primary key?** As long as an agent does not
    // have it, every start of a container with secrets fails (ADR-0098,
    // determination 7) -- running ones stay untouched.
    //
    // In the scrape, because the key changes at most every three hours: a gauge
    // that is set only at the takeover expires after 15 minutes (ADR-0088).
    let key = options
        .data_dir
        .join(tg_identity::layout::DIR)
        .join(tg_identity::layout::SECRETS_KEY);
    health.on_scrape(tg_telemetry::names::DATA_KEY, move || {
        tg_identity::agent::report_data_key(&key);
    });

    // **And the protocol version** (ADR-0072). `tgd` reports the same name, and
    // only both together answer the question in the maintenance window of a
    // format change: **does everyone already speak the same version?** Until here
    // it was unanswerable -- in this window every agent is silent, so a forgotten
    // one looks like a waiting one, and every statement over the session would be
    // exactly the one the skew breaks.
    //
    // In the scrape, because it is constant over a process's life.
    tg_telemetry::probes::report_protocol(&health, tg_store::session::PROTOCOL_FIELDS);

    if let Some(addr) = options.telemetry.addr {
        let served = health.clone();
        tokio::spawn(async move {
            if let Err(err) = tg_telemetry::serve::serve(addr, served, scrape).await {
                // Fail-soft: a node without a metrics endpoint is a poorly
                // observable node, not a broken one (ADR-0019).
                tracing::warn!(%addr, error = %err, "telemetry endpoint");
            }
        });
        tracing::info!(%addr, "the telemetry endpoint stands");
    }

    health
}

async fn start_identity_refresh(
    options: &Options,
    wake: std::sync::Arc<tokio::sync::Notify>,
) -> Option<impl Fn() -> tokio::task::JoinHandle<()> + Send + 'static> {
    let mut endpoints = crate::endpoints::Endpoints::new(options.control_plane.clone())?;

    // The first attempt may hit a follower: then it moves on and tries there
    // (ADR-0077). Without that the agent stayed stuck at an address that no
    // longer leads.
    for _ in 0..endpoints.len() {
        match join::fetch(
            &options.data_dir,
            &options.node,
            &options.trust_domain,
            endpoints.current(),
            options.underlay_endpoint.as_deref(),
        )
        .await
        {
            Ok(()) => {
                tracing::info!(
                    endpoint = endpoints.current(),
                    every = ?join::RENEW_EVERY,
                    "identity fetched"
                );
                break;
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    endpoint = endpoints.current(),
                    "the identity was not fetched"
                );
                endpoints.advance();
            }
        }
    }

    // **A factory instead of a handle** (ADR-0116, determination 2): if the
    // renewer dies of a panic, the watcher sets it up again. It is this process's
    // most expensive case -- without it no SVID rotates any more, and after twelve
    // hours none of this node's is accepted any more (ADR-0014).
    //
    // The **endpoints travel along as they stand**: the first attempt above has
    // possibly already moved on, and a restart that began at the front again
    // would run into the follower once more (ADR-0077).
    let data_dir = options.data_dir.clone();
    let node = options.node.clone();
    let domain = options.trust_domain.clone();
    let underlay = options.underlay_endpoint.clone();

    Some(move || {
        tokio::spawn(join::keep_fresh(
            data_dir.clone(),
            node.clone(),
            domain.clone(),
            endpoints.clone(),
            underlay.clone(),
            std::sync::Arc::clone(&wake),
        ))
    })
}

const LOCK: &str = "agent.lock";

const _: () = assert!(
    tg_runtime::oci::CALL_TIMEOUT.as_secs() < 5 * 60,
    "the deadline of a runtime call must lie below the watchdog tolerance (ADR-0064)"
);

const _: () = assert!(
    tg_runtime::volume::TOOL_TIMEOUT.as_secs() < 5 * 60,
    "the deadline of a volume tool must lie below the watchdog tolerance (ADR-0064)"
);

fn watch_reconcile(health: &tg_telemetry::probes::Health, interval: Duration) {
    health.watch(
        WATCH_RECONCILE,
        (interval * 10).max(Duration::from_mins(5)),
        unix_now(),
    );
}

struct Sinks<'a> {
    projection: &'a tg_store::Projection,
    node: &'a str,
    observed: &'a session::Observed,
    net: Option<&'a network::Network>,
    minting: Option<&'a identity::Api>,
}

fn absorb(
    sinks: &Sinks<'_>,
    material: Option<&mut identity::Material>,
    report: &reconcile::Report,
) {
    let Sinks {
        projection,
        node,
        observed,
        net,
        minting,
    } = *sinks;

    publish(projection, node, report);
    session::observe(observed, report, net);
    refresh_identity(minting, material, report);
    if let Some(net) = net {
        net.refresh(projection);
        // The node's rule set belongs to the desired state like a container: it
        // is reconciled, not set once (ADR-0010).
        net.ensure_rules();
    }
}

fn report_relaxations(options: &Options) {
    if options.no_seccomp {
        tracing::warn!(
            "no seccomp profile: --no-seccomp applies to all containers of this node (ADR-0090)"
        );
    }
}

fn hardening(options: &Options, oci: &OciRuntime) -> Result<(), String> {
    let Some(mapping) = options.userns else {
        return Ok(());
    };

    if !tg_runtime::userns::supported_by(oci.name()) {
        return Err(format!(
            "--userns-base demands a runtime that can put a container with a \
             user namespace into a network namespace named over a path; '{}' \
             cannot do that (ADR-0091). Possible are: {}",
            oci.name(),
            tg_runtime::userns::CAPABLE_RUNTIMES.join(", ")
        ));
    }

    tracing::info!(
        base = mapping.base(),
        size = tg_runtime::userns::SIZE,
        "user namespace: uid 0 in the container is not uid 0 on the node (ADR-0091)"
    );
    Ok(())
}

fn volume_keys(data_dir: &std::path::Path) -> tg_runtime::volume::Derive {
    let key_path = data_dir
        .join("identity")
        .join(tg_identity::layout::SECRETS_KEY);

    let previous_path = key_path.with_file_name(tg_identity::layout::SECRETS_KEY_PREVIOUS);

    std::sync::Arc::new(
        move |volume: &str| -> Option<tg_runtime::volume::Passphrases> {
            let read = |path: &std::path::Path| {
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|text| tg_identity::secrets::DataKey::from_base64(text.trim()).ok())
                    .map(|key| key.volume_passphrase(volume))
            };

            Some(tg_runtime::volume::Passphrases {
                current: read(&key_path)?,
                // **An unreadable one to be replaced is passed over**, as in
                // `secrets::ring`: it is the fallback, and making it a condition
                // would take from the node the volumes the valid one very much
                // opens (ADR-0019).
                previous: read(&previous_path),
            })
        },
    )
}

fn open_data_dir(
    options: &Options,
) -> Result<(NodePaths, Vec<tg_defs::generated::WorkloadType>), String> {
    let paths = NodePaths::new(&options.data_dir);
    paths.seal();

    let desired = DesiredState::open(paths.data_dir()).map_err(|err| err.to_string())?;
    let workloads = readable(&desired)?;
    thaw_leftovers(&paths);

    Ok((paths, workloads))
}

async fn serve(options: &Options, scrape: tg_telemetry::serve::Scrape) -> Result<(), String> {
    // **First the lock on the data directory** (ADR-0043: one per node). A
    // second agent on it silently takes the first's workload API socket -- that
    // is removed before binding, because otherwise a crashed predecessor would
    // never come up again --, and afterwards every SVID of this node expires
    // within fifteen minutes (ADR-0014). Plus two reconcile loops on the same
    // desired state and two writers on the same address ledger.
    //
    // `tgd` is protected against the same thing, but for free: `redb` locks the
    // Raft store. The agent has no database, so it takes the lock itself -- and
    // **before** everything else, so that nothing at all is touched.
    let _lock = tg_syscall::lock::hold(&options.data_dir, LOCK).map_err(|err| err.to_string())?;

    let health = start_telemetry(options, scrape);

    let (paths, workloads) = open_data_dir(options)?;

    // With a control plane an empty cache is no reason to stop: the first slice
    // fills it (ADR-0040). Without one it very much is -- then there is nobody
    // who would ever fill it.
    if workloads.is_empty() && options.control_plane.is_empty() {
        tracing::info!("no desired workload in the local cache");
        return Ok(());
    }

    // The workload API socket comes up **before** the runtime search, and that
    // is no order out of convenience: a container that is already running and
    // must rotate its SVID shall get it even if the runtime binary is missing by
    // then. Identity does not depend on being able to start new containers right
    // now (ADR-0019).
    //
    // The socket also runs **beside** the reconcile loop and not in it: a request
    // shall not wait because an image is being pulled right now.
    // With a control plane the agent fetches its intermediate **before** the
    // first minting attempt -- otherwise it would start with whatever happened to
    // be left from yesterday. If that fails, it runs on all the same: what it has
    // carries twelve hours (ADR-0014), and the renewer tries again.
    // **One wake-up, two tasks** (ADR-0042): the session sees what the cluster
    // knows about this node, and the renewer carries the announcement. The one
    // wakes the other -- no second way out, no listening port.
    let wake = std::sync::Arc::new(tokio::sync::Notify::new());

    let _renewal = start_identity_refresh(options, std::sync::Arc::clone(&wake))
        .await
        .map(|make| tg_telemetry::probes::supervise(&health, TASK_IDENTITY, make));

    let (registries, secrets) = sinks(options);

    let ledgers = std::sync::Arc::new(ledgers(options));

    let identity = open_identity(options, &workloads);
    let listeners = identity
        .as_ref()
        .map(|(held, _, _)| std::sync::Arc::clone(held));
    let minting = identity.as_ref().map(|(_, api, _)| api.clone());
    // The marker comes from **the same** reading as the service (see
    // `Material::read`) and not from a second one here.
    let mut material = identity.as_ref().map(|(_, _, material)| material.clone());

    let net = start_network(options, &workloads, &health);

    let oci = OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root())
        .map_err(|err| err.to_string())?;

    hardening(options, &oci)?;

    tracing::info!(
        workloads = workloads.len(),
        runtime = oci.name(),
        quorum = match options.quorum {
            Quorum::Available => "reachable",
            Quorum::Unavailable => "NOT reachable - autonomous actions only",
        }
    );

    report_relaxations(options);

    // The projection is a read model (ADR-0004), no truth: it lives in memory
    // and is rebuilt at every start (ADR-0030). There is nothing to open and
    // nothing that could fail in the process.
    let projection = std::sync::Arc::new(Projection::new());
    projection.materialize(&workloads);

    // ADR-0040: the session to the control plane. It **fills** the local cache;
    // it is read by the reconcile loop, never from the network.
    // The observation state: the reconcile loop writes it, the session reads it
    // (ADR-0040). It comes from the **observer** and not from the projection --
    // otherwise the instance number in the report would be a zero again.
    let observed = session::observed();
    // **A second wake-up, and it goes in the other direction** (ADR-0076,
    // determination 7): the slice that has arrived brings a pass forward. Without
    // it a single writer took up its granted role only at the next pass -- with
    // `--interval 60` measured a whole minute later, while the slice already lay
    // on the disk.
    let reconcile_now = std::sync::Arc::new(tokio::sync::Notify::new());
    let trace = Trace::default();
    let _session = start_session(
        options,
        &observed,
        wake,
        std::sync::Arc::clone(&reconcile_now),
        std::sync::Arc::clone(&trace),
        (registries.clone(), secrets.clone()),
        &ledgers.inventory(),
    )
    .map(|make| tg_telemetry::probes::supervise(&health, TASK_SESSION, make));

    // The seam from ADR-0012: the reconciler attaches every instance to the
    // network **before** its container starts. Without a node network it stays
    // empty, and a container gets a fresh, empty network namespace -- no network,
    // but not the host's either.
    let wiring = net
        .as_ref()
        .map(|net| net as &dyn tg_runtime::network::Wiring);

    let empty = || empty_means(&options.data_dir);
    let mesh = mesh(options);
    // The **local** clock for the active-role lease (ADR-0064): the self-fence
    // must take hold when the cluster is not reachable.
    let clock = now_millis;
    // **One socket per instance** (ADR-0081). The sidecar gets its own over the
    // same way -- the entry in `Mesh { mounts }` has fallen away, for there is no
    // path left both could share.
    let workload_api = sockets(listeners.as_ref());
    let volume_keys = volume_keys(&options.data_dir);
    let context = reconcile::Context {
        devices: Some(ledgers.as_ref()),
        volume_keys: Some(&volume_keys),
        keep_snapshots: options.keep_snapshots,
        quorum: options.quorum,
        no_seccomp: options.no_seccomp,
        userns: options.userns,
        network: wiring,
        mesh: mesh.as_ref(),
        // **Every container gets its own socket** (ADR-0079, ADR-0081) -- and
        // the socket **is** the attestation: whoever reached it is in this
        // container. Without identity material there is none, and then no
        // workload gets an SVID; what hangs on it reports by itself.
        workload_api,
        // Without a mapping and without a grant the pull is anonymous (ADR-0096).
        credentials: Some(&registries),
        // **The mount is the authorization** (ADR-0098): a container gets
        // exactly the secrets for which `AllowSecret` names its name. Without a
        // grant no mount, and without a data key a workload with secrets does not
        // start.
        secrets: Some(&secrets),
        empty: &empty,
        now: &clock,
        // **The safety margin hangs on no setting** (ADR-0076). Here stood
        // `--interval` plus the grace period: the detection latency was a whole
        // pass. With the default of ten seconds the distance became larger than
        // the remaining time in the trough, and a **healthy** single writer
        // counted as fenced two thirds of the time.
        //
        // The comparison now wakes near the threshold (`nap_for`), so the
        // detection is a floor instead of a setting -- and the ordering condition
        // is a build assurance in `tg_model::lease` instead of a check at
        // startup.
        fence_margin: tg_model::lease::FENCE_MARGIN_MILLIS,
        wake: Some(&reconcile_now),
    };

    // The sinks a pass flows into -- formed once so that `--once` and the loop
    // use the same ones.
    let sinks = Sinks {
        projection: &projection,
        node: &options.node,
        observed: &observed,
        net: net.as_ref(),
        minting: minting.as_ref(),
    };

    if options.once {
        let report = reconcile::once(&paths, &oci, &context)
            .await
            .map_err(|err| err.to_string())?;
        absorb(&sinks, material.as_mut(), &report);

        return verdict(&report);
    }

    tracing::info!(interval = ?options.interval, "reconcile loop");

    watch_reconcile(&health, options.interval);
    // `run_with` instead of `run`: every pass goes into the projection and from
    // there into the resolution. Without that the resolver would know nothing
    // after the start, and every name would stay NODATA (ADR-0013: only
    // **healthy** endpoints are resolved).
    reconcile::run_traced(
        &paths,
        &oci,
        &context,
        options.interval,
        |outcome| after_pass(&health, &sinks, material.as_mut(), outcome),
        || parent_of(&trace),
    )
    .await
    .map_err(|err| err.to_string())
}

fn after_pass(
    health: &Health,
    sinks: &Sinks<'_>,
    material: Option<&mut identity::Material>,
    outcome: Result<&reconcile::Report, &tg_runtime::RuntimeError>,
) {
    health.beat(WATCH_RECONCILE, unix_now());
    let Ok(report) = outcome else {
        health.set(WATCH_RECONCILE, Readiness::down("the pass failed"));
        return;
    };
    absorb(sinks, material, report);
    health.set(WATCH_RECONCILE, Readiness::up());
}

pub(crate) type Trace = std::sync::Arc<std::sync::RwLock<Option<String>>>;

fn parent_of(trace: &Trace) -> Option<String> {
    trace
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn cluster_net(options: &Options) -> Result<tg_net::ipam::ClusterNet, String> {
    let file = session::Paths::new(&options.data_dir).cluster_network();
    let from_cluster = underlay::read_network(&file);
    match from_cluster {
        Ok(cluster) => {
            tracing::info!(
                net = %cluster.net(),
                "address plan from consensus"
            );
            return Ok(cluster);
        }
        Err(reason) => {
            // No error as long as the setting carries: a fresh node does not
            // have the file yet.
            tracing::debug!(%reason, "no network parameters from consensus yet");
        }
    }

    let cidr = options
        .cluster_cidr
        .parse()
        .map_err(|_| format!("--cluster-cidr '{}' is no network", options.cluster_cidr))?;

    tg_net::ipam::ClusterNet::new(cidr, options.node_prefix).map_err(|err| err.to_string())
}

fn open_identity(
    options: &Options,
    workloads: &[tg_defs::generated::WorkloadType],
) -> Option<(
    std::sync::Arc<sockets::Listeners>,
    identity::Api,
    identity::Material,
)> {
    match start_identity(options, workloads) {
        Ok(handle) => handle,
        Err(message) => {
            tracing::warn!(%message, "no workload API socket");
            None
        }
    }
}

fn start_network(
    options: &Options,
    workloads: &[tg_defs::generated::WorkloadType],
    health: &tg_telemetry::probes::Health,
) -> Option<network::Network> {
    // The node network comes **after** the socket and **before** the runtime
    // search, for the same reason as the socket: a container that is already
    // running shall keep its address and its resolver even if the runtime binary
    // is missing (ADR-0019). And like the socket it is fail-soft -- a node
    // without a network mints on.
    match cluster_net(options) {
        Ok(cluster) => {
            let names: Vec<String> = workloads
                .iter()
                .map(|workload| tg_defs::WorkloadExt::name(workload).to_owned())
                .collect();

            match network::start(
                &options.data_dir,
                options.dns_forward,
                &cluster,
                &options.dns_domain,
                &names,
                options.userns,
            ) {
                Ok(mut net) => {
                    // The two resolver tasks get their watcher (ADR-0082): they
                    // return `Infallible`, so they can end only by a panic -- and
                    // that was mute until here.
                    net.supervise(health);
                    tracing::info!(
                        bridge = tg_net::ipam::BRIDGE,
                        subnet = %net.subnet().net(),
                        zone = %options.dns_domain,
                        resolver = %format_args!("{}:{}", net.gateway(), tg_net::resolver::PORT),
                        "the node network stands"
                    );
                    // Expressly reported, because the absence is the default:
                    // without an upstream a container does not resolve a
                    // permitted egress name (ADR-0041, determination 6), and that
                    // looks like a network problem.
                    if let Some(upstream) = options.dns_forward {
                        tracing::info!(
                            %upstream,
                            allowed = net.forwarded_names(),
                            "egress names are forwarded"
                        );
                    } else {
                        // `warn!`: the absence is the default, but its consequence
                        // looks like a network problem (ADR-0041).
                        tracing::warn!(
                            "no DNS forwarding (--dns-forward is missing) -- \
                             permitted egress names do not resolve"
                        );
                    }
                    Some(net)
                }
                Err(message) => {
                    tracing::warn!(%message, "no node network");
                    None
                }
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "no node network");
            None
        }
    }
}

fn announcement(options: &Options) -> Option<session::Announcement> {
    let endpoint = options.underlay_endpoint.clone()?;

    // **Said, not silently skipped.** A node that shall announce an endpoint and
    // has no key is a case one wants to see -- otherwise an operator looks for the
    // comparison that never took place.
    //
    // What is checked is only **that** there is one: which one it is the
    // comparison reads anew at every slice, for since ADR-0055 it can change in
    // operation.
    if join::announced_key(&options.data_dir).is_none() {
        tracing::warn!("no underlay key -- no comparison of the announcement");
        return None;
    }

    Some(session::Announcement {
        node: options.node.clone(),
        data_dir: options.data_dir.clone(),
        endpoint,
    })
}

fn sockets(
    listeners: Option<&std::sync::Arc<sockets::Listeners>>,
) -> Option<&dyn tg_runtime::network::Sockets> {
    listeners.map(|held| held.as_ref() as &dyn tg_runtime::network::Sockets)
}

fn empty_means(data_dir: &std::path::Path) -> reconcile::EmptyMeans {
    if session::slice_applied(data_dir) {
        reconcile::EmptyMeans::NothingWanted
    } else {
        reconcile::EmptyMeans::NothingHeard
    }
}

fn ledgers(options: &Options) -> devices::Ledgers {
    let dirs: Vec<std::path::PathBuf> = if options.cdi_dirs.is_empty() {
        tg_runtime::cdi::DEFAULT_DIRS
            .iter()
            .map(std::path::PathBuf::from)
            .collect()
    } else {
        options.cdi_dirs.clone()
    };

    let (ledgers, notes) = devices::Ledgers::open(&options.data_dir, &dirs);
    for note in notes {
        tracing::warn!(finding = %note, "CDI spec not usable (ADR-0143)");
    }
    tracing::info!(
        devices = ledgers.len(),
        directories = dirs.len(),
        "CDI inventory read"
    );
    ledgers
}

fn sinks(options: &Options) -> (registries::Registries, secrets::SecretStore) {
    (registries(options), secrets(options))
}

fn secrets(options: &Options) -> secrets::SecretStore {
    secrets::SecretStore::new(
        &options.data_dir,
        &options
            .data_dir
            .join(tg_identity::layout::DIR)
            .join(tg_identity::layout::SECRETS_KEY),
        options.userns,
    )
}

fn registries(options: &Options) -> registries::Registries {
    registries::Registries::new(
        &options
            .data_dir
            .join(tg_identity::layout::DIR)
            .join(tg_identity::layout::SECRETS_KEY),
    )
}

fn start_session(
    options: &Options,
    observed: &session::Observed,
    wake: std::sync::Arc<tokio::sync::Notify>,
    reconcile_now: std::sync::Arc<tokio::sync::Notify>,
    trace: Trace,
    sinks: (registries::Registries, secrets::SecretStore),
    devices: &std::collections::BTreeMap<String, u64>,
) -> Option<impl Fn() -> tokio::task::JoinHandle<()> + Send + 'static> {
    let (registries, secrets) = sinks;
    // **Several addresses** (ADR-0077): the session goes to the leader, and a
    // follower only refers on. Without a list the agent stayed permanently
    // without a slice after a leader change.
    let endpoints = crate::endpoints::Endpoints::new(if options.node_session.is_empty() {
        options.control_plane.clone()
    } else {
        options.node_session.clone()
    })?;

    match cluster::Cluster::load(&options.data_dir, &options.trust_domain, &options.node) {
        Ok(cluster) => {
            tracing::info!(
                endpoint = endpoints.current(),
                endpoints = endpoints.len(),
                anchors = cluster.anchors(),
                "session (mTLS)"
            );
            // **Half-configured is the frequent state**, and it otherwise stands
            // out only when the uncovered node leads (ADR-0077): whoever extends
            // `--control-plane` and forgets `control-plane.pem` gets
            // `UnknownIssuer` there and nothing else.
            if let Some(missing) = cluster::anchors_cover(endpoints.len(), cluster.anchors()) {
                tracing::warn!(
                    endpoints = endpoints.len(),
                    anchors = cluster.anchors(),
                    file = tg_identity::layout::CONTROL_PLANE,
                    "{missing} named control-plane nodes have no anchor: the \
                     handshake fails there. The leaves of all nodes belong \
                     concatenated in this file"
                );
            }
            // **A factory instead of a handle** (ADR-0116, determination 2). If
            // the session dies of a panic, it comes back -- and without it this
            // node would get no slice any more: no withdrawal of an edge
            // (ADR-0025), every single writer fenced (ADR-0064), tombstones left
            // lying (ADR-0042).
            //
            // The **anchor and the endpoints travel along as they stand**: they
            // come from the disk and from the setting, not from the run.
            let data_dir = options.data_dir.clone();
            let introduction = session::Introduction {
                registries,
                secrets,
                node: options.node.clone(),
                endpoints,
                announcement: announcement(options),
                proxy_image: options.proxy_image.clone(),
                devices: devices.clone(),
                userns: options.userns.map(tg_runtime::userns::Mapping::base),
            };
            let observed = std::sync::Arc::clone(observed);

            Some(move || {
                tokio::spawn(session::keep_open(
                    data_dir.clone(),
                    introduction.clone(),
                    cluster.clone(),
                    std::sync::Arc::clone(&observed),
                    std::sync::Arc::clone(&wake),
                    std::sync::Arc::clone(&reconcile_now),
                    std::sync::Arc::clone(&trace),
                ))
            })
        }
        Err(err) => {
            tracing::warn!(error = %err, "no session");
            None
        }
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

fn publish(projection: &Projection, node: &str, report: &reconcile::Report) {
    // **The readiness, replacing per pass** (ADR-0080). It expressly does
    // **not** go through the buckets below: an unready instance stays `Running`,
    // for it runs -- it only does not serve (determination 1). A state of its own
    // would take from the leader the statement "runs" and from the clearer an
    // instance out of what is wanted (ADR-0058).
    projection.report_unready(
        node,
        report
            .unready
            .iter()
            .map(|which| (which.workload.clone(), which.instance))
            .collect(),
    );

    let buckets = [
        (&report.untouched, ActualStatus::Running),
        (&report.reconciled, ActualStatus::Running),
        (&report.deferred, ActualStatus::Stopped),
        // Held back is **stopped**, not failed (ADR-0061): the reconciliation
        // did what ADR-0009 demands. What matters above all is that it stands
        // here at all -- otherwise the resolver would offer an instance that does
        // not run (ADR-0013: only **healthy** endpoints).
        (&report.held, ActualStatus::Stopped),
        // And the active-role lease (ADR-0064, determination 6). **Stopped, not
        // failed:** the fence did what ADR-0010 demands. Both belong here for the
        // same reason as `held` -- otherwise the resolver would go on offering the
        // writer that has just stopped.
        (&report.fenced, ActualStatus::Stopped),
        (&report.waiting, ActualStatus::Stopped),
    ];

    // **Collected and replacing per node**, like the readiness above. Until here
    // it was reported per instance individually, additively -- and the only
    // clearer was `materialize`, which the agent calls exactly once. An instance
    // that disappears (`replicas` 3 -> 1) thereby stayed standing forever.
    let mut states: Vec<(String, u32, ActualStatus)> = buckets
        .into_iter()
        .flat_map(|(instances, status)| {
            instances
                .iter()
                .map(move |which| (which.workload.clone(), which.instance, status))
        })
        .collect();

    // **Failed ones individually**, because they carry their reason along
    // (`Failure`). The projection still takes only the state: the text names
    // names from a payload, and the resolver needs only to know that this address
    // serves nothing.
    states.extend(report.failed.iter().map(|failure| {
        (
            failure.instance.workload.clone(),
            failure.instance.instance,
            ActualStatus::Failed,
        )
    }));

    // **`report.unclear` is missing here on purpose** (ADR-0122,
    // determination 5).
    //
    // `report_instances` **replaces** this node's set, so an omitted instance is
    // afterwards without an entry -- and that is exactly the statement:
    // `ActualStatus::Unknown`, "never seen", ignorance is no state. `health_of`
    // turns that into `Unhealthy`, so the resolver does not offer it (ADR-0013).
    //
    // `Stopped` would be a claim we cannot substantiate, and `Failed` would tear
    // the dependants along (ADR-0061). A variant of its own would be a format
    // break (ADR-0072) for a statement the absence already carries.
    projection.report_instances(node, states);
}

fn verdict(report: &reconcile::Report) -> Result<(), String> {
    // **Stale is no finding** (ADR-0070, determination 5): the instances run,
    // `is_clean` stays true, and the caller gets no error status. It is named all
    // the same, for it is the statement for whose sake the number exists -- until
    // here the same situation was called `untouched`.
    if !report.stale.is_empty() {
        tracing::warn!(
            stale = report.stale.len(),
            instances = %report
                .stale
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            "run from an older declaration -- it takes effect at the next start (ADR-0070)"
        );
    }

    // **Unknown is no finding, but a statement** (ADR-0122). The pass did
    // nothing wrong -- it did nothing, and that was the decision. It must not be
    // kept quiet all the same: otherwise the safe direction would be a silence,
    // and an operator would look for the error where it is not.
    if !report.unclear.is_empty() {
        tracing::warn!(
            unclear = report.unclear.len(),
            instances = %report
                .unclear
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            "state unknown -- not touched and not resolved (ADR-0122)"
        );
    }

    if report.is_clean() {
        tracing::info!(
            untouched = report.untouched.len(),
            reconciled = report.reconciled.len(),
            deferred = report.deferred.len(),
            unclear = report.unclear.len(),
            "pass ended"
        );
        return Ok(());
    }

    let mut message = format!("{} workload(s) not reconciled", report.failed.len());
    if !report.isolated.is_empty() {
        use std::fmt::Write as _;
        let _ = write!(
            message,
            ", {} isolated: {}",
            report.isolated.len(),
            report.isolated.join(", ")
        );
    }

    Err(message)
}

fn readable(desired: &DesiredState) -> Result<Vec<tg_defs::generated::WorkloadType>, String> {
    let cached = desired.load_readable().map_err(|err| err.to_string())?;
    if !cached.unreadable.is_empty() {
        tracing::error!(
            entries = ?cached.unreadable,
            "unreadable entries in the desired-state cache -- they are passed over"
        );
    }

    Ok(cached.workloads)
}

fn refresh_identity(
    api: Option<&identity::Api>,
    material: Option<&mut identity::Material>,
    report: &reconcile::Report,
) {
    let Some(api) = api else {
        return;
    };

    api.set_assigned(report.own.clone());
    api.set_delegations(report.delegations.clone());

    // And the material that is minted from. It stands here and not in a cadence
    // of its own, because it is the same question: what applies on this node right
    // now? A second cadence would be a second opportunity to stand still.
    if let Some(material) = material {
        material.refresh(api);
    }
}

fn mesh(options: &Options) -> Option<tg_runtime::network::Mesh> {
    use tg_runtime::bundle::VolumeMount;

    let image = options.proxy_image.as_ref()?;
    let spec = match SidecarSpec::new(image.clone(), options.trust_domain.clone())
        .map(|spec| spec.pinned_shards(options.pin_sidecar_shards))
    {
        Ok(spec) => spec,
        Err(err) => {
            tracing::error!(error = %err, "no sidecar -- the proxy image is unusable");
            return None;
        }
    };

    // **From `Paths`, not as a literal**: `session::apply` writes the same files
    // from the slice, and a second source would let the mount point at a path
    // nobody ever writes -- measured without a single red test.
    let paths = session::Paths::new(&options.data_dir);

    Some(tg_runtime::network::Mesh {
        spec,
        // **From `Paths` like the mounts**: `session::apply` writes the file
        // from the slice, the reconciler reads it per pass (ADR-0086). It is
        // **not** mounted -- the kernel sets the limit over the cgroup, the
        // sidecar never sees it.
        overhead: paths.sidecar_overhead(),
        mounts: vec![
            VolumeMount {
                source: paths.edges(),
                destination: tg_model::mesh::EDGES_IN_CONTAINER.to_owned(),
                readonly: true,
            },
            VolumeMount {
                source: paths.egress(),
                destination: tg_model::mesh::EGRESS_IN_CONTAINER.to_owned(),
                readonly: true,
            },
            // Read-only, like the two before it: a sidecar that could write its
            // own active role would be no enforcement (ADR-0059, ADR-0066).
            VolumeMount {
                source: paths.roles(),
                destination: tg_model::mesh::ROLE_IN_CONTAINER.to_owned(),
                readonly: true,
            },
        ],
    })
}

fn start_identity(
    options: &Options,
    workloads: &[tg_defs::generated::WorkloadType],
) -> Result<
    Option<(
        std::sync::Arc<sockets::Listeners>,
        identity::Api,
        identity::Material,
    )>,
    String,
> {
    if !options.identity {
        return Ok(None);
    }
    if !identity::is_configured(&options.data_dir) {
        return Err(format!(
            "no agent intermediate lies under {}",
            identity::dir(&options.data_dir).display()
        ));
    }

    let domain = TrustDomain::new(options.trust_domain.clone()).map_err(|err| err.to_string())?;

    // **How long the intermediate carries stands in the certificate** -- and is
    // read there (ADR-0014: the hard expiry stays enforced). `i64::MAX` stood
    // here, with the rationale that `rustls` refuses an expired one anyway. That
    // is true and hits the wrong side: the agent then minted merrily on, and the
    // failure landed at the workloads' connections instead of with whoever can
    // fix it.
    //
    // **One** reading: service and marker arise from the same bytes. Two would be
    // a window into which the renewal path writes -- and afterwards the node would
    // never take anything over again.
    let material = identity::Material::read(&options.data_dir);
    let mut minter = identity::minter(&material, &domain).map_err(|err| err.to_string())?;
    let anchors = material.anchors().map_err(|err| err.to_string())?;

    // The sidecars are part of the desired state: they are derived before
    // anybody asks for an identity (ADR-0007/0036).
    //
    // **This here is the seeding, not the list.** What this node may mint the
    // reconciler writes on at every pass (`refresh_identity`) -- only so does a
    // workload that arrives **after** the start ever get an SVID. Starting empty
    // and waiting on that alone would be wrong all the same: the socket comes up
    // deliberately **before** the runtime search so that a running container can
    // rotate even when no pass comes about any more (ADR-0019). Without the
    // seeding this case would have nothing to mint from.
    //
    // The derivation *rule* is the same as there -- `tg_model::mesh::expand`,
    // once in the tree (ADR-0059). What differs is only the input: here the whole
    // cache, there what is really assigned to the node. The pass therefore
    // narrows, it does not contradict.
    let (assigned, delegated) = match &options.proxy_image {
        Some(image) => {
            let spec = SidecarSpec::new(image.clone(), options.trust_domain.clone())
                .map(|spec| spec.pinned_shards(options.pin_sidecar_shards))
                .map_err(|err| err.to_string())?;
            let expanded =
                tg_model::mesh::expand(workloads, &spec).map_err(|err| err.to_string())?;
            let assignment = identity::assignment(&expanded, &spec);
            (assignment.assigned, assignment.delegations)
        }
        None => (
            identity::container_ids(workloads),
            std::collections::BTreeMap::new(),
        ),
    };

    tracing::info!(
        sockets = %options.data_dir.join("sockets").display(),
        workloads = assigned.len(),
        delegations = delegated.len(),
        "workload API"
    );
    minter.set_assigned(assigned);
    minter.set_delegations(delegated);

    let api = identity::workload_api(minter, anchors);
    // **The handle stays here.** What this node may mint changes while it runs
    // (ADR-0019: from the local cache) -- the reconciler writes it on at every
    // pass.
    let handle = api.clone();

    // **One listener per instance** (ADR-0081, determination 5): they arise in
    // the reconciler's start path, because the socket must be there **before**
    // the bundle -- it is mounted.
    let listeners = sockets::Listeners::open(&options.data_dir, api)?;

    Ok(Some((std::sync::Arc::new(listeners), handle, material)))
}

fn thaw_leftovers(paths: &NodePaths) {
    match tg_runtime::volume::VolumeStore::open(paths.data_dir()).and_then(|store| store.thaw_all())
    {
        Ok(0) => {}
        Ok(thawed) => tracing::warn!(thawed, "frozen volumes thawed"),
        Err(err) => tracing::warn!(detail = %err, "volumes not checked for a freeze"),
    }
}

#[cfg(test)]
mod tests {
    // ============================ The address plan has one source (ADR-0069)

    fn with_cluster_network(cidr: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let network = dir.path().join("network");
        std::fs::create_dir_all(&network).expect("directory");
        std::fs::write(
            network.join("cluster.json"),
            format!(r#"{{"cidr":"{cidr}","node_prefix":24}}"#),
        )
        .expect("Netzparameter");
        dir
    }

    fn options_in(dir: &std::path::Path) -> super::Options {
        super::Options {
            data_dir: dir.to_path_buf(),
            ..super::Options::default()
        }
    }

    #[test]
    fn the_address_plan_comes_from_the_cluster_when_it_is_there() {
        let dir = with_cluster_network("10.99.0.0/16");
        let options = options_in(dir.path());

        // The setting stands at the default and is thereby *different* --
        // otherwise the test would not say which source won.
        assert_eq!(options.cluster_cidr, "10.42.0.0/16");

        let plan = super::cluster_net(&options).expect("address plan");

        assert_eq!(plan.net().to_string(), "10.99.0.0/16");
    }

    #[test]
    fn without_the_file_the_flag_carries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut options = options_in(dir.path());
        options.cluster_cidr = String::from("10.77.0.0/16");

        let plan = super::cluster_net(&options).expect("address plan");

        assert_eq!(plan.net().to_string(), "10.77.0.0/16");
    }

    #[test]
    fn a_typo_in_the_cidr_does_not_become_the_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut options = options_in(dir.path());
        options.cluster_cidr = String::from("10.42.0/16");

        let refused = super::cluster_net(&options).expect_err("no address plan");

        assert!(refused.contains("10.42.0/16"), "{refused}");
    }

    use super::{Options, mesh, publish};
    use std::path::Path;
    use std::time::Duration;
    use tg_model::Quorum;
    use tg_runtime::reconcile::{Instance, Report};
    use tg_store::{ActualStatus, Projection};

    fn options(args: &[&str]) -> Options {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        Options::from(&args)
    }

    // ======================== The trust domain reaches the sidecar (0006)

    #[test]
    fn the_sidecar_gets_the_trust_domain_of_this_node() {
        let options = options(&[
            "--proxy-image",
            "registry.example.test/proxy:1",
            "--trust-domain",
            "acme.internal",
        ]);

        let mesh = mesh(&options).expect("with a proxy image a mesh arises");
        assert_eq!(
            mesh.spec.trust_domain(),
            "acme.internal",
            "the sidecar would otherwise get its own default and would find no anchor"
        );
    }

    #[test]
    fn the_cdi_directories_are_repeatable() {
        let named = options(&["--cdi-dir", "/a/cdi", "--cdi-dir", "/b/cdi"]);
        assert_eq!(
            named.cdi_dirs,
            vec![
                std::path::PathBuf::from("/a/cdi"),
                std::path::PathBuf::from("/b/cdi")
            ]
        );

        // **Without a setting: empty** -- `ledgers` sets the default, not the
        // parser. Two places for the same list would be two opportunities for
        // them to drift apart.
        let without = options(&[]);
        assert!(without.cdi_dirs.is_empty());
    }

    #[test]
    fn without_the_option_the_nodes_default_reaches_the_sidecar() {
        let options = options(&["--proxy-image", "registry.example.test/proxy:1"]);

        let mesh = mesh(&options).expect("mesh");
        assert_eq!(mesh.spec.trust_domain(), "cluster.local");
    }

    // ==================== The user namespace demands a runtime (0091)

    #[test]
    fn a_demanded_mapping_without_a_capable_runtime_refuses_to_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut demanded = options(&[]);
        demanded.userns = Some(tg_runtime::userns::Mapping::new(100_000).expect("range"));

        for name in ["youki", "crun"] {
            let Ok(runtime) = super::OciRuntime::discover(&[name], dir.path()) else {
                // Both are an operational prerequisite of this tree (ADR-0003);
                // if one is missing, the test says so instead of skipping
                // silently.
                panic!("'{name}' does not lie in the PATH -- an operational prerequisite");
            };

            let verdict = super::hardening(&demanded, &runtime);
            assert_eq!(
                verdict.is_ok(),
                tg_runtime::userns::supported_by(name),
                "'{name}': {verdict:?}"
            );
        }
    }

    #[test]
    fn the_userns_range_is_read_and_a_bad_one_refused() {
        assert_eq!(
            options(&["--userns-base", "100000"]).userns,
            Some(tg_runtime::userns::Mapping::new(100_000).expect("valid")),
        );

        for unusable in ["1000", "0", "no-number", "", "4294967295"] {
            assert_eq!(
                options(&["--userns-base", unusable]).userns,
                None,
                "'{unusable}' should have been refused"
            );
        }

        // And without the setting everything stays as it was.
        assert_eq!(options(&[]).userns, None);
    }

    #[test]
    fn without_the_option_no_runtime_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = super::OciRuntime::discover(&["youki"], dir.path()).expect("youki");

        super::hardening(&options(&[]), &runtime)
            .expect("without --userns-base there is nothing to do");
    }

    #[test]
    fn defaults_apply_without_arguments() {
        let parsed = options(&[]);

        assert_eq!(parsed.data_dir, Path::new(tg_runtime::DEFAULT_DATA_DIR));
        assert_eq!(parsed.interval, Duration::from_secs(10));
        assert!(!parsed.once);
        assert_eq!(parsed.quorum, Quorum::Available);
    }

    #[test]
    fn every_flag_is_read() {
        let parsed = options(&[
            "--once",
            "--no-quorum",
            "--no-seccomp",
            "--no-identity",
            "--pin-sidecar-shards",
            "--data-dir",
            "/srv/tg",
            "--interval",
            "3",
            "--keep-snapshots",
            "7",
            "--cluster-cidr",
            "10.99.0.0/16",
            "--node-prefix",
            "26",
            "--dns-domain",
            "acme.internal",
            "--dns-forward",
            "10.0.0.53:53",
            "--trust-domain",
            "acme.example",
            "--proxy-image",
            "reg.test/tg-proxy:1",
            "--node",
            "node-7",
            "--control-plane",
            "cp-a:9443",
            "--node-session",
            "cp-a:9444",
            "--underlay-endpoint",
            "203.0.113.7:51820",
            "--userns-base",
            "500000",
        ]);

        assert!(parsed.once);
        assert_eq!(parsed.quorum, Quorum::Unavailable);
        assert!(parsed.no_seccomp);
        assert!(!parsed.identity);
        assert!(parsed.pin_sidecar_shards, "ADR-0114, Festlegung 3");
        assert_eq!(parsed.data_dir, Path::new("/srv/tg"));
        assert_eq!(parsed.interval, Duration::from_secs(3));
        assert_eq!(parsed.keep_snapshots, 7);
        assert_eq!(parsed.cluster_cidr, "10.99.0.0/16");
        assert_eq!(parsed.node_prefix, 26);
        assert_eq!(parsed.dns_domain, "acme.internal");
        assert_eq!(
            parsed.dns_forward,
            Some("10.0.0.53:53".parse().expect("Adresse"))
        );
        assert_eq!(parsed.trust_domain, "acme.example");
        assert_eq!(parsed.proxy_image.as_deref(), Some("reg.test/tg-proxy:1"));
        assert_eq!(parsed.node, "node-7");
        assert_eq!(parsed.control_plane, vec![String::from("cp-a:9443")]);
        assert_eq!(parsed.node_session, vec![String::from("cp-a:9444")]);
        assert_eq!(
            parsed.underlay_endpoint.as_deref(),
            Some("203.0.113.7:51820")
        );
        assert!(parsed.userns.is_some());

        // The counter-direction: **none** of these values is the default.
        let plain = options(&[]);
        assert!(!plain.no_seccomp, "the profile is the default (ADR-0090)");
        assert!(plain.identity, "the identity service is the default");
        assert_eq!(plain.keep_snapshots, 3);
        assert_eq!(plain.node_prefix, 24);
        assert_eq!(plain.dns_domain, "tardigrade.internal");
        assert_eq!(plain.dns_forward, None);
        assert!(plain.userns.is_none(), "no user namespace (ADR-0091 D3)");
        // **And no pinning** (ADR-0114 D3). The same stance, the same place:
        // both defaults are "off", because the measurement does not carry them
        // generally -- and a default without a witness is one that tips over at
        // the next rebuild.
        assert!(!plain.pin_sidecar_shards, "no pinning (ADR-0114 D3)");
    }

    #[test]
    fn every_parsed_flag_has_a_witness() {
        let source = include_str!("main.rs");
        let cut = source
            .find("#[cfg(test)]")
            .expect("the source has a test module");
        let tests = &source[cut..];
        let flags = parsed_flags();

        let missing: Vec<&str> = flags
            .iter()
            .copied()
            .filter(|flag| !tests.contains(flag))
            .collect();
        assert!(
            missing.is_empty(),
            "these flags are parsed and named by no test: {missing:?}"
        );
    }

    #[test]
    fn order_does_not_matter_and_the_last_value_wins() {
        let a = options(&["--data-dir", "/a", "--interval", "5", "--once"]);
        let b = options(&["--once", "--interval", "5", "--data-dir", "/a"]);
        assert_eq!(a.data_dir, b.data_dir);
        assert_eq!(a.interval, b.interval);
        assert_eq!(a.once, b.once);

        let last = options(&["--data-dir", "/a", "--data-dir", "/b"]);
        assert_eq!(last.data_dir, Path::new("/b"));
    }

    #[test]
    fn a_dangling_flag_falls_back_to_the_default() {
        assert_eq!(
            options(&["--data-dir"]).data_dir,
            Path::new(tg_runtime::DEFAULT_DATA_DIR)
        );
        assert_eq!(options(&["--interval"]).interval, Duration::from_secs(10));
    }

    #[test]
    fn an_unusable_interval_is_ignored() {
        for value in [
            "0",
            "-5",
            "abc",
            "3.5",
            "",
            " 3",
            "99999999999999999999999999",
        ] {
            assert_eq!(
                options(&["--interval", value]).interval,
                Duration::from_secs(10),
                "'{value}' must not have been taken over"
            );
        }
    }

    #[test]
    fn a_zero_interval_no_longer_starves_the_loop() {
        assert_eq!(
            options(&["--interval", "0"]).interval,
            Options::default().interval,
            "a zero must not let the reconciliation run without a pause"
        );

        // The counter-check: a usable number still applies. Without it a parser
        // that discards **every** value would be just as green.
        assert_eq!(
            options(&["--interval", "30"]).interval,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn unknown_arguments_do_not_shift_the_others() {
        let parsed = options(&["--whatever", "--data-dir", "/srv/tg", "rest"]);
        assert_eq!(parsed.data_dir, Path::new("/srv/tg"));
    }

    #[test]
    fn a_flag_shaped_value_is_taken_as_a_value() {
        let parsed = options(&["--data-dir", "--once"]);
        assert_eq!(parsed.data_dir, Path::new("--once"));
        assert!(!parsed.once);
    }

    #[test]
    fn odd_paths_arrive_unchanged() {
        for path in [
            "/srv/tg data",
            "/srv/tg;rm -rf /",
            "relativ/pfad",
            "/srv/tg\n",
        ] {
            assert_eq!(options(&["--data-dir", path]).data_dir, Path::new(path));
        }
    }

    fn parsed_flags() -> Vec<&'static str> {
        let source = include_str!("main.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap_or(source.len())];

        let mut flags: Vec<&str> = production
            .match_indices("\"--")
            .filter_map(|(at, _)| {
                let rest = &production[at + 1..];
                let end = rest.find('"')?;
                let flag = &rest[..end];
                (flag.len() > 2
                    && flag[2..]
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '-'))
                .then_some(flag)
            })
            .collect();
        flags.sort_unstable();
        flags.dedup();

        // Without this assurance **both** callers would be green too if the
        // search found nothing -- and precisely then they check nothing.
        assert!(
            flags.len() > 15,
            "only {} flags were found -- the cut is wrong",
            flags.len()
        );
        flags
    }

    #[test]
    fn the_usage_text_lists_every_flag() {
        let help = super::usage();
        for flag in parsed_flags() {
            assert!(
                tg_telemetry::args::mentions_word(&help, flag),
                "{flag} is missing from the overview"
            );
        }
    }

    // --- Reporting into the projection --------------------------------------

    fn workloads(names: &[&str]) -> Vec<tg_defs::generated::WorkloadType> {
        use std::fmt::Write as _;

        let mut body = String::new();
        for name in names {
            let _ = write!(
                body,
                "  <workload name=\"{name}\" kind=\"service\">\n\
                 \x20   <image reference=\"example.com/{name}:1\"/>\n\
                 \x20 </workload>\n"
            );
        }
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <workloads xmlns=\"urn:tardigrade:workload:v1\">\n{body}</workloads>\n"
        );

        tg_defs::from_str(&xml)
            .expect("the fixture must parse")
            .workloads()
            .to_vec()
    }

    #[test]
    fn a_fenced_and_a_waiting_instance_count_as_stopped() {
        let projection = Projection::new();
        projection.materialize(&workloads(&["fenced", "waiting"]));

        publish(
            &projection,
            "node-test",
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                fenced: vec![Instance::new("fenced", 0)],
                waiting: vec![Instance::new("waiting", 0)],
                ..Report::default()
            },
        );

        let actual = projection.actual_states();
        assert_eq!(
            actual.get(&("fenced".to_owned(), 0)),
            Some(&ActualStatus::Stopped),
            "a fenced instance must not count as running"
        );
        assert_eq!(
            actual.get(&("waiting".to_owned(), 0)),
            Some(&ActualStatus::Stopped)
        );
    }

    #[test]
    fn every_bucket_maps_to_the_status_it_means() {
        let projection = Projection::new();
        projection.materialize(&workloads(&["runs", "new", "waits", "broken"]));

        publish(
            &projection,
            "node-test",
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                stale: Vec::new(),
                unready: Vec::new(),
                waiting: Vec::new(),
                fenced: Vec::new(),
                untouched: vec![Instance::new("runs", 0)],
                reconciled: vec![Instance::new("new", 0)],
                deferred: vec![Instance::new("waits", 0)],
                failed: vec![tg_runtime::reconcile::Failure {
                    instance: Instance::new("broken", 0),
                    class: "runtime",
                    reason: "for the test".to_owned(),
                }],
                held: Vec::new(),
                isolated: Vec::new(),
                reaped: Vec::new(),
                own: std::collections::BTreeMap::new(),
                delegations: std::collections::BTreeMap::new(),
            },
        );

        let actual = projection.actual_states();
        assert_eq!(
            actual.get(&("runs".to_owned(), 0)),
            Some(&ActualStatus::Running)
        );
        assert_eq!(
            actual.get(&("new".to_owned(), 0)),
            Some(&ActualStatus::Running)
        );
        assert_eq!(
            actual.get(&("waits".to_owned(), 0)),
            Some(&ActualStatus::Stopped)
        );
        assert_eq!(
            actual.get(&("broken".to_owned(), 0)),
            Some(&ActualStatus::Failed)
        );
    }

    #[test]
    fn an_unknown_workload_does_not_cost_the_others() {
        let projection = Projection::new();
        projection.materialize(&workloads(&["known"]));

        publish(
            &projection,
            "node-test",
            &Report {
                unclear: Vec::new(),
                next_fence: None,
                waiting: Vec::new(),
                fenced: Vec::new(),
                untouched: vec![Instance::new("known", 0)],
                failed: vec![tg_runtime::reconcile::Failure {
                    instance: Instance::new("vanished", 0),
                    class: "runtime",
                    reason: "for the test".to_owned(),
                }],
                ..Report::default()
            },
        );

        let actual = projection.actual_states();
        assert_eq!(
            actual.get(&("known".to_owned(), 0)),
            Some(&ActualStatus::Running),
            "the remaining report must arrive"
        );
        assert_eq!(
            actual.get(&("vanished".to_owned(), 0)),
            Some(&ActualStatus::Failed),
            "and the unknown one is held, not discarded"
        );
    }

    #[test]
    fn an_empty_report_reports_nothing() {
        let projection = Projection::new();
        projection.materialize(&workloads(&["api"]));

        publish(&projection, "node-test", &Report::default());

        assert!(projection.actual_states().is_empty());
        assert_eq!(projection.worst_of("api"), ActualStatus::Unknown);
    }

    #[test]
    fn reporting_twice_is_the_same_as_reporting_once() {
        let projection = Projection::new();
        projection.materialize(&workloads(&["api"]));
        let report = Report {
            waiting: Vec::new(),
            fenced: Vec::new(),
            reconciled: vec![Instance::new("api", 0)],
            ..Report::default()
        };

        publish(&projection, "node-test", &report);
        let after_first = projection.actual_states();
        publish(&projection, "node-test", &report);

        assert_eq!(projection.actual_states(), after_first);
    }

    #[test]
    fn an_unready_instance_stays_running() {
        let projection = Projection::new();
        projection.materialize(&workloads(&["api"]));
        let report = Report {
            untouched: vec![Instance::new("api", 0)],
            unready: vec![Instance::new("api", 0)],
            ..Report::default()
        };

        publish(&projection, "node-test", &report);

        assert_eq!(
            projection.worst_of("api"),
            ActualStatus::Running,
            "unready is no state -- the instance runs, it only does not serve"
        );
        assert!(
            projection.unready().contains(&("api".to_owned(), 0)),
            "the readiness must arrive in the projection, otherwise the resolver \
             goes on resolving the mute endpoint"
        );
    }

    #[test]
    fn becoming_ready_again_clears_the_finding() {
        let projection = Projection::new();
        projection.materialize(&workloads(&["api"]));

        publish(
            &projection,
            "node-test",
            &Report {
                unclear: Vec::new(),
                untouched: vec![Instance::new("api", 0)],
                unready: vec![Instance::new("api", 0)],
                ..Report::default()
            },
        );
        assert!(!projection.unready().is_empty(), "erst unbereit");

        publish(
            &projection,
            "node-test",
            &Report {
                unclear: Vec::new(),
                untouched: vec![Instance::new("api", 0)],
                ..Report::default()
            },
        );

        assert!(
            projection.unready().is_empty(),
            "a probe that answers again must clear the finding"
        );
    }
    #[test]
    fn every_fixed_path_in_the_container_has_a_mount() {
        let parsed = options(&["--proxy-image", "registry.example.com/proxy:1"]);
        let mesh = mesh(&parsed).expect("with a proxy image there is a mesh");

        let mut destinations: Vec<&str> = mesh
            .mounts
            .iter()
            .map(|mount| mount.destination.as_str())
            .collect();
        destinations.sort_unstable();

        // **The socket no longer stands here** (ADR-0081): it is per instance,
        // and `Mesh { mounts }` is **one** list for all sidecars -- a path in it
        // could only be one. It now comes over `Sockets::ensure`, and for
        // **every** container at that, not only the sidecar. The three files
        // stay.
        let mut expected = vec![
            tg_model::mesh::EDGES_IN_CONTAINER,
            tg_model::mesh::EGRESS_IN_CONTAINER,
            tg_model::mesh::ROLE_IN_CONTAINER,
        ];
        expected.sort_unstable();

        assert_eq!(destinations, expected);

        // And the direction: the three files are **read-only** -- a sidecar that
        // could change its own permission list would be no enforcement
        // (ADR-0059).
        for mount in &mesh.mounts {
            assert!(mount.readonly, "{} must be read-only", mount.destination);
        }
    }
    #[test]
    fn the_alert_rules_quote_the_real_cadences() {
        let rules = include_str!("../../../docs/alerts.yml");

        // The head names them as `#   <name>   <number> <unit>`; the
        // intermediate's line names **two** (lifetime and renewal cadence), so the
        // helper takes the n-th. The ADR references behind them do not parse as a
        // number (`(ADR-0014,`), so they do not disturb.
        let quoted = |label: &str, nth: usize| -> u64 {
            let line = rules
                .lines()
                .find(|line| line.trim_start().starts_with(&format!("#   {label}")))
                .unwrap_or_else(|| panic!("'{label}' does not stand in the head of alerts.yml"));
            line.split_whitespace()
                .filter_map(|word| word.parse::<u64>().ok())
                .nth(nth)
                .unwrap_or_else(|| panic!("'{label}' names no number {}: {line}", nth + 1))
        };

        for (label, nth, measured, what) in [
            (
                "Lease",
                0,
                tg_model::lease::LEASE_SECONDS.unsigned_abs(),
                "the lease deadline (ADR-0014)",
            ),
            (
                "Lease cadence",
                0,
                tg_model::lease::LEASE_TICK_MILLIS / 1_000,
                "the lease cadence (ADR-0076)",
            ),
            (
                "Report cadence",
                0,
                tg_store::session::REPORT_EVERY_SECONDS.unsigned_abs(),
                "the report cadence (ADR-0068)",
            ),
            (
                "Report window",
                0,
                tg_store::session::REPORT_WINDOW_SECONDS.unsigned_abs(),
                "the report window (ADR-0068)",
            ),
            (
                "Staleness window",
                0,
                tg_proxy::policy::RevocationWindow::adr_0014()
                    .staleness
                    .as_secs()
                    / 60,
                "the staleness window of the policy cache (ADR-0014)",
            ),
            (
                "SVID",
                0,
                tg_identity::Lifetime::default().ttl.as_secs() / 60,
                "the SVID lifetime (ADR-0014)",
            ),
            (
                "Agent intermediate",
                0,
                tg_identity::IntermediateProfile::TTL.as_secs() / 3_600,
                "the lifetime of the agent intermediate (ADR-0014)",
            ),
            (
                "Agent intermediate",
                1,
                crate::join::RENEW_EVERY.as_secs() / 3_600,
                "the agent's renewal cadence (ADR-0037)",
            ),
        ] {
            assert_eq!(
                quoted(label, nth),
                measured,
                "{what}: the head of alerts.yml names a different number than the \
                 code -- either the constant has moved and the text drifts, or the \
                 `for:` durations below rest on a cadence that does not exist"
            );
        }
    }
}
