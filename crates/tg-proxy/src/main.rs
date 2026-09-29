//! The sidecar process (ADR-0007, ADR-0022, ADR-0025, ADR-0036).
//!
//! It runs in the container beside its workload, fetches its identity over the
//! workload API socket and terminates mTLS in both directions.
//!
//! # What it does at startup, in this order
//!
//! 1. **Fetch the identity.** Over the socket, with the `spiffe` library. It
//!    gets two SVIDs (ADR-0036) and takes the one with `hint = "delegated"` --
//!    only that way do the `may_talk` edges read what the operator wrote.
//! 2. **Load the policy.** Until the control plane distributes it, from a
//!    file.
//! 3. **Run the shards.** One `current_thread` runtime per core, each with its
//!    own `SO_REUSEPORT` socket (ADR-0022).
//!
//! If step 1 fails, it does **not** start. A sidecar without an identity could
//! terminate nothing and authorize nothing; it would run as an open port
//! without an opinion, and that would be worse than a process that is
//! missing.

#![forbid(unsafe_code)]
// **No panic-capable call in the production path** (ADR-0082): there a panic
// costs its task and not the node -- and that is a state an operator sees only
// at a metric. `not(test)`, because the unit tests in `src` need them; the
// guard lies in `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tg_proxy::identity::Identity;
use tg_proxy::options::{Options, edges_from_text};
use tg_proxy::policy::{PolicyCache, RevocationWindow, Snapshot};
use tg_proxy::sidecar::{Config, Route};
use tg_proxy::verify::{Bundle, SharedBundle, SharedPolicy};

const USAGE: &str = "\
tg-proxy -- the mTLS sidecar for Tardigrade

Calls:
  tg-proxy --workload <name> --upstream-port <n> --socket <path> [...]

Mandatory settings (they stand in the derived sidecar unit):
  --workload <name>         for whom it proxies
  --upstream-port <n>       where incoming traffic goes on loopback
  --socket <path>           the workload API socket (ADR-0035)

Further:
  --listen <address>        where incoming mTLS is accepted
  --route <peer>=<address>  one outgoing route; can be given several times
  --policy <file>           may_talk edges, one per line: 'a -> b'
  --trust-domain <name>     default: cluster.local
  --shards <n>              default: as many as there are cores (ADR-0022)
  --egress-listen <address> where outgoing traffic is accepted (ADR-0041).
                            Without this setting there is no egress --
                            deny-by-default applies to the port itself too.
  --mesh-listen <address>   where redirected mesh traffic is accepted
                            (ADR-0060). The destination then comes from the
                            kernel (SO_ORIGINAL_DST) and not from --route.
  --egress <file>           egress permissions, one per line:
                            'workload name port'. The agent writes them from
                            the slice (ADR-0040).
  --mesh-udp-listen <addr>  where incoming datagrams are accepted (ADR-0142)
                            -- the constant, not the declaration: the sending
                            sidecar does not know its peer's definition
                            (ADR-0040).
  --mesh-udp-upstream <p>   where incoming datagrams are passed through to:
                            the workload's port from the udp attribute of
                            <mesh>, as --upstream-port with TCP.
  --mesh-udp <file>         the peer mapping for UDP in the mesh, one per line:
                            'workload peer address:port local-port'. The local
                            port carries which peer was meant -- with UDP the
                            destination address survives no redirect
                            (ADR-0142, determination 8).
  --active-role <file>      the active-role leases, one per line:
                            'workload epoch deadline'. The agent writes them
                            from the slice (ADR-0064).
  --single-writer           this workload is a single writer (ADR-0066). Only
                            then does the sidecar rein it in: if the workload
                            does not hold the active role, neither mesh nor
                            egress traffic gets through. The setting stands
                            **here** and not in the file -- fail-closed: a
                            missing file must not mean 'nobody is affected'.
  --pin-shards              pin every shard onto a fixed core (ADR-0114).
                            Default off: measured, it brings no tail
                            advantage, and whoever is the only one nailed down
                            cannot move aside from an occupied core -- the
                            neighbour is its own workload (ADR-0059). Pinning
                            happens over the cores the cgroup concedes
                            (sched_getaffinity), not over the number of the
                            machine's cores.
";

const USAGE_TAIL: &str = "\
  help                      this overview (also -h, --help)

Without --policy deny-by-default applies and nothing gets through (ADR-0025).
Without --mesh-listen there is no collector port for redirected mesh traffic;
then what --route says applies (the setup without a redirect).
";

const RELOAD: Duration = Duration::from_mins(1);

fn usage() -> String {
    format!("{USAGE}{}{USAGE_TAIL}", tg_telemetry::args::Args::USAGE)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // The helper lies in `tg_telemetry::args`, where the shared part of the
    // overview lies too.
    if tg_telemetry::args::wants_help(&args) {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }

    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(err) => {
            // Before the subscriber: a `tracing` event would be silent here.
            eprintln!("tg-proxy: {err}\n\n{}", usage());
            return ExitCode::FAILURE;
        }
    };

    // As in the two other binaries: the holder outlives the run.
    let telemetry = match tg_telemetry::init::init(
        &options.telemetry.to_options(
            "tg-proxy",
            // A sidecar does not know the node (ADR-0059) -- its label is
            // the workload.
            tg_telemetry::init::Reporter::Workload(options.workload.clone()),
        ),
        tg_telemetry::init::Reactor::NoTracing,
    ) {
        Ok(telemetry) => Some(telemetry),
        Err(err) => {
            eprintln!("tg-proxy: the telemetry did not come up: {err}");
            None
        }
    };
    let scrape: tg_telemetry::serve::Scrape = telemetry.as_ref().map_or_else(
        || std::sync::Arc::new(String::new) as tg_telemetry::serve::Scrape,
        tg_telemetry::init::Telemetry::scrape,
    );

    match run(options, scrape) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!(%message, "tg-proxy has ended");
            ExitCode::FAILURE
        }
    }
}

fn start_telemetry(
    options: &Options,
    health: &tg_telemetry::probes::Health,
    scrape: tg_telemetry::serve::Scrape,
) {
    let Some(addr) = options.telemetry.addr else {
        return;
    };
    let health = health.clone();

    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            tracing::warn!("the telemetry runtime is not startable");
            return;
        };
        if let Err(err) = runtime.block_on(tg_telemetry::serve::serve(addr, health, scrape)) {
            // Fail-soft: a sidecar without metrics carries on enforcing.
            tracing::warn!(%addr, error = %err, "the telemetry endpoint");
        }
    });
}

fn prepare(
    options: &Options,
    scrape: tg_telemetry::serve::Scrape,
) -> Result<
    (
        tg_proxy::identity::SharedIdentity,
        SharedBundle,
        tg_telemetry::probes::Health,
    ),
    String,
> {
    let bootstrap = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("the runtime is not startable: {err}"))?;
    let (identity, anchors) = bootstrap.block_on(fetch_identity(options))?;

    let health = tg_telemetry::probes::Health::new();
    health.set("sidecar", tg_telemetry::probes::Readiness::up());
    // **Refresh the open connections in the scrape** (ADR-0114, ADR-0088). A
    // sidecar with four standing connections does not set the gauge for hours;
    // after fifteen minutes the series would expire, and an operator would
    // read "no data" where "four" would be right. The same construction as
    // with the QUIC flows below (ADR-0121).
    health.on_scrape(
        tg_telemetry::names::PROXY_CONNECTIONS,
        tg_proxy::sidecar::refresh_connections,
    );
    drop(bootstrap);
    start_telemetry(options, &health, scrape);

    Ok((
        tg_proxy::identity::SharedIdentity::new(identity),
        SharedBundle::new(Bundle::from_der(anchors)),
        // **The handle travels along** (ADR-0121, determination 6): the
        // gauge over the open QUIC flows changes rarely enough that without a
        // registration in the scrape it would expire after a quarter of an
        // hour (ADR-0088). Without it, it would stay lying here.
        health,
    ))
}

fn shards(options: &Options) -> tg_proxy::Shards {
    let set = options
        .shards
        .map_or_else(tg_proxy::Shards::all_cores, tg_proxy::Shards::exactly)
        // ADR-0114, determination 3: default off, and when on, then over the
        // cores the cgroup concedes.
        .pinned(options.pin_shards);

    tracing::info!(
        shards = set.count(),
        pinned = options.pin_shards,
        cores = ?tg_proxy::allowed_cores(),
        "thread-per-core (ADR-0022, ADR-0114)"
    );

    set
}

fn run(options: Options, scrape: tg_telemetry::serve::Scrape) -> Result<(), String> {
    let (identity, bundle, health) = prepare(&options, scrape)?;

    let policy = load_policy(&options)?;
    // **Once for all the shards** -- the same consideration as with the
    // edges: cached locally, enforced locally (ADR-0025), and reading it
    // several times would bring nothing but more file accesses.
    let egress = tg_proxy::egress::SharedEgress::new(load_egress_or_empty(&options));
    let window = RevocationWindow::adr_0014();
    let config = Config {
        identity: identity.clone(),
        bundle: bundle.clone(),
        policy: policy.clone(),
        window,
        role: gate_for(&options),
    };

    tracing::info!(
        workload = %options.workload,
        id = %config.identity.id(),
        routes = options.routes.len(),
        "the sidecar is ready"
    );

    // **`SIGTERM` is a signal, no no-op** (ADR-0058). The sidecar is PID 1 in
    // its container, and without an installed handler the kernel does not
    // apply the default handling -- measured, the container ran on through the
    // whole grace period and was **removed** afterwards, whereby every running
    // connection tore down at one stroke.
    let stop = stop_on_sigterm();

    let shards = shards(&options);

    let options = Arc::new(options);
    shards
        .run(move |shard| {
            let config = config.clone();
            let options = Arc::clone(&options);
            let policy = policy.clone();
            let egress = egress.clone();
            let identity = identity.clone();
            let bundle = bundle.clone();
            let stop = stop.clone();
            let health = health.clone();

            async move {
                let mut tasks = Vec::new();

                if let Some(addr) = options.inbound {
                    match listener(addr) {
                        Ok(listener) => {
                            let config = config.clone();
                            let port = options.upstream_port;
                            let shutdown = stopped(&stop);
                            tasks.push(tokio::spawn(async move {
                                if let Err(error) =
                                    tg_proxy::serve_inbound(config, listener, port, shutdown).await
                                {
                                    tracing::error!(shard, %error, "the incoming route has ended");
                                }
                            }));
                        }
                        Err(err) => {
                            tracing::error!(shard, %addr, error = %err, "the shard failed");
                        }
                    }
                }

                for (peer, connect) in &options.routes {
                    let Ok(id) = options.peer_id(peer) else {
                        continue;
                    };
                    let route = Route {
                        listen: *connect,
                        connect: *connect,
                        peer: id,
                    };
                    // **Listening and dialling are the same address here**,
                    // and that is the purpose of `--route`: a route by hand,
                    // without a redirect and without privileges.
                    //
                    // It stood here "as soon as phase 9 brings the redirect"
                    // -- that has existed since ADR-0060, and in operation
                    // nobody sets `--route`: the derived unit hands over
                    // `--mesh-listen`, and the destination comes from the
                    // kernel (`SO_ORIGINAL_DST`). This route stays because it
                    // is the only way to check the mTLS rejection cases in the
                    // ordinary suite.
                    let Ok(listener) = listener(route.listen) else {
                        continue;
                    };
                    let config = config.clone();
                    let shutdown = stopped(&stop);
                    tasks.push(tokio::spawn(async move {
                        if let Err(error) =
                            tg_proxy::serve_outbound(config, route, listener, shutdown).await
                        {
                            tracing::error!(%error, "the outgoing route has ended");
                        }
                    }));
                }

                if let Some(task) = spawn_mesh(&options, &config, shard, &stop) {
                    tasks.push(task);
                }

                if let Some(task) =
                    spawn_egress(&options, &egress, shard, config.role.clone(), &stop)
                {
                    tasks.push(task);
                }

                if shard == 0 {
                    // The gate comes from the config: a second derivation
                    // would be a second opportunity to differ.
                    let gate = config.role.clone();

                    // **The QUIC listeners here and not per shard**
                    // (ADR-0094, determination 2). They follow the allowlist,
                    // and the refresher beside them already reads that on this
                    // shard anyway -- one supervisor per shard would be N
                    // supervisors quarrelling over the same port.
                    //
                    // Unsharded is defensible, because the work per datagram
                    // is one copy and once per flow a decryption of the
                    // Initial; the sidecar terminates nothing here (ADR-0041).
                    // If a measurement showed that it costs the tail target
                    // from ADR-0022, the answer would be a thread of its own
                    // with its own runtime -- as with the telemetry
                    // endpoint.
                    tasks.push(tokio::spawn(tg_proxy::quic_egress::supervise(
                        egress.clone(),
                        tg_proxy::egress::Resolver::System,
                        health,
                        stopped(&stop),
                    )));

                    tasks.extend(freshness(&options, policy, egress, identity, bundle, gate));
                }

                // **A `let _ =` stood here**, and with it a panic in one of
                // these tasks disappeared without a trace: `tokio` catches it,
                // the `JoinError` was discarded, and the shard ran on -- with
                // one renewer fewer, which fifteen minutes later costs every
                // handshake (ADR-0014).
                //
                // That `tokio` catches it at all hangs on the release profile
                // (ADR-0082): with `panic = "abort"` the process dies before
                // this loop runs -- measured.
                for task in tasks {
                    if let Err(error) = task.await {
                        tracing::error!(shard, %error, "a task of the shard has ended");
                    }
                }
            }
        })
        .map_err(|err| format!("the shards are not startable: {err}"))
}

async fn fetch_identity(options: &Options) -> Result<(Identity, Vec<Vec<u8>>), String> {
    let endpoint = format!("unix://{}", options.socket.display());
    let client = spiffe::WorkloadApiClient::connect_to(&endpoint)
        .await
        .map_err(|err| format!("the workload API {endpoint} is not reachable: {err}"))?;

    let svids = client
        .fetch_all_x509_svids()
        .await
        .map_err(|err| format!("no SVID: {err}"))?;

    let identity = Identity::for_mesh(&material(svids.iter())).map_err(|err| err.to_string())?;

    let bundles = client
        .fetch_x509_bundles()
        .await
        .map_err(|err| format!("no trust bundle: {err}"))?;
    let domain = spiffe::TrustDomain::new(&options.trust_domain)
        .map_err(|err| format!("the trust domain: {err}"))?;
    let anchors = {
        use spiffe::BundleSource as _;

        bundles
            .bundle_for_trust_domain(&domain)
            .map_err(|err| format!("the trust bundle: {err}"))?
            .ok_or_else(|| format!("no anchor for {}", options.trust_domain))?
            .authorities()
            .iter()
            .map(|cert| cert.as_bytes().to_vec())
            .collect()
    };

    Ok((identity, anchors))
}

fn load_policy(options: &Options) -> Result<SharedPolicy, String> {
    let cache = PolicyCache::new(RevocationWindow::adr_0014());
    let shared = SharedPolicy::new(cache);

    if let Some(path) = &options.policy {
        let text =
            std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
        let edges = edges_from_text(&text).map_err(|err| err.to_string())?;
        shared
            .apply(&Snapshot::from_edges(1, edges), now())
            .map_err(|err| err.to_string())?;
    } else {
        // Without a file the cache stays empty, and empty means
        // deny-by-default (ADR-0025). That is the right direction, but it is
        // worth saying: otherwise somebody looks for the error in the
        // network.
        tracing::warn!("no --policy given -- nothing gets through");
    }

    Ok(shared)
}

fn stop_on_sigterm() -> tokio::sync::watch::Sender<bool> {
    let (sender, _) = tokio::sync::watch::channel(false);
    let signalled = sender.clone();

    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::warn!(%error, "no thread for SIGTERM -- the sidecar ends only when it is removed");
                return;
            }
        };

        runtime.block_on(async move {
            let mut term =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(term) => term,
                    Err(error) => {
                        tracing::warn!(%error, "SIGTERM is not catchable");
                        return;
                    }
                };
            term.recv().await;
            tracing::info!("SIGTERM -- no new connections, the running ones are being ended");
            // A failure means that nobody is listening any more: then the
            // shards are already finished.
            let _ = signalled.send(true);
        });
    });

    sender
}

fn stopped(stop: &tokio::sync::watch::Sender<bool>) -> impl Future<Output = ()> + Send + use<> {
    let mut seen = stop.subscribe();
    async move {
        // An error means that the sender is gone -- the process ends anyway,
        // so that counts as "end".
        let _ = seen.wait_for(|stopped| *stopped).await;
    }
}

fn spawn_mesh(
    options: &Options,
    config: &tg_proxy::sidecar::Config,
    shard: usize,
    stop: &tokio::sync::watch::Sender<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    let addr = options.mesh_listen?;

    let listener = match listener(addr) {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(shard, %addr, error = %err, "the mesh port failed");
            return None;
        }
    };
    let config = config.clone();
    let shutdown = stopped(stop);

    Some(tokio::spawn(async move {
        if let Err(error) = tg_proxy::sidecar::serve_mesh(config, listener, shutdown).await {
            tracing::error!(shard, %error, "the mesh port has ended");
        }
    }))
}

fn spawn_egress(
    options: &Options,
    egress: &tg_proxy::egress::SharedEgress,
    shard: usize,
    role: Option<tg_proxy::role::Gate>,
    stop: &tokio::sync::watch::Sender<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    let addr = options.egress_listen?;
    let policy = egress.clone();
    let shutdown = stopped(stop);

    let listener = match listener(addr) {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(shard, %addr, error = %err, "the route failed");
            return None;
        }
    };

    Some(tokio::spawn(async move {
        // **The same window as in the mesh** (ADR-0041: one enforcement
        // place for both directions). A number of its own here would be a
        // second source for the same deadline from ADR-0014.
        tg_proxy::egress::serve(
            listener,
            policy,
            tg_proxy::egress::Resolver::System,
            tg_proxy::policy::RevocationWindow::adr_0014(),
            role,
            shutdown,
        )
        .await;
    }))
}

fn gate_for(options: &Options) -> Option<tg_proxy::role::Gate> {
    options.single_writer.then(|| {
        let roles = tg_proxy::role::SharedRoles::new(load_roles_or_empty(options));
        tg_proxy::role::Gate::new(options.workload.clone(), roles)
    })
}

fn load_roles_or_empty(options: &Options) -> tg_proxy::role::Roles {
    let Some(path) = &options.active_role else {
        // **And that is a permanently mute sidecar.** Without a file there
        // is no role, and without a role the gate refuses in both directions
        // (ADR-0066) -- fail-closed and thereby the safe direction, but
        // without a word it would not be distinguishable from a network
        // problem.
        //
        // In the field the case does not occur: `mesh::build` hands
        // `--active-role` over unconditionally (ADR-0059). It arises by hand
        // -- and then somebody looks at the workload.
        tracing::warn!(
            "--single-writer without --active-role: this sidecar never gets an \
             active role and serves nobody"
        );
        return tg_proxy::role::Roles::default();
    };

    match std::fs::read_to_string(path) {
        Ok(text) => tg_proxy::role::Roles::from_text(&text),
        Err(err) => {
            tracing::warn!(error = %err, path = %path.display(), "no active role is readable");
            tg_proxy::role::Roles::default()
        }
    }
}

fn load_egress_or_empty(options: &Options) -> tg_proxy::egress::EgressPolicy {
    let Some(addr) = options.egress_listen else {
        // **The permissions are then not read at all.** The port is not only
        // the listener, it also carries the bolt from ADR-0051 determination 3
        // (the own port must never stand in the list) -- without it there is
        // no list, and thereby no way out and no QUIC listener (ADR-0094).
        //
        // This too does not occur in the field (`mesh::build` hands both
        // over), and here too the coupling stood nowhere.
        if options.egress.is_some() {
            tracing::warn!(
                "--egress without --egress-listen: the permissions are not read, \
                 and nothing goes out"
            );
        }
        return tg_proxy::egress::EgressPolicy::from_entries([]);
    };

    load_egress(options, addr.port()).unwrap_or_else(|err| {
        tracing::error!(error = %err, "no egress -- the list stays empty");
        tg_proxy::egress::EgressPolicy::from_entries([])
    })
}

fn load_egress(options: &Options, listen: u16) -> Result<tg_proxy::egress::EgressPolicy, String> {
    let Some(path) = &options.egress else {
        return Ok(tg_proxy::egress::EgressPolicy::from_entries([]));
    };

    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let entries = tg_proxy::options::egress_from_text(&text, &options.workload)
        .map_err(|err| err.to_string())?;

    // **The own port never belongs in the list** (ADR-0051, determination
    // 3). Whoever dials it directly has not run through the redirect from 9b,
    // and `SO_ORIGINAL_DST` then names precisely that port -- if it stood in
    // the list, everyone who reaches it would get out.
    //
    // Until here that stood in the operations manual. The **one** permission
    // is discarded and not the whole list: the gap is thereby closed, and
    // taking all its targets away from a workload because one is wrong would
    // be disproportionate. It is said nevertheless -- silently it would be a
    // riddle.
    let (entries, dropped) = tg_proxy::egress::without_listen_port(entries, listen);
    for (host, port, transport) in dropped {
        tracing::warn!(
            %host,
            port,
            %transport,
            "the egress permission onto the own port is discarded -- it would \
             be the bypass of the redirect (ADR-0051)"
        );
    }

    Ok(tg_proxy::egress::EgressPolicy::from_entries(entries))
}

async fn reload_policy(policy: SharedPolicy, options: Arc<Options>) {
    let Some(path) = options.policy.clone() else {
        return;
    };
    let mut version = 1_u64;

    loop {
        tokio::time::sleep(RELOAD).await;
        let at = now();

        match tg_proxy::policy::refresh(&policy, &path, version + 1, at) {
            tg_proxy::policy::Refresh::Applied => version += 1,
            tg_proxy::policy::Refresh::Unreadable { detail } => {
                tracing::warn!(%detail, path = %path.display(), "the edge file is unreadable");
            }
            tg_proxy::policy::Refresh::Malformed { detail } => {
                tracing::warn!(%detail, path = %path.display(), "the edge file is uninterpretable");
            }
            tg_proxy::policy::Refresh::Rejected { detail } => {
                tracing::warn!(%detail, "the policy was not taken over");
            }
        }

        tg_proxy::policy::report(&policy, at);
    }
}

fn freshness(
    options: &Arc<Options>,
    policy: SharedPolicy,
    egress: tg_proxy::egress::SharedEgress,
    identity: tg_proxy::identity::SharedIdentity,
    bundle: SharedBundle,
    role: Option<tg_proxy::role::Gate>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut tasks = Vec::new();

    if options.policy.is_some() {
        tasks.push(tokio::spawn(reload_policy(policy, Arc::clone(options))));
    }
    if options.egress.is_some() {
        tasks.push(tokio::spawn(reload_egress(egress, Arc::clone(options))));
    }
    if let Some(gate) = role {
        tasks.push(tokio::spawn(tg_proxy::role::reload(
            gate,
            options.active_role.clone(),
            RELOAD,
        )));
    }
    // **Always.** An SVID expires after fifteen minutes (ADR-0014); a sidecar
    // without a renewer is one with a quarter of an hour of lifetime.
    tasks.push(tokio::spawn(renew_identity(
        identity,
        bundle,
        Arc::clone(options),
    )));

    tasks
}

const RECONNECT: Duration = Duration::from_secs(5);

async fn renew_identity(
    identity: tg_proxy::identity::SharedIdentity,
    bundle: SharedBundle,
    options: Arc<Options>,
) {
    loop {
        match follow_identity(&identity, &bundle, &options).await {
            Ok(()) => tracing::warn!("the identity stream has ended -- it is reconnecting"),
            Err(detail) => tracing::warn!(%detail, "the identity stream was not set up"),
        }

        tokio::time::sleep(RECONNECT).await;
    }
}

async fn follow_identity(
    identity: &tg_proxy::identity::SharedIdentity,
    bundle: &SharedBundle,
    options: &Options,
) -> Result<(), String> {
    use futures_util::StreamExt as _;

    let endpoint = format!("unix://{}", options.socket.display());
    let client = spiffe::WorkloadApiClient::connect_to(&endpoint)
        .await
        .map_err(|err| err.to_string())?;
    let mut stream = client
        .stream_x509_contexts()
        .await
        .map_err(|err| err.to_string())?;

    while let Some(update) = stream.next().await {
        let context = match update {
            Ok(context) => context,
            Err(err) => return Err(err.to_string()),
        };

        match Identity::for_mesh(&material(context.svids().iter().map(AsRef::as_ref))) {
            Ok(fresh) => {
                // At `info!`: a rotation every seven minutes is normal
                // operation (ADR-0014), no incident.
                tracing::info!(id = %fresh.id(), "the SVID is renewed");
                identity.replace(fresh);
            }
            // A stream **without** a delegated SVID is a finding and no
            // reason to throw the previous one away (ADR-0036, ADR-0019).
            Err(err) => tracing::warn!(detail = %err, "no delegated SVID in the stream"),
        }

        // **The anchors come along in the same stream** --
        // `stream_x509_contexts` carries SVIDs and bundles. An empty one is
        // not taken over: it would verify nothing, and the agent can deliver
        // one while it is just coming up (ADR-0019).
        let anchors = anchors_of(&context, &options.trust_domain);
        if !anchors.is_empty() && bundle.replace(Bundle::from_der(anchors)) {
            tracing::info!("the trust anchors are renewed");
        }
    }

    Ok(())
}

fn anchors_of(context: &spiffe::X509Context, domain: &str) -> Vec<Vec<u8>> {
    use spiffe::BundleSource as _;

    let Ok(domain) = spiffe::TrustDomain::new(domain) else {
        return Vec::new();
    };

    context
        .bundle_set()
        .bundle_for_trust_domain(&domain)
        .ok()
        .flatten()
        .map(|bundle| {
            bundle
                .authorities()
                .iter()
                .map(|cert| cert.as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

fn material<'a>(
    svids: impl IntoIterator<Item = &'a spiffe::X509Svid>,
) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    svids
        .into_iter()
        .map(|svid| {
            let chain = svid
                .cert_chain()
                .iter()
                .flat_map(|cert| cert.as_bytes().to_vec())
                .collect();
            (
                svid.hint().unwrap_or_default().to_owned(),
                chain,
                svid.private_key().as_bytes().to_vec(),
            )
        })
        .collect()
}

async fn reload_egress(egress: tg_proxy::egress::SharedEgress, options: Arc<Options>) {
    let (Some(path), Some(addr)) = (options.egress.clone(), options.egress_listen) else {
        return;
    };

    loop {
        tokio::time::sleep(RELOAD).await;
        let at = now();

        match tg_proxy::egress::refresh(&egress, &path, &options.workload, addr.port(), at) {
            tg_proxy::policy::Refresh::Applied => {}
            tg_proxy::policy::Refresh::Unreadable { detail } => {
                tracing::warn!(%detail, path = %path.display(), "the egress file is unreadable");
            }
            tg_proxy::policy::Refresh::Malformed { detail } => {
                tracing::warn!(%detail, path = %path.display(), "the egress file is uninterpretable");
            }
            tg_proxy::policy::Refresh::Rejected { detail } => {
                tracing::warn!(%detail, "the egress permissions were not taken over");
            }
        }

        tg_proxy::egress::report(&egress, at);
    }
}

fn listener(addr: std::net::SocketAddr) -> Result<tokio::net::TcpListener, String> {
    let socket = tg_proxy::reuseport_listener(addr).map_err(|err| err.to_string())?;

    tokio::net::TcpListener::from_std(socket).map_err(|err| err.to_string())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_usage_text_lists_every_flag() {
        // `options.rs` reads the switches, `main.rs` holds the help -- the
        // two sides of the same contract lie in two files, and that **is** the
        // reason they could diverge.
        let source = include_str!("options.rs");
        let source = &source[..source.find("#[cfg(test)]").unwrap_or(source.len())];
        let help = super::usage();

        let mut seen = 0_usize;
        let mut rest = source;
        while let Some(start) = rest.find("\"--") {
            rest = &rest[start + 1..];
            let Some(end) = rest.find('"') else { break };
            let flag = &rest[..end];
            if flag.len() > 2
                && flag[2..]
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-')
            {
                assert!(
                    tg_telemetry::args::mentions_word(&help, flag),
                    "{flag} is missing from the overview"
                );
                seen += 1;
            }
        }

        // Without this assertion the test would be green even if the search
        // found nothing -- and precisely then it checks nothing.
        assert!(seen >= 12, "only {seen} switches found");
    }

    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt as _;

    #[derive(Clone, Default)]
    struct Collected(Arc<Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Collected {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Grab<'a>(&'a mut String);
            impl tracing::field::Visit for Grab<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        *self.0 = format!("{value:?}");
                    }
                }
            }
            let mut message = String::new();
            event.record(&mut Grab(&mut message));
            if let Ok(mut all) = self.0.lock() {
                all.push(message);
            }
        }
    }

    fn said(options: &super::Options, run: &dyn Fn(&super::Options)) -> String {
        let collected = Collected::default();
        let subscriber = tracing_subscriber::registry().with(collected.clone());
        tracing::subscriber::with_default(subscriber, || run(options));
        let all = collected.0.lock().expect("the messages").clone();
        all.join(" | ")
    }

    fn options_from(extra: &[&str]) -> super::Options {
        let mut args: Vec<String> = [
            "--workload",
            "api",
            "--upstream-port",
            "8080",
            "--socket",
            "/tmp/s.sock",
        ]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
        args.extend(extra.iter().map(|word| (*word).to_owned()));
        super::Options::parse(&args).expect("the options")
    }

    #[test]
    fn a_flag_without_its_partner_says_so() {
        let options = options_from(&["--single-writer", "--egress", "/does-not-exist"]);

        let roles = said(&options, &|options| {
            let _ = super::load_roles_or_empty(options);
        });
        assert!(
            roles.contains("--single-writer") && roles.contains("--active-role"),
            "the message must name both switches: {roles}"
        );

        let egress = said(&options, &|options| {
            let _ = super::load_egress_or_empty(options);
        });
        assert!(
            egress.contains("--egress") && egress.contains("--egress-listen"),
            "the message must name both switches: {egress}"
        );
    }

    #[test]
    fn without_the_flag_there_is_nothing_to_warn_about() {
        let options = options_from(&[]);

        let said = said(&options, &|options| {
            let policy = super::load_egress_or_empty(options);
            assert!(policy.is_empty(), "without egress the list stays empty");
        });

        assert!(
            !said.contains("--egress-listen"),
            "without --egress there is nothing to report: {said}"
        );
    }
}
