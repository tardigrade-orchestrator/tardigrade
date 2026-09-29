//! Command-line client.
//!
//! ADR-0018. `apply`, `list` and `remove` work **locally and directly** on the
//! node — built that way in phase 2, and that is where they belong: they write
//! the node-local desired state.
//!
//! Two subcommands come along with them, and they are deliberately connected
//! **differently**:
//!
//! - `node invite` speaks the admin socket (ADR-0044). An invitation is a log
//!   command, and only the cluster can append one.
//! - `audit` reads a **file**. That is the promise from ADR-0020: the hash
//!   chain checks itself without the cluster. A checking tool that needed
//!   quorum checks nothing an operator cannot switch off.
//!
//! The mTLS surface from ADR-0018 is still missing — ADR-0044 names the
//! reason: there is no credential for an operator, only for nodes and
//! workloads.

#![forbid(unsafe_code)]
// **No panicking call in the production path** (ADR-0082): since then a panic
// costs its task and not the node -- and that is a state an operator sees only
// at a metric. `not(test)`, because the unit tests in `src` need them; the
// guard lies in `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

mod audit;
mod cluster;
mod node;
mod signer;

const CLUSTER_SUBCOMMANDS: [&str; 27] = [
    "apply",
    "show",
    "get",
    "settings",
    "trust",
    "volumes",
    "nodes",
    "lint",
    "remove",
    "restart",
    "promote",
    "allow",
    "revoke",
    "allow-egress",
    "revoke-egress",
    "delete-volume",
    "snapshot-volume",
    "network",
    "sidecar-overhead",
    "members",
    "learner",
    "voters",
    "secret",
    "registry",
    "secrets",
    "signer-refresh",
    "signer",
];

async fn signer_command(sub: &str, data_dir: &Path, options: &Options) -> Result<(), String> {
    let socket = access(data_dir, options)?;
    if sub == "signer" {
        return cluster::signer_show(&socket).await;
    }
    cluster::signer_refresh(&socket).await
}

async fn secret_command(args: &[String], data_dir: &Path, options: &Options) -> Result<(), String> {
    const USE: &str = "expected: tgctl cluster secret put <name> <file|-> | \
                       rm <name> | allow|revoke <workload> <name> | rekey";

    // **The settings first, then the socket.** A typo shall not depend on
    // whether an admin socket is found.
    match args.get(1).map(String::as_str) {
        Some("put") => {
            let (name, source) = (args.get(2).ok_or(USE)?, args.get(3).ok_or(USE)?);
            let socket = access(data_dir, options)?;
            cluster::put_secret(name, source, data_dir, &socket).await
        }
        Some("rm") => {
            let name = args.get(2).ok_or(USE)?;
            let socket = access(data_dir, options)?;
            cluster::remove_secret(name, &socket).await
        }
        Some("rekey") => {
            let socket = access(data_dir, options)?;
            cluster::rekey_secrets(data_dir, &socket).await
        }
        Some(verb @ ("allow" | "revoke")) => {
            let (workload, name) = (args.get(2).ok_or(USE)?, args.get(3).ok_or(USE)?);
            let socket = access(data_dir, options)?;
            cluster::grant_secret(workload, name, verb == "allow", &socket).await
        }
        _ => Err(USE.to_owned()),
    }
}

async fn registry_command(
    args: &[String],
    data_dir: &Path,
    options: &Options,
) -> Result<(), String> {
    const USE: &str =
        "expected: tgctl cluster registry <host> <secret> | tgctl cluster registry rm <host>";

    // **The settings first, then the socket** — as at `secret`.
    match args.get(1).map(String::as_str) {
        Some("rm") => {
            let host = args.get(2).ok_or(USE)?;
            let socket = access(data_dir, options)?;
            cluster::clear_registry(host, &socket).await
        }
        Some(host) => {
            let secret = args.get(2).ok_or(USE)?;
            let socket = access(data_dir, options)?;
            cluster::set_registry(host, secret, &socket).await
        }
        None => Err(USE.to_owned()),
    }
}

async fn delete_volume_command(
    args: &[String],
    data_dir: &Path,
    options: &Options,
) -> Result<(), String> {
    const FORM: &str = "expected: tgctl cluster delete-volume <volume> <node> --yes";

    let volume = args.get(1).ok_or(FORM)?;
    let node = args.get(2).ok_or(FORM)?;
    // **The confirmation is the action, not a field in the log** (phase 10b).
    // It is demanded here and not sent along.
    if !args.iter().any(|arg| arg == "--yes") {
        return Err(format!(
            "'{volume}@{node}' is not deleted: that is destructive and demands \
             --yes (ADR-0027). It cannot be brought back."
        ));
    }

    let socket = access(data_dir, options)?;
    cluster::delete_volume(volume, node, now(), &socket).await
}

async fn snapshot_volume_command(
    args: &[String],
    data_dir: &Path,
    options: &Options,
) -> Result<(), String> {
    const FORM: &str = "expected: tgctl cluster snapshot-volume <volume> <node> <generation>";

    let volume = args.get(1).ok_or(FORM)?;
    let node = args.get(2).ok_or(FORM)?;
    let generation: u64 = args
        .get(3)
        .ok_or(FORM)?
        .parse()
        .map_err(|_| format!("the generation must be a number. {FORM}"))?;

    let socket = access(data_dir, options)?;
    cluster::snapshot_volume(volume, node, generation, &socket).await
}

async fn restart_command(
    args: &[String],
    data_dir: &Path,
    options: &Options,
) -> Result<(), String> {
    const FORM: &str = "expected: tgctl cluster restart <workload> <generation> [--instance <n>]";

    let workload = args.get(1).ok_or(FORM)?;
    let generation: u64 = args
        .get(2)
        .ok_or(FORM)?
        .parse()
        .map_err(|_| "the generation is no number".to_owned())?;
    let instance = match args.iter().position(|arg| arg == "--instance") {
        Some(at) => Some(
            args.get(at + 1)
                .ok_or("--instance needs a number")?
                .parse()
                .map_err(|_| "the instance is no number".to_owned())?,
        ),
        None => None,
    };

    let socket = access(data_dir, options)?;
    cluster::restart(workload, instance, generation, &socket).await
}

async fn promote_command(
    args: &[String],
    data_dir: &Path,
    options: &Options,
) -> Result<(), String> {
    const FORM: &str = "expected: tgctl cluster promote <workload> <instance>";

    let workload = args.get(1).ok_or(FORM)?;
    let instance: u32 = args
        .get(2)
        .ok_or(FORM)?
        .parse()
        .map_err(|_| "the instance is no number".to_owned())?;

    let socket = access(data_dir, options)?;
    cluster::promote(workload, instance, &socket).await
}

fn refuse_if_rejected(subject: &str, outcome: &tg_model::command::Outcome) -> Result<(), String> {
    match outcome {
        tg_model::command::Outcome::Rejected(reason) => Err(format!("'{subject}': {reason}")),
        tg_model::command::Outcome::Applied
        | tg_model::command::Outcome::LeaseGranted { .. }
        | tg_model::command::Outcome::LeaseRenewed { .. } => Ok(()),
    }
}

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tg_defs::WorkloadExt as _;
use tg_model::DependencyGraph;
use tg_model::command::{Attachment, Class, Schedulability};
use tg_runtime::oci::{DEFAULT_RUNTIMES, OciRuntime};
use tg_runtime::state::DesiredState;
use tg_runtime::{NodePaths, apply};

const USAGE: &str = "\
tgctl — command-line client for Tardigrade

Calls:
  tgctl apply <file.xml>    take a definition and start workloads
  tgctl list                show the node's wanted workloads
  tgctl remove <name>       remove a workload from the wanted state
  tgctl cluster apply <d>   send a definition to the **cluster**
                            (`apply` writes only this node, phase 2)
  tgctl cluster lint        query the hints about the wanted set
  tgctl node detach <n>     take a node out of the data plane (ordinal and
                            trust stay; ADR-0054)
  tgctl node attach <n>     ... and bring it back
  tgctl node rotation --rotate-every <kind>=<days>
                            how often keys are changed; the leader spreads
                            the changes (ADR-0057). Without a setting: off
  tgctl node rotate <n> <kind> <generation>
                            decree a key generation (identity|underlay); the
                            node follows (ADR-0055)
  tgctl cluster show        workloads in the cluster: wanted and observed
  tgctl cluster nodes       nodes in the cluster: wanted and observed
  tgctl cluster remove <n>  withdraw a workload (edges and egress
                            permissions go with it)
  tgctl cluster get <workload>
                            the stored definition, on standard output -- the
                            node line goes to stderr, so a redirect yields the
                            pure XML
  tgctl cluster secrets     which secrets there are and who may read them
                            (ADR-0016). **Without the values** — and the line
                            that explains a refused deletion
  tgctl cluster settings    what holds cluster-wide: address plan, sidecar
                            surcharge, capacity and rotation policy
  tgctl cluster trust       who may be a node, together with the underlay and
                            the open invitations
  tgctl cluster volumes     which volumes are deleted, per node
  tgctl cluster restart <w> <generation> [--instance <n>]
                            make a changed declaration take effect
                            (ADR-0071). Without --instance all instances
                            restart; with it the operator rolls themselves.
  tgctl cluster promote <w> <instance>
                            arm a replica: from now on it carries the active
                            role (ADR-0111). If another node still holds it,
                            it takes effect only after that lease expires —
                            that is the fence, not sluggishness.
  tgctl cluster allow <a> <b>
                            `a` may call `b` (may_talk, ADR-0025).
                            The direction counts; the server decides.
  tgctl cluster revoke <a> <b>
                            withdraw the edge — existing connections end
                            within the revocation window
  tgctl cluster allow-egress <w> <name:port[/transport]>
                            `w` may go out to <name> (ADR-0041).
                            The port is mandatory: the sidecar dials exactly
                            it (ADR-0051). The transport is `tcp` (default)
                            or `quic` (ADR-0092); it is not guessed.
  tgctl cluster revoke-egress <w> <name:port[/transport]>
                            withdraw the permission — the transport belongs
                            to the key
  tgctl cluster sidecar-overhead --resource <name=number>
                            what a sidecar costs; the planner reckons it in
                            per mesh instance (ADR-0067). Without --resource:
                            withdraw
  tgctl cluster network <cidr> <prefix>
                            set the cluster network (one source for all
                            nodes, ADR-0040)
  tgctl cluster delete-volume <v> <node> --yes
                            delete a volume — destructive, demands --yes
                            (ADR-0027); cannot be brought back
  tgctl cluster snapshot-volume <v> <node> <generation>
                            decree a snapshot (ADR-0099). The node briefly
                            freezes the file system; the snapshot is
                            crash-consistent, not application-consistent
  tgctl restore-volume <v> <generation> --yes
                            restore from a snapshot — destructive,
                            **node-local** and in no log (ADR-0099).
                            Demands an unmounted volume; the overwritten
                            state is secured beforehand
  tgctl cluster members     show voters and leader (ADR-0005)
  tgctl cluster learner <id>
                            admit a node as a learner and wait until it has
                            caught up — step 1 of 2 (phase 5d). It must be
                            reachable beforehand: the address in every
                            --peer, the leaf in every peers/<id>.pem
                            (ADR-0043)
  tgctl cluster voters <id>,<id>,…
                            set the voters — step 2 of 2. The **complete**
                            set, not an increment: a delta would be a
                            read-modify-write, and two operators would lose
                            each other silently
  tgctl cluster secret rekey
                            re-key every value onto the primary data key
                            (ADR-0100, step 3 of 5). Presupposes that the old
                            one lies in secrets.key.previous and the new one
                            in secrets.key
  tgctl signer repair <seat> --helper <n>=<url> [--helper ...]
                            restore a lost share (RTS, ADR-0108). Runs on the
                            node of the **affected** seat and puts material
                            down -- `tgd` does not start without a share.
                            Needs **no** admin socket: the signing group is
                            decoupled from consensus (ADR-0014). At least `t`
                            helpers (default 3).
  tgctl cluster signer      show what this node knows about the signing
                            group: seat, shape, epochs, the fingerprint of
                            the group key and the entered links (ADR-0097,
                            ADR-0107)
  tgctl cluster signer-refresh
                            renew the signer shares (proactive refresh,
                            ADR-0107). The group key stays the same, so
                            certificates and chains keep applying; the epoch
                            appears on standard output. The old one is
                            discarded only once all five have reported the new
                            one — whether it is through is said by
                            `tgctl cluster signer`
  tgctl cluster secret put <name> <file|->
                            store a secret — **sealed** (ADR-0016,
                            ADR-0095). `-` reads from standard input; a value
                            on the command line does not exist, it would
                            stand in the process list
  tgctl cluster secret rm <name>
                            remove a secret — refused as long as somebody may
                            still read it
  tgctl cluster secret allow|revoke <workload> <name>
                            who may read it. Deny-by-default: without a
                            permission nobody reads
  tgctl cluster registry <host> <secret>
                            which secret applies for a registry (ADR-0096).
                            Cluster-wide, because it is a statement about the
                            **registry**; who may use it is said by
                            `secret allow`. The plaintext is one line:
                            `basic <user>:<password>` or `bearer <token>`
  tgctl cluster registry rm <host>
                            withdraw the mapping — the pull then runs
                            anonymously and fails at the registry
  tgctl secret keygen       produce the cluster-wide data key (ADR-0095). It
                            belongs on **every** tgd node under
                            <data-dir>/identity/secrets.key and is backup
                            material — if it is lost, all secrets are lost
  tgctl operator keygen     produce an operator's key pair (ADR-0103). The
                            private part stays here; the SPKI line is what
                            `enrol` gets
  tgctl operator enrol <name> <spki> --class <class>[,...]
                            register an operator (ADR-0105). Classes:
                            read, secrets, write, membership, operators —
                            mandatory, with no default: a default would be a
                            decision nobody made
  tgctl operator list       who is registered and what they may do
  tgctl operator revoke <name>
                            withdraw the registration; takes effect on the
                            next request
  tgctl node invite <name>  invite a node (only on the leader, ADR-0037)
  tgctl node upsert <name>  enter or change a node
  tgctl node policy         set the capacity policy (without --rule: withdraw)
  tgctl node revoke-trust <name>
                            declare a node's key invalid (ADR-0054); the
                            ordinal stays
  tgctl node remove <name>  remove a node — only that frees its ordinal
                            (ADR-0039)
  tgctl node cordon <name>  place nothing new there any more
  tgctl node drain <name>   and: what runs there moves away — except what a
                            writable volume nails down (ADR-0027)
  tgctl node uncordon <n>   withdraw both
  tgctl audit [<file>]      recompute the audit chain (without a cluster,
                            ADR-0020); without <file> the whole chain of all
                            segments — including the DST evidence from
                            `xtask dst --report` (a log range as a segment is
                            drawn by `tgd --audit-export`, ADR-0137)
  tgctl help                this overview (also -h, --help)

Options:
  --data-dir <path>         data directory (default: /var/lib/tardigrade)
  --node-id <n>             which node in the data directory
  --ttl <seconds>           deadline of the invitation (default: 900)
  --anchor <hex>            anchor of the chain (default: GENESIS)
  --peer <host:port>        over the operator port instead of over the socket
                            (ADR-0103). Demands --operator, --operator-key
                            and --anchors; without the three it is refused
                            and **not** fallen back to the socket
  --operator <name>         under which name this operator is registered
  --operator-key <file>     their private key (PEM), from
                            `tgctl operator keygen`
  --anchors <file>          the cluster leaves of the tgd nodes, concatenated
                            -- the same file an agent reads as
                            identity/control-plane.pem
  --domain <name>           trust domain of the cluster (default:
                            cluster.local)
  --site/--hall/--rack      failure domain for `node upsert` (all mandatory)
  --resource <name=number>    capacity, repeatable
  --reserve <name=number>     of it set aside (ADR-0047), repeatable
  --rule <name:k=v,...>     rule of the policy, repeatable. Keys:
                            subtract, percent (mandatory), cap, reserve

The token from `node invite` appears on standard output and nowhere else —
`tgctl node invite api > join-token` is thereby the file the agent redeems.
";

// `tgctl` writes with `eprintln!` and not with `tracing`, and that is a
// decision: it sets up no subscriber (it is node-local and has no
// `--telemetry-addr`, ADR-0018), and `tracing` discards an event without a
// subscriber **silently**. Switched over, this tool's output would be gone —
// and it is not observation but the answer to the caller.

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (data_dir, mut rest) = split_data_dir(&args);
    let options = match Options::take(&mut rest) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("tgctl: {message}");
            return ExitCode::FAILURE;
        }
    };

    let command = rest.first().map_or("help", String::as_str);
    if asks_for_usage(command) {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("tgctl: the tokio runtime is not startable: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(dispatch(command, &rest[1..], &data_dir, &options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("tgctl: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn cluster_read(
    sub: &str,
    args: &[String],
    data_dir: &Path,
    options: &Options,
) -> Option<Result<(), String>> {
    // The socket is sought **after** the argument check: a typo shall not
    // depend on whether a data directory is readable.
    if sub == "get" {
        // `args` still carries the subcommand at position 0, hence `get(1)` for
        // the first real argument.
        let Some(name) = args.get(1) else {
            return Some(Err("expected: tgctl cluster get <workload>".to_owned()));
        };
        let name = name.clone();
        return Some(match access(data_dir, options) {
            Ok(socket) => cluster::get(&name, &socket).await,
            Err(why) => Err(why),
        });
    }

    // **Classify first, then seek the socket.** The other way round an unknown
    // subcommand would be reported as "no admin socket" — the wrong information
    // at the place at which an operator made a typo.
    //
    // `settings`: what applies cluster-wide (ADR-0049/0057/0067/0069).
    // `nodes`: the same for the nodes (ADR-0054, ADR-0055, ADR-0059).
    if !matches!(
        sub,
        "lint" | "show" | "settings" | "trust" | "volumes" | "nodes" | "secrets"
    ) {
        return None;
    }

    let socket = match access(data_dir, options) {
        Ok(socket) => socket,
        Err(why) => return Some(Err(why)),
    };

    Some(match sub {
        "lint" => cluster::lint(&socket).await,
        "show" => cluster::show(&socket).await,
        "settings" => cluster::settings(&socket).await,
        "secrets" => cluster::secrets(&socket).await,
        // **Who may be a node** (ADR-0037, ADR-0043).
        "trust" => cluster::trust(&socket).await,
        // **What is deleted and where it still lies** (ADR-0042).
        "volumes" => cluster::volumes(&socket).await,
        "nodes" => cluster::nodes(&socket).await,
        _ => return None,
    })
}

async fn cluster_command(
    args: &[String],
    data_dir: &Path,
    options: &Options,
) -> Result<(), String> {
    let sub = args.first().map(String::as_str).ok_or(&format!(
        "cluster needs a subcommand: {}",
        CLUSTER_SUBCOMMANDS.join(", ")
    ))?;
    // **The read paths first.** They need no file — they ask the state
    // (ADR-0048, determination 2) —, and `get` **produces** one.
    if let Some(done) = cluster_read(sub, args, data_dir, options).await {
        return done;
    }
    // **Allow and withdraw** (ADR-0025, ADR-0041). They stand up here because
    // they need no file — they carry their settings in the arguments.
    if let Some(allow) = match sub {
        "allow" => Some(true),
        "revoke" => Some(false),
        _ => None,
    } {
        let from = args
            .get(1)
            .ok_or("expected: tgctl cluster allow|revoke <from> <to>")?;
        let to = args
            .get(2)
            .ok_or("expected: tgctl cluster allow|revoke <from> <to>")?;
        let socket = access(data_dir, options)?;
        return cluster::traffic(from, to, allow, &socket).await;
    }
    if let Some(allow) = match sub {
        "allow-egress" => Some(true),
        "revoke-egress" => Some(false),
        _ => None,
    } {
        let workload = args.get(1).ok_or(
            "expected: tgctl cluster allow-egress|revoke-egress <workload> \
                 <name:port[/transport]>",
        )?;
        let endpoint = args.get(2).ok_or(
            "expected: tgctl cluster allow-egress|revoke-egress <workload> \
                 <name:port[/transport]>",
        )?;
        // **The setting first, then the socket.** A typo shall not depend on
        // whether an admin socket is found.
        let (host, port, transport) = cluster::endpoint(endpoint)?;
        let socket = access(data_dir, options)?;
        return cluster::egress(workload, &host, port, transport, allow, &socket).await;
    }
    if sub == "secret" {
        return secret_command(args, data_dir, options).await;
    }
    if sub == "registry" {
        return registry_command(args, data_dir, options).await;
    }
    // **The membership** (ADR-0005, phase 5d). A function of its own, because
    // `cluster_command` would otherwise grow past the line limit — that is a
    // sign, not an annoyance.
    if matches!(sub, "members" | "learner" | "voters") {
        return membership_command(sub, args, data_dir, options).await;
    }
    if sub == "delete-volume" {
        return delete_volume_command(args, data_dir, options).await;
    }
    if sub == "snapshot-volume" {
        return snapshot_volume_command(args, data_dir, options).await;
    }
    // **The signing group** — both verbs together, because it is one
    // statement: renew (ADR-0107) and look up. They go to a node that holds a
    // **seat**, not to the leader: the group is decoupled from the Raft
    // membership (ADR-0014, determination 1).
    if matches!(sub, "signer" | "signer-refresh") {
        return signer_command(sub, data_dir, options).await;
    }
    if sub == "network" {
        let cidr = args
            .get(1)
            .ok_or("expected: tgctl cluster network <cidr> <prefix>")?;
        let prefix: u8 = args
            .get(2)
            .ok_or("expected: tgctl cluster network <cidr> <prefix>")?
            .parse()
            .map_err(|_| "the node prefix is no number".to_owned())?;

        // **The form of the CIDR too, before the access.** Up to here an
        // operator with `cluster network broken 24` read "unreadable" while
        // their line was the problem. It is checked with the **same** function
        // the state machine uses (ADR-0069) — a check of its own would be a
        // second source for the same question, and the cluster checks it once
        // more anyway (it must).
        tg_model::network::Plan::parse(cidr, prefix).map_err(|err| err.to_string())?;

        let socket = access(data_dir, options)?;
        return cluster::network(cidr, prefix, &socket).await;
    }
    // **What a sidecar costs** (ADR-0067). The same number cluster-wide;
    // without `--resource` the surcharge is withdrawn.
    if sub == "sidecar-overhead" {
        // **The settings first, then the access**: a `--resource broken`
        // (without `=`) otherwise read "unreadable" instead of the form.
        // Without `--resource` the empty map is the withdrawal and not an
        // error.
        let resources = crate::node::resources(&options.resources)?;
        let socket = access(data_dir, options)?;
        return cluster::sidecar_overhead(&socket, resources).await;
    }
    // **Decree a restart** (ADR-0071). A function of its own, because
    // `cluster_command` would otherwise grow past the line limit — that is a
    // sign, not an annoyance.
    if sub == "promote" {
        return promote_command(args, data_dir, options).await;
    }
    if sub == "restart" {
        return restart_command(args, data_dir, options).await;
    }
    if sub == "remove" {
        let name = args
            .get(1)
            .ok_or("remove needs a name: tgctl cluster remove <name>")?;
        let socket = access(data_dir, options)?;
        return cluster::remove(name, &socket).await;
    }
    if sub != "apply" {
        return Err(format!("unknown cluster subcommand '{sub}'\n\n{USAGE}"));
    }
    let file = args
        .get(1)
        .ok_or("apply needs a file: tgctl cluster apply <file.xml>")?;
    // **The file first** (ADR-0084, determination 3): the setting a human typed
    // is checked before the environment is asked. The other way round an
    // operator reads "no socket" while their document is the problem — the same
    // ordering error as once at `node invite`.
    let set = cluster::read(Path::new(file))?;
    let socket = access(data_dir, options)?;
    cluster::apply(&set, &socket).await
}

async fn membership_command(
    sub: &str,
    args: &[String],
    data_dir: &Path,
    options: &Options,
) -> Result<(), String> {
    if sub == "members" {
        let socket = access(data_dir, options)?;
        return cluster::members(&socket).await;
    }

    // **The setting first, then the socket** — a typo shall not depend on
    // whether an admin socket is found.
    let ids = cluster::ids(&args[1..])?;

    // **The empty set first**, beside the check of `learner`: it lay in
    // `cluster::voters` and thereby **behind** the socket, and an operator who
    // forgets the identifiers read "unreadable" instead of the form. The same
    // asymmetry as once at `node upsert` and at `--peer` — the setting a human
    // typed comes before the environment.
    if sub == "voters" && ids.is_empty() {
        return Err("expected: tgctl cluster voters <id>,<id>,… — the complete \
                    set, not an increment"
            .to_owned());
    }

    if sub == "learner" {
        let [id] = ids.as_slice() else {
            return Err("expected: tgctl cluster learner <id> — exactly one identifier".to_owned());
        };
        let socket = access(data_dir, options)?;
        return cluster::learner(*id, &socket).await;
    }

    let socket = access(data_dir, options)?;
    cluster::voters(&ids, &socket).await
}

fn access(data_dir: &Path, options: &Options) -> Result<cluster::Access, String> {
    cluster::access(
        data_dir,
        options.node_id,
        options.peer.as_deref(),
        options.operator.as_deref(),
        options.operator_key.as_deref(),
        options.anchors.as_deref(),
        &options.domain,
    )
}

async fn operator(args: &[String], data_dir: &Path, options: &Options) -> Result<(), String> {
    const USE: &str = "expected: tgctl operator keygen | list \
                       | enrol <name> <spki> --class <class>[,...] | revoke <name>";

    // **The settings first, then the socket** — the ordering error from
    // `node invite`: a typo in the name shall not appear as "no socket".
    match args.first().map(String::as_str) {
        Some("keygen") => operator_keygen(),
        Some("enrol") => {
            let (name, spki) = (args.get(1).ok_or(USE)?, args.get(2).ok_or(USE)?);
            let classes = classes_from(&args[3..])?;

            // **The form of the SPKI, before the access.** Up to here an
            // operator with a broken setting read "unreadable" while their
            // line was the problem. It is checked with the **same** function as
            // in the state machine (ADR-0103): a registration the verifier
            // cannot decode would be an entry that **never** carries a
            // handshake — and the error showed up only at the first
            // connection.
            tg_identity::cluster::NodeTrust::from_base64([(name.as_str(), spki.as_str())])
                .map_err(|err| err.to_string())?;

            let socket = access(data_dir, options)?;
            cluster::enrol_operator(name, spki, &classes, &socket).await
        }
        Some("list") => {
            let socket = access(data_dir, options)?;
            cluster::operators(&socket).await
        }
        Some("revoke") => {
            let name = args.get(1).ok_or(USE)?;
            let socket = access(data_dir, options)?;
            cluster::revoke_operator(name, &socket).await
        }
        _ => Err(USE.to_owned()),
    }
}

fn classes_from(args: &[String]) -> Result<Vec<Class>, String> {
    const USE: &str = "expected: --class <class>[,<class>...] with";

    let mut names = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg != "--class" {
            return Err(format!("unknown setting '{arg}'; {USE} {}", known()));
        }
        let value = rest
            .next()
            .ok_or_else(|| format!("--class needs a value; {USE} {}", known()))?;
        names.extend(value.split(',').map(str::trim).filter(|s| !s.is_empty()));
    }

    if names.is_empty() {
        return Err(format!(
            "--class is missing. A registration without a class would be a \
             registration that may do nothing (ADR-0105); {USE} {}",
            known()
        ));
    }

    let mut classes = Vec::new();
    for name in names {
        let class = Class::from_name(name)
            .ok_or_else(|| format!("unknown class '{name}'; {USE} {}", known()))?;
        classes.push(class);
    }
    classes.sort_unstable();
    classes.dedup();
    Ok(classes)
}

fn known() -> String {
    Class::ALL
        .iter()
        .map(|class| class.name())
        .collect::<Vec<_>>()
        .join(", ")
}

fn operator_keygen() -> Result<(), String> {
    // **Produced in `tg-identity`**, not here: what a credential of this system
    // looks like is known by that crate (the same layer as `node_leaf`) -- and
    // otherwise `rcgen` and `base64` would be two more crates in a delivery
    // binary (ADR-0023).
    let (key, spki) = tg_identity::cluster::operator_keys()?;

    eprintln!(
        "The private part belongs in a file with 0600 and never leaves this \
         machine. The SPKI line is what `tgctl operator enrol` gets — it is no \
         secret (ADR-0103)."
    );
    print!("{key}");
    println!("spki: {spki}");

    Ok(())
}

fn secret(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(),
        Some(other) => Err(format!(
            "unknown subcommand 'secret {other}' — known is: keygen"
        )),
        None => Err("secret needs a subcommand: keygen".to_owned()),
    }
}

fn keygen() -> Result<(), String> {
    let key =
        tg_identity::secrets::DataKey::generate().map_err(|err| format!("no data key: {err}"))?;

    // The hint on **stderr**, the key on stdout.
    eprintln!(
        "This key belongs on **every** tgd node under \
         <data-dir>/identity/secrets.key (0600) and is backup material: if it \
         is lost, all secrets are lost (ADR-0095)."
    );
    println!("{}", key.to_base64());

    Ok(())
}

async fn dispatch(
    command: &str,
    args: &[String],
    data_dir: &PathBuf,
    options: &Options,
) -> Result<(), String> {
    match command {
        "apply" => {
            let file = args
                .first()
                .ok_or("apply needs a file: tgctl apply <file.xml>")?;
            apply_file(PathBuf::from(file), data_dir).await
        }
        "list" => list(data_dir),
        "remove" => {
            let name = args
                .first()
                .ok_or("remove needs a name: tgctl remove <name>")?;
            remove(name, data_dir)
        }
        "secret" => secret(args),
        "operator" => operator(args, data_dir, options).await,
        "restore-volume" => restore_volume(args, data_dir),
        "node" => node(args, data_dir, options).await,
        "signer" => signer::command(
            args,
            data_dir,
            &options.domain,
            &tokio::runtime::Handle::current(),
        ),
        "cluster" => cluster_command(args, data_dir, options).await,
        "audit" => match args.first() {
            // An explicitly named file is checked **individually**: it can be
            // a segment somebody put into the archive, and then the anchor is a
            // setting. Without a setting the **chain** in the data directory is
            // checked — there `tgctl` knows which segments belong together.
            Some(file) => audit::verify(&PathBuf::from(file), &options.anchor),
            None => audit::verify_chain(
                &audit::find_archive(data_dir, options.node_id)?,
                &options.anchor,
            ),
        },
        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
}

fn restore_volume(args: &[String], data_dir: &Path) -> Result<(), String> {
    const FORM: &str = "expected: tgctl restore-volume <volume> <generation> --yes";

    let volume = args.first().ok_or(FORM)?;
    let generation: u64 = args
        .get(1)
        .ok_or(FORM)?
        .parse()
        .map_err(|_| format!("the generation must be a number. {FORM}"))?;

    // **The confirmation is the action** (phase 10b, ADR-0027). It stands here
    // and is sent along nowhere — there is no field one could copy.
    if !args.iter().any(|arg| arg == "--yes") {
        return Err(format!(
            "'{volume}' is not restored: that overwrites the data and demands \
             --yes (ADR-0027)"
        ));
    }

    let store = tg_runtime::volume::VolumeStore::open(data_dir)
        .map_err(|err| format!("volume store cannot be opened: {err}"))?;
    let confirmation = tg_runtime::volume::Confirmation::of(volume);
    let replaced = store
        .restore(volume, generation, &confirmation)
        .map_err(|err| format!("'{volume}': {err}"))?;

    println!("{volume}: restored from generation {generation}");
    // **The trace this operation leaves.** It stands in no log, so the
    // before-snapshot is the only record — and the only reversibility. It
    // therefore belongs named and not kept quiet.
    eprintln!(
        "hint: the overwritten state lies as generation {} ({} bytes). This \
         operation stands in **no** log (ADR-0099).",
        replaced.generation, replaced.bytes
    );
    Ok(())
}

async fn apply_file(path: PathBuf, data_dir: &PathBuf) -> Result<(), String> {
    let xml = std::fs::read_to_string(&path)
        .map_err(|err| format!("{} is unreadable: {err}", path.display()))?;
    let set = tg_defs::from_str(&xml).map_err(|err| err.to_string())?;

    // ADR-0009: referential integrity and freedom from cycles are properties of
    // the set, not of the individual workload - the XSD cannot check them, here
    // is their place.
    let graph = DependencyGraph::build(&set).map_err(|err| err.to_string())?;
    for lint in graph.lints() {
        eprintln!("warning: {lint}");
    }

    let paths = NodePaths::new(data_dir);
    // ADR-0115: `tgctl apply` is the **second** process that creates a data
    // directory (phase 2, the node-local way). Without this line the protection
    // would hang on who was there first.
    paths.seal();

    // **Is this node steered by the cluster?** Then a local `apply` is an
    // action the next slice turns back: it removes what it does not name
    // (ADR-0040, determination 6), and the clearer ends the container
    // afterwards (ADR-0058). The operator would see "taken" and seconds later a
    // workload that is gone.
    //
    // **Warned, not refused.** Whoever has lost the cluster and must run
    // something locally shall be able to — the mark stays lying then too. The
    // same choice as at `cluster remove` on an unknown name: say it and do it
    // anyway.
    if paths.slice_applied().exists() {
        eprintln!(
            "warning: this node is steered by the cluster (an applied slice \
             lies there). The next slice removes what does not come from it, \
             and the container is cleared away afterwards (ADR-0040/0058). For \
             the cluster way: tgctl cluster apply <file>"
        );
    }

    let desired = DesiredState::open(paths.data_dir()).map_err(|err| err.to_string())?;
    let runtime = OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root())
        .map_err(|err| err.to_string())?;

    for workload in set.workloads() {
        desired
            .put(workload)
            .map_err(|err| format!("desired state for '{}': {err}", workload.name()))?;
    }

    // The start order comes from the ordering subgraph, not from the document
    // order (ADR-0009).
    for name in graph.start_order() {
        let workload = set
            .workloads()
            .iter()
            .find(|w| w.name() == name)
            .ok_or_else(|| {
                format!("workload '{name}' from the graph is missing from the definition")
            })?;

        // Instance 0: `tgctl apply` is the node-local way from phase 2, and
        // without a planner nobody assigned this node a second instance
        // (ADR-0034).
        //
        // **Without a network connection** (ADR-0012): the node network belongs
        // to the agent, which holds it as long as it runs — bridge, address
        // ledger and resolver. A `tgctl` call that built it on the side would
        // be a second source for the same addresses, and the two would hand out
        // the same one twice. The container thereby runs in an empty network
        // namespace; whoever wants a network lets the agent reconcile.
        // **And without a sidecar** (ADR-0059): derivation happens from a
        // node's slice, and here an operator writes the cache themselves — what
        // they do not write down does not exist.
        let context = tg_runtime::reconcile::Context {
            volume_keys: None,
            no_seccomp: false,
            // **And without devices** (ADR-0143): the assignment is an
            // inventory of the **agent** and must survive its restart. Keeping
            // a second one here would mean giving two instances the same device
            // -- exactly what ADR-0028 excludes with its ban on time slicing.
            devices: None,
            // **And without a user namespace** (ADR-0091): the mapping is a
            // setting of the **agent** -- it moves the ownership in the layer
            // store and in the volumes. Inventing it here would mean writing a
            // store the agent reads differently.
            userns: None,
            // `tgctl apply` drives **one** pass; there is no loop anybody
            // could wake.
            wake: None,
            // ADR-0064: the local clock for the active-role lease.
            now: &|| 0,
            fence_margin: 0,
            keep_snapshots: 3,
            quorum: tg_model::Quorum::Available,
            network: None,
            mesh: None,
            empty: &|| tg_runtime::reconcile::EmptyMeans::NothingHeard,
            // **No workload API socket** (ADR-0079): the agent runs it, and
            // `tgctl apply` is the node-local way **without** it (phase 2). A
            // path here would point at a socket nobody listens on.
            workload_api: None,
            secrets: None,
            // And **no registry credential** (ADR-0096), for the same reason:
            // it comes from the slice, and that does not exist on the
            // node-local way. Pulls are anonymous.
            credentials: None,
        };
        // Instance 0 and generation **zero**: the node-local way knows no
        // decree from the log (ADR-0071). Whoever reconciles here writes the
        // desired state themselves — and whoever wants a restart ends the
        // container.
        let target = apply::Target {
            workload,
            instance: 0,
            principal: None,
            generation: 0,
            // `tgctl apply` derives no sidecar (ADR-0059): here an operator
            // writes the cache themselves, and what they do not write down does
            // not exist.
            has_sidecar: false,
        };
        let outcome = apply::reconcile_one(&paths, &runtime, &target, &context)
            .await
            .map_err(|err| format!("workload '{name}': {err}"))?;
        println!("{name}: {outcome}");
    }

    Ok(())
}

fn list(data_dir: &PathBuf) -> Result<(), String> {
    let paths = NodePaths::new(data_dir);
    let desired = DesiredState::open(paths.data_dir()).map_err(|err| err.to_string())?;
    let workloads = desired.load_all().map_err(|err| err.to_string())?;

    if workloads.is_empty() {
        println!("(no wanted workload on this node)");
        return Ok(());
    }

    for workload in &workloads {
        println!("{}", workload.name());
    }

    Ok(())
}

fn remove(name: &str, data_dir: &PathBuf) -> Result<(), String> {
    let paths = NodePaths::new(data_dir);
    let desired = DesiredState::open(paths.data_dir()).map_err(|err| err.to_string())?;
    desired.remove(name).map_err(|err| err.to_string())?;
    println!("{name}: removed from the wanted state");
    Ok(())
}

#[derive(Debug, Clone)]
struct Options {
    node_id: Option<u64>,
    ttl: i64,
    anchor: String,
    site: String,
    hall: String,
    rack: String,
    resources: Vec<String>,
    reserves: Vec<String>,
    rules: Vec<String>,
    rotations: Vec<String>,
    peer: Option<String>,
    operator: Option<String>,
    operator_key: Option<PathBuf>,
    anchors: Option<PathBuf>,
    domain: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            node_id: None,
            ttl: node::DEFAULT_TTL,
            anchor: audit::default_anchor().to_owned(),
            peer: None,
            operator: None,
            operator_key: None,
            anchors: None,
            // The same default as in `tgd` and in the agent: one setting per
            // process, and whoever changes it changes it everywhere.
            domain: tg_identity::DEFAULT_TRUST_DOMAIN.to_owned(),
            site: String::new(),
            hall: String::new(),
            rack: String::new(),
            resources: Vec::new(),
            reserves: Vec::new(),
            rules: Vec::new(),
            rotations: Vec::new(),
        }
    }
}

fn asks_for_usage(command: &str) -> bool {
    matches!(command, "help" | "-h" | "--help")
}

impl Options {
    fn take(rest: &mut Vec<String>) -> Result<Self, String> {
        let mut options = Self::default();

        if let Some(value) = take_value(rest, "--node-id") {
            options.node_id = Some(
                value
                    .parse()
                    .map_err(|_| format!("--node-id needs a number, not '{value}'"))?,
            );
        }
        if let Some(value) = take_value(rest, "--ttl") {
            let ttl: i64 = value
                .parse()
                .map_err(|_| format!("--ttl needs seconds, not '{value}'"))?;
            if ttl <= 0 {
                return Err(format!(
                    "--ttl {ttl} would be an invitation that never applies"
                ));
            }
            options.ttl = ttl;
        }
        if let Some(value) = take_value(rest, "--anchor") {
            options.anchor = value;
        }
        options.peer = take_value(rest, "--peer");
        options.operator = take_value(rest, "--operator");
        options.operator_key = take_value(rest, "--operator-key").map(PathBuf::from);
        options.anchors = take_value(rest, "--anchors").map(PathBuf::from);
        if let Some(value) = take_value(rest, "--domain") {
            options.domain = value;
        }
        for (flag, slot) in [
            ("--site", &mut options.site),
            ("--hall", &mut options.hall),
            ("--rack", &mut options.rack),
        ] {
            if let Some(value) = take_value(rest, flag) {
                *slot = value;
            }
        }
        options.resources = take_all(rest, "--resource");
        options.reserves = take_all(rest, "--reserve");
        options.rules = take_all(rest, "--rule");
        options.rotations = take_all(rest, "--rotate-every");

        Ok(options)
    }
}

fn topology(options: &Options) -> Result<tg_model::command::Topology, String> {
    for (flag, value) in [
        ("--site", &options.site),
        ("--hall", &options.hall),
        ("--rack", &options.rack),
    ] {
        if value.is_empty() {
            return Err(format!("upsert needs {flag}"));
        }
    }

    Ok(tg_model::command::Topology {
        site: options.site.clone(),
        hall: options.hall.clone(),
        rack: options.rack.clone(),
    })
}

fn take_all(args: &mut Vec<String>, name: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut kept = Vec::with_capacity(args.len());
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        if arg == name {
            if let Some(next) = iter.next() {
                values.push(next.clone());
            }
        } else {
            kept.push(arg.clone());
        }
    }

    *args = kept;
    values
}

fn take_value(args: &mut Vec<String>, name: &str) -> Option<String> {
    let mut value = None;
    let mut kept = Vec::with_capacity(args.len());
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        if arg == name {
            if let Some(next) = iter.next() {
                value = Some(next.clone());
            }
        } else {
            kept.push(arg.clone());
        }
    }

    *args = kept;
    value
}

fn split_data_dir(args: &[String]) -> (PathBuf, Vec<String>) {
    let mut data_dir = PathBuf::from(tg_runtime::DEFAULT_DATA_DIR);
    let mut rest = Vec::new();
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        if arg == "--data-dir" {
            if let Some(value) = iter.next() {
                data_dir = PathBuf::from(value);
            }
        } else {
            rest.push(arg.clone());
        }
    }

    (data_dir, rest)
}

async fn node(args: &[String], data_dir: &Path, options: &Options) -> Result<(), String> {
    let sub = args
        .first()
        .map(String::as_str)
        .ok_or("node needs a subcommand: tgctl node invite <name>")?;
    // `policy` and `rotation` are the subcommands **without a name**: they apply
    // cluster-wide (ADR-0049, ADR-0057). That is why they stand **before** the
    // name check.
    // **The settings first, then the socket** — at both: a `--rule broken` or
    // `--rotate-every broken` otherwise read "unreadable" instead of the form.
    // Without a setting the empty policy is in each case the **withdrawal**
    // (ADR-0049, ADR-0057) and not an error.
    if sub == "policy" {
        let policy = node::policy_of(&options.rules)?;
        let socket = node::find_socket(data_dir, options.node_id)?;
        return node::policy(policy, &socket).await;
    }
    if sub == "rotation" {
        let policy = node::rotation_of(&options.rotations)?;
        let socket = node::find_socket(data_dir, options.node_id)?;
        return node::rotation(policy, &socket).await;
    }

    let name = args
        .get(1)
        .ok_or_else(|| format!("{sub} needs a name: tgctl node {sub} <name>"))?;

    // The socket is sought **after** the argument check: a typo in the line
    // shall not appear as "no socket".
    let mode = match sub {
        "invite" => {
            let socket = node::find_socket(data_dir, options.node_id)?;
            return node::invite(name, options.ttl, &socket).await;
        }
        "upsert" => {
            // **The settings first, then the socket.** Without `--site` or
            // with a `--resource broken` this call measurably reported "no
            // admin socket -- is tgd running on this node?", and an operator
            // looked at the service instead of at their line. The same order as
            // at `node invite` and `cluster allow`.
            let topology = topology(options)?;
            let capacity = node::resources(&options.resources)?;
            let reserved = node::resources(&options.reserves)?;
            let socket = node::find_socket(data_dir, options.node_id)?;
            return node::upsert(name, topology, capacity, reserved, &socket).await;
        }
        // Detach and attach lie on an **axis of their own** (ADR-0054) and
        // therefore return early here instead of flowing into placeability.
        "revoke-trust" => {
            let socket = node::find_socket(data_dir, options.node_id)?;
            return node::revoke_trust(name, &socket).await;
        }
        "remove" => {
            let socket = node::find_socket(data_dir, options.node_id)?;
            return node::remove(name, &socket).await;
        }
        "detach" | "attach" => {
            let mode = if sub == "detach" {
                Attachment::Detached
            } else {
                Attachment::Attached
            };
            let socket = node::find_socket(data_dir, options.node_id)?;
            return node::set_attachment(name, mode, &socket).await;
        }
        // `rotate` needs two further settings and therefore returns here.
        "rotate" => {
            let kind = args
                .get(2)
                .ok_or(
                    "rotate needs the kind: \
                     tgctl node rotate <name> identity|underlay <generation>",
                )?
                .parse()?;
            let generation: u64 = args
                .get(3)
                .ok_or("rotate needs the generation: tgctl node rotate <name> <kind> <generation>")?
                .parse()
                .map_err(|_| "the generation is a number".to_owned())?;
            let socket = node::find_socket(data_dir, options.node_id)?;
            return node::rotate(name, kind, generation, &socket).await;
        }
        "cordon" => Schedulability::Cordoned,
        "drain" => Schedulability::Draining,
        "uncordon" => Schedulability::Schedulable,
        other => {
            return Err(format!("unknown node subcommand '{other}'\n\n{USAGE}"));
        }
    };
    let socket = node::find_socket(data_dir, options.node_id)?;
    node::set_schedulability(name, mode, &socket).await
}

#[cfg(test)]
mod tests {
    use super::{
        CLUSTER_SUBCOMMANDS, Options, USAGE, access, dispatch, refuse_if_rejected, split_data_dir,
        take_value,
    };
    use std::path::{Path, PathBuf};

    fn split(args: &[&str]) -> (PathBuf, Vec<String>) {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        split_data_dir(&args)
    }

    #[test]
    fn without_the_flag_the_default_applies_and_nothing_is_reordered() {
        let (dir, rest) = split(&["apply", "workload.xml"]);

        assert_eq!(dir, Path::new(tg_runtime::DEFAULT_DATA_DIR));
        assert_eq!(rest, ["apply", "workload.xml"]);
    }

    #[test]
    fn the_flag_and_its_value_are_cut_out() {
        for args in [
            ["--data-dir", "/srv/tg", "list", "extra"],
            ["list", "--data-dir", "/srv/tg", "extra"],
            ["list", "extra", "--data-dir", "/srv/tg"],
        ] {
            let (dir, rest) = split(&args);
            assert_eq!(dir, Path::new("/srv/tg"), "{args:?}");
            assert_eq!(rest, ["list", "extra"], "{args:?}");
        }
    }

    #[test]
    fn the_last_occurrence_wins() {
        let (dir, rest) = split(&["--data-dir", "/a", "--data-dir", "/b", "list"]);

        assert_eq!(dir, Path::new("/b"));
        assert_eq!(rest, ["list"]);
    }

    #[test]
    fn a_dangling_flag_falls_back_to_the_default() {
        let (dir, rest) = split(&["list", "--data-dir"]);

        assert_eq!(dir, Path::new(tg_runtime::DEFAULT_DATA_DIR));
        assert_eq!(rest, ["list"]);
    }

    #[test]
    fn a_command_shaped_value_is_taken_as_a_value() {
        let (dir, rest) = split(&["--data-dir", "list", "remove", "api"]);

        assert_eq!(dir, Path::new("list"));
        assert_eq!(rest, ["remove", "api"]);
    }

    #[test]
    fn odd_paths_arrive_unchanged() {
        for path in [
            "/srv/tg data",
            "/srv/tg;rm -rf /",
            "../../etc",
            "/srv/$(whoami)",
            "/srv/tg\n",
        ] {
            let (dir, rest) = split(&["--data-dir", path, "list"]);
            assert_eq!(dir, Path::new(path));
            assert_eq!(rest, ["list"]);
        }
    }

    #[test]
    fn an_empty_line_yields_an_empty_rest() {
        let (dir, rest) = split(&[]);

        assert_eq!(dir, Path::new(tg_runtime::DEFAULT_DATA_DIR));
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn an_unknown_command_is_named_and_rejected() {
        let dir = PathBuf::from("/does/not/exist");
        let err = dispatch("aplly", &[], &dir, &Options::default())
            .await
            .expect_err("unknown command");

        assert!(err.contains("aplly"), "{err}");
        assert!(err.contains(USAGE), "{err}");
    }

    #[tokio::test]
    async fn apply_and_remove_need_their_argument() {
        let dir = PathBuf::from("/does/not/exist");

        let err = dispatch("apply", &[], &dir, &Options::default())
            .await
            .expect_err("without a file");
        assert!(err.contains("tgctl apply <file.xml>"), "{err}");

        let err = dispatch("remove", &[], &dir, &Options::default())
            .await
            .expect_err("without a name");
        assert!(err.contains("tgctl remove <name>"), "{err}");
    }

    #[tokio::test]
    async fn a_missing_file_is_reported_with_its_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist.xml");

        let err = dispatch(
            "apply",
            &[missing.display().to_string()],
            &dir.path().to_path_buf(),
            &Options::default(),
        )
        .await
        .expect_err("the file is missing");

        assert!(err.contains(&missing.display().to_string()), "{err}");
        assert!(err.contains("is unreadable"), "{err}");
    }

    #[tokio::test]
    async fn a_cyclic_definition_never_reaches_the_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("cycle.xml");
        std::fs::write(
            &file,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="a" kind="service">
    <image reference="example.com/a:1"/>
    <dependencies>
      <after ref="b"/>
    </dependencies>
  </workload>
  <workload name="b" kind="service">
    <image reference="example.com/b:1"/>
    <dependencies>
      <after ref="a"/>
    </dependencies>
  </workload>
</workloads>"#,
        )
        .expect("write");

        let data_dir = dir.path().join("data");
        let err = dispatch(
            "apply",
            &[file.display().to_string()],
            &data_dir,
            &Options::default(),
        )
        .await
        .expect_err("cycle");

        assert!(err.to_lowercase().contains("cycle"), "{err}");
        assert!(!data_dir.exists(), "the cycle reached the desired state");
    }

    #[tokio::test]
    async fn a_malformed_definition_never_reaches_the_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("broken.xml");
        std::fs::write(&file, "<workloads><not-closed>").expect("write");

        let data_dir = dir.path().join("data");
        assert!(
            dispatch(
                "apply",
                &[file.display().to_string()],
                &data_dir,
                &Options::default(),
            )
            .await
            .is_err()
        );
        assert!(!data_dir.exists());
    }

    #[test]
    fn without_flags_the_defaults_apply() {
        let mut rest = vec!["audit".to_owned()];
        let options = Options::take(&mut rest).expect("defaults");

        assert_eq!(options.node_id, None);
        assert_eq!(options.ttl, 900);
        assert_eq!(options.anchor, super::audit::default_anchor());
        assert_eq!(rest, ["audit"]);
    }

    #[test]
    fn a_flag_may_stand_anywhere() {
        for args in [
            vec!["--node-id", "3", "audit", "file"],
            vec!["audit", "--node-id", "3", "file"],
            vec!["audit", "file", "--node-id", "3"],
        ] {
            let mut rest: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
            let options = Options::take(&mut rest).expect("number");

            assert_eq!(options.node_id, Some(3), "{args:?}");
            assert_eq!(rest, ["audit", "file"], "{args:?}");
        }
    }

    #[test]
    fn an_unusable_value_is_an_error_and_names_itself() {
        for (flag, value) in [
            ("--ttl", "15m"),
            ("--ttl", ""),
            ("--ttl", "9999999999999999999999"),
            ("--node-id", "one"),
            ("--node-id", "-1"),
            ("--node-id", "1.0"),
        ] {
            let mut rest = vec![flag.to_owned(), value.to_owned(), "audit".to_owned()];
            let err = Options::take(&mut rest).expect_err("{flag} {value}");

            assert!(err.contains(flag), "{flag} {value}: {err}");
            assert!(err.contains(value), "{flag} {value}: {err}");
        }
    }

    #[test]
    fn a_ttl_that_never_holds_is_refused() {
        for ttl in ["0", "-1", "-9223372036854775808"] {
            let mut rest = vec!["--ttl".to_owned(), ttl.to_owned()];
            assert!(Options::take(&mut rest).is_err(), "{ttl}");
        }
    }

    #[test]
    fn the_boundaries_of_the_ttl_are_accepted() {
        for ttl in ["1", "9223372036854775807"] {
            let mut rest = vec!["--ttl".to_owned(), ttl.to_owned()];
            let options = Options::take(&mut rest).expect(ttl);
            assert_eq!(options.ttl.to_string(), ttl);
        }
    }

    #[test]
    fn take_value_follows_the_same_rules_as_data_dir() {
        let mut args: Vec<String> = ["--ttl", "60", "--ttl", "120", "list"]
            .iter()
            .map(|a| (*a).to_owned())
            .collect();
        assert_eq!(take_value(&mut args, "--ttl").as_deref(), Some("120"));
        assert_eq!(args, ["list"]);

        let mut args: Vec<String> = ["list", "--ttl"].iter().map(|a| (*a).to_owned()).collect();
        assert_eq!(take_value(&mut args, "--ttl"), None);
        assert_eq!(args, ["list"]);

        let mut args: Vec<String> = ["list"].iter().map(|a| (*a).to_owned()).collect();
        assert_eq!(take_value(&mut args, "--ttl"), None);
        assert_eq!(args, ["list"]);
    }

    #[test]
    fn every_flag_of_the_common_options_is_read() {
        let mut rest = vec![
            "node".to_owned(),
            "--domain".to_owned(),
            "acme.internal".to_owned(),
            "--rule".to_owned(),
            "cpu-millicores:percent=80".to_owned(),
            "--rule".to_owned(),
            "memory-bytes:percent=90".to_owned(),
            "--rotate-every".to_owned(),
            "identity=90".to_owned(),
            "--rotate-every".to_owned(),
            "underlay=30".to_owned(),
        ];
        let options = Options::take(&mut rest).expect("readable");

        assert_eq!(options.domain, "acme.internal");
        assert_eq!(
            options.rules,
            ["cpu-millicores:percent=80", "memory-bytes:percent=90"]
        );
        assert_eq!(options.rotations, ["identity=90", "underlay=30"]);
        assert_eq!(rest, ["node"], "the command stays standing");

        // The counter-direction: **none** of these values is the default.
        let mut rest = vec!["node".to_owned()];
        let plain = Options::take(&mut rest).expect("defaults");
        assert_eq!(plain.domain, tg_identity::DEFAULT_TRUST_DOMAIN);
        assert!(plain.rules.is_empty(), "without a rule no capacity");
        assert!(plain.rotations.is_empty(), "without a setting no rotation");
    }

    #[test]
    fn every_parsed_flag_has_a_witness() {
        let source = include_str!("main.rs");
        let cut = source
            .find("#[cfg(test)]")
            .expect("the source has a test module");
        let (production, own) = source.split_at(cut);

        // **The haystack is both.** `tgctl` has unit tests in the binary
        // **and** integration tests beside it; a switch that occurs only there
        // (`--site`, `--yes`, …) would otherwise be a false finding — and
        // exactly that sort has already once in this session produced an
        // all-clear that was not right.
        let mut tests = String::from(own);
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let mut files = 0_usize;
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "rs") {
                    let text = std::fs::read_to_string(&path).expect("readable");
                    tests.push_str(&text);
                    files += 1;
                }
            }
        }
        assert!(
            files >= 5,
            "only {files} integration tests were read — the path is wrong"
        );

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

        // Without this assurance the test would be green even if the search
        // found nothing — and then it checks nothing.
        assert!(
            flags.len() > 15,
            "only {} switches were found — the cut is wrong",
            flags.len()
        );

        let missing: Vec<&str> = flags
            .into_iter()
            .filter(|flag| !tests.contains(flag))
            .collect();
        assert!(
            missing.is_empty(),
            "these switches are parsed and named by no test: {missing:?}"
        );
    }

    #[tokio::test]
    async fn the_instance_is_read_before_the_socket_is_looked_for() {
        let dir = PathBuf::from("/does/not/exist");
        let options = Options::default();

        let err = dispatch(
            "cluster",
            &[
                "restart".to_owned(),
                "api".to_owned(),
                "7".to_owned(),
                "--instance".to_owned(),
                "two".to_owned(),
            ],
            &dir,
            &options,
        )
        .await
        .expect_err("no number");
        assert!(err.contains("instance"), "{err}");

        let err = dispatch(
            "cluster",
            &[
                "restart".to_owned(),
                "api".to_owned(),
                "7".to_owned(),
                "--instance".to_owned(),
            ],
            &dir,
            &options,
        )
        .await
        .expect_err("without a value");
        assert!(err.contains("--instance"), "{err}");
    }

    #[test]
    fn the_usage_is_a_command_not_a_flag() {
        for spelling in ["help", "-h", "--help"] {
            assert!(super::asks_for_usage(spelling), "'{spelling}' asks for it");
        }
        assert!(
            !super::asks_for_usage("cluster"),
            "a command is no question"
        );
        assert!(!super::asks_for_usage(""), "and an empty name neither");
    }

    #[test]
    fn the_anchor_is_taken_as_given() {
        let mut rest = vec!["--anchor".to_owned(), "no hex".to_owned()];
        let options = Options::take(&mut rest).expect("setting");

        assert_eq!(options.anchor, "no hex");
    }

    #[tokio::test]
    async fn node_needs_its_subcommand_and_its_name() {
        let dir = PathBuf::from("/does/not/exist");
        let options = Options::default();

        let err = dispatch("node", &[], &dir, &options)
            .await
            .expect_err("without a subcommand");
        assert!(err.contains("tgctl node invite <name>"), "{err}");

        let err = dispatch("node", &["invite".to_owned()], &dir, &options)
            .await
            .expect_err("without a name");
        assert!(err.contains("tgctl node invite <name>"), "{err}");

        let err = dispatch("node", &["delete".to_owned()], &dir, &options)
            .await
            .expect_err("wrong subcommand");
        assert!(err.contains("delete"), "{err}");
    }

    #[test]
    fn the_usage_text_lists_every_flag() {
        // `tgctl`'s switches lie scattered: the verb groups have files of
        // their own. The guard reads them all — forgetting a file would be the
        // same error as a hand-maintained list.
        let sources = [
            include_str!("main.rs"),
            include_str!("cluster.rs"),
            include_str!("node.rs"),
            include_str!("audit.rs"),
        ];

        let mut seen = 0_usize;
        for source in sources {
            let source = &source[..source.find("#[cfg(test)]").unwrap_or(source.len())];
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
                        tg_telemetry::args::mentions_word(USAGE, flag),
                        "{flag} is missing from the overview"
                    );
                    seen += 1;
                }
            }
        }

        // Without this assurance the test would be green even if the search
        // found nothing.
        assert!(seen >= 13, "only {seen} switches found");
    }

    #[test]
    fn a_peer_without_its_credentials_is_refused_not_downgraded() {
        let mut options = Options {
            peer: Some("10.0.0.1:7005".to_owned()),
            ..Options::default()
        };
        let nowhere = Path::new("/does-not-exist");

        let err = access(nowhere, &options).expect_err("must refuse");
        assert!(err.contains("--operator"), "{err}");

        options.operator = Some("dana".to_owned());
        let err = access(nowhere, &options).expect_err("must refuse");
        assert!(err.contains("--operator-key"), "{err}");

        options.operator_key = Some(PathBuf::from("/key.pem"));
        let err = access(nowhere, &options).expect_err("must refuse");
        assert!(err.contains("--anchors"), "{err}");

        // And with all three: an access over the network, **without** a socket
        // being sought. The counter-check to everything above — without it a
        // function that always refuses would be just as green.
        options.anchors = Some(PathBuf::from("/anchors.pem"));
        let access = access(nowhere, &options).expect("access");
        assert!(
            access.describe().contains("10.0.0.1:7005"),
            "{}",
            access.describe()
        );
    }

    #[test]
    fn without_a_peer_it_stays_on_the_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("admin-1.sock"), []).expect("socket");

        let access = access(dir.path(), &Options::default()).expect("access");
        assert!(
            access.describe().contains("admin-1.sock"),
            "{}",
            access.describe()
        );
    }

    #[test]
    fn the_usage_text_names_every_class() {
        for class in tg_model::command::Class::ALL {
            assert!(
                USAGE.contains(class.name()),
                "the class '{}' stands in no usage help -- an operator must \
                 type it and does not find it",
                class.name()
            );
        }
    }

    #[test]
    fn the_usage_text_lists_every_subcommand() {
        // **Read from the dispatch, not from a list.** Here stood a
        // hand-maintained one -- the shape this tree has measured four times as
        // a source of error (`KINDS`, `samples()`, `invariants.rs`, the ADR
        // table) --, and measured it named **five of ten** verbs. Whoever adds
        // one and forgets the overview now gets a red test instead of a command
        // nobody finds. The same construction as the guard for `cluster`
        // beside it.
        let source = include_str!("main.rs");
        let start = source
            .find("async fn dispatch(")
            .expect("the dispatch of the verbs");
        let end = source[start..].find("unknown command").expect("its end") + start;
        let dispatch = &source[start..end];

        let mut found: Vec<&str> = Vec::new();
        for line in dispatch.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix('"')
                && let Some((name, tail)) = rest.split_once('"')
                && (tail.trim_start().starts_with("=>") || tail.trim_start().starts_with("if"))
            {
                found.push(name);
            }
        }

        assert!(found.len() >= 8, "the dispatch was not read: {found:?}");
        for command in &found {
            // **As a verb, not as a substring.** Measured, this guard was green
            // for `signer`, because `tgctl cluster signer` stands in the
            // overview -- a mention an operator searching for `tgctl signer`
            // does not find. The same blindness as at the manual guard, which
            // counted `--node` as known because `--node-listen` exists. The
            // counter-check shows it: with the old comparison **and** without
            // the line it stays green.
            let named = USAGE.lines().any(|line| {
                line.trim_start()
                    .strip_prefix("tgctl ")
                    .and_then(|rest| rest.strip_prefix(*command))
                    .is_some_and(|tail| tail.is_empty() || tail.starts_with(' '))
            });
            assert!(named, "the verb '{command}' is missing from the overview");
        }

        // And the switches that exist nowhere else.
        for flag in ["help", "--data-dir", "--node-id", "--ttl", "--anchor"] {
            assert!(
                tg_telemetry::args::mentions_word(USAGE, flag),
                "{flag} is missing from the overview"
            );
        }
    }

    #[test]
    fn a_rejection_becomes_an_error_that_says_why() {
        let outcome =
            tg_model::command::Outcome::Rejected(tg_model::command::Rejection::UnknownNode {
                name: "node-7".to_owned(),
            });

        let err = refuse_if_rejected("node-7", &outcome).expect_err("must refuse");

        assert!(err.contains("node-7"), "{err}");
        assert!(err.contains("does not exist"), "{err}");
        // And **no** Rust syntax: the debug form carries field names and curly
        // braces, an operator reads a sentence here.
        assert!(!err.contains("UnknownNode"), "{err}");
        assert!(!err.contains('{'), "{err}");
    }

    #[test]
    fn every_other_outcome_is_not_a_refusal() {
        let epoch = tg_model::command::Epoch::default();

        for outcome in [
            tg_model::command::Outcome::Applied,
            tg_model::command::Outcome::LeaseGranted { epoch },
            tg_model::command::Outcome::LeaseRenewed { epoch },
        ] {
            assert!(
                refuse_if_rejected("whatever", &outcome).is_ok(),
                "{outcome:?} was treated as a refusal"
            );
        }
    }

    #[test]
    fn the_cluster_message_names_every_subcommand() {
        let source = include_str!("main.rs");
        // **The dispatch is in two parts**, since the read paths lie in
        // `cluster_read` (otherwise `cluster_command` would lie past the line
        // limit). The guard reported the rebuild — that is exactly what it is
        // for —, and the cut therefore begins at the first of the two functions
        // instead of at the error message between them.
        let start = source
            .find("async fn cluster_read(")
            .expect("the read paths of `cluster`");
        let end = source[start..]
            .find("unknown cluster subcommand")
            .expect("its end")
            + start;
        let dispatch = &source[start..end];

        let mut found: Vec<String> = Vec::new();
        for (index, _) in dispatch.match_indices("sub == \"") {
            let rest = &dispatch[index + 8..];
            let name = &rest[..rest.find('"').expect("closing quotation mark")];
            found.push(name.to_owned());
        }
        for line in dispatch.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix('"')
                && let Some((name, tail)) = rest.split_once('"')
                && tail.trim_start().starts_with("=>")
            {
                found.push(name.to_owned());
            }
        }
        // **And the third form of the dispatch**: `matches!(sub, "a" | "b")`.
        // It came along with the membership commands, and without this branch
        // the guard reported them as missing — it did so, and that is the
        // point: it reads the source and not a second list.
        for (index, _) in dispatch.match_indices("matches!(sub,") {
            let rest = &dispatch[index..];
            let arm = &rest[..rest.find(')').expect("closing bracket")];
            // Every **second** piece is a name; between them stands ` | `.
            for name in arm.split('"').skip(1).step_by(2) {
                if !name.is_empty() && !found.iter().any(|seen| seen == name) {
                    found.push(name.to_owned());
                }
            }
        }

        // Without this assurance the test would check nothing as soon as the
        // dispatch looks different: an empty found set is contained in every
        // list.
        assert!(found.len() >= 10, "the dispatch was not read: {found:?}");

        for name in &found {
            assert!(
                CLUSTER_SUBCOMMANDS.contains(&name.as_str()),
                "'{name}' is dispatched but does not stand in the message"
            );
        }
        for named in CLUSTER_SUBCOMMANDS {
            // **`apply` is the fall-through branch**, and therefore not to be
            // found: the dispatch writes `if sub != "apply" { return Err(...) }`
            // and handles it afterwards. So there is no line at which a reader
            // of the source could see it — the exception is a statement about
            // the form of the dispatch and not leniency.
            assert!(
                found.iter().any(|found| found == named) || named == "apply",
                "'{named}' stands in the message but is not dispatched"
            );
        }
    }
    #[test]
    fn every_write_checks_the_outcome() {
        let sources = [
            ("cluster.rs", include_str!("cluster.rs")),
            ("node.rs", include_str!("node.rs")),
        ];

        let mut writes = 0_usize;
        for (name, source) in sources {
            let body = source
                .split_once("#[cfg(test)]")
                .map_or(source, |(head, _)| head);
            let lines: Vec<&str> = body.lines().collect();
            for (number, line) in lines.iter().enumerate() {
                if !line.contains(".write(") || line.contains("fn ") {
                    continue;
                }
                writes += 1;
                let window = lines[number..lines.len().min(number + 30)].join("\n");
                assert!(
                    window.contains("refuse_if_rejected"),
                    "{name}:{} issues a command and does not check the verdict: {}",
                    number + 1,
                    line.trim()
                );
            }
        }

        // Without this assurance a run that finds no write — a renamed
        // `write`, a moved file — would be just as green and would confirm
        // everything.
        assert!(
            writes >= 16,
            "only {writes} writes found — the search no longer takes hold"
        );
    }
}
