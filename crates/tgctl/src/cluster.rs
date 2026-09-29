//! `tgctl cluster …` — the way into the **cluster** (ADR-0018, ADR-0048).
//!
//! # Why a group of its own and not a switch on `apply`
//!
//! `tgctl apply` has written the node-local desired state and started
//! containers since phase 2. `tgctl cluster apply` sends the same definition to
//! consensus. Those are **two targets**, and a switch that flips the target of
//! a writing action is the kind of operation that goes wrong at three in the
//! morning. Two verbs leave no doubt which was meant.
//!
//! # It is checked twice, and that is deliberate
//!
//! The same ingest check as in `apply` runs here — schema, cycles, referential
//! integrity (ADR-0009). The cluster checks as well; it must, for it cannot
//! rely on any client. The check here saves not its time but the waiting time:
//! a cycle stands out before half the workloads are already written.

use std::path::{Path, PathBuf};

use tg_admin::{AdminClient, MembershipChange, MembershipResult, WriteResult};
use tg_defs::WorkloadExt as _;
use tg_model::DependencyGraph;
use tg_model::command::{Class, Command};
use tg_model::egress::Transport;

pub(crate) fn read(path: &Path) -> Result<tg_defs::WorkloadSet, String> {
    let xml = std::fs::read_to_string(path)
        .map_err(|err| format!("{} is unreadable: {err}", path.display()))?;
    let set = tg_defs::from_str(&xml).map_err(|err| err.to_string())?;

    // Before the first write, not between: a set with a cycle must not reach
    // the cluster half way in the first place (ADR-0009).
    let graph = DependencyGraph::build(&set).map_err(|err| err.to_string())?;

    // Likewise, and for the same reason (ADR-0084, determination 3): a workload
    // carrying the name of a derived sidecar blocks its derivation. The cluster
    // refuses that — here an operator learns it **before** half their file
    // stands in the log.
    tg_model::mesh::validate_names(set.workloads()).map_err(|err| err.to_string())?;

    for lint in graph.lints() {
        // **On stderr**, because here they are an aside: stdout carries the
        // acceptance. In `lint` the same lines stand on stdout — there they are
        // the result (see there).
        eprintln!("warning: {lint}");
    }

    Ok(set)
}

pub(crate) async fn apply(set: &tg_defs::WorkloadSet, socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let all: Vec<&str> = set
        .workloads()
        .iter()
        .map(tg_defs::WorkloadExt::name)
        .collect();
    for (at, workload) in set.workloads().iter().enumerate() {
        let name = workload.name().to_owned();
        // **What was no longer sent after a failure.** A file with five
        // workloads is a convenience of the operator and not a unit in the log
        // (ADR-0004: one `UpsertWorkload` carries exactly one). If the third
        // aborts, the cluster stopped at two -- and without this information an
        // operator does not know whether the fourth and fifth are in.
        let rest = || pending(&all, at);
        // The **canonical** document from the parsed model, not the submitted
        // text: that way what arrives in the log is what the loader understood
        // and not what somebody wrote (ADR-0008).
        let document =
            tg_defs::workload_to_xml(workload).map_err(|err| format!("'{name}': {err}"))?;

        match client
            .write(Command::UpsertWorkload { document })
            .await
            .map_err(|status| format!("{}: {status}", socket.describe()))?
        {
            WriteResult::Applied { outcome, lints } => {
                crate::refuse_if_rejected(&name, &outcome).map_err(|err| err + &rest())?;
                println!("{name}: taken");
                // **The hints belong to the whole set**, not to this workload
                // (ADR-0009): they can arise from a change to another one. That
                // is why they stand here without a name before them.
                for lint in lints {
                    eprintln!("warning: {lint}");
                }
            }
            WriteResult::ForwardTo { leader } => {
                return Err(match leader {
                    Some(leader) => {
                        format!("this node does not lead — the command belongs on node {leader}")
                    }
                    None => "this node does not lead and knows no leader".to_owned(),
                });
            }
            WriteResult::Failed { detail } => {
                return Err(format!("'{name}': {detail}{}", rest()));
            }
        }
    }

    Ok(())
}

fn pending(all: &[&str], at: usize) -> String {
    let rest = all.get(at + 1..).unwrap_or(&[]);
    if rest.is_empty() {
        return String::new();
    }
    let named: Vec<&str> = rest.iter().take(5).copied().collect();
    let more = rest.len().saturating_sub(named.len());
    let tail = if more == 0 {
        String::new()
    } else {
        format!(" and {more} more")
    };
    format!(
        " — {} of {} was/were no longer sent: {}{tail}",
        rest.len(),
        all.len(),
        named.join(", "),
    )
}

pub(crate) fn socket(data_dir: &Path, id: Option<u64>) -> Result<Access, String> {
    Ok(Access::Socket(crate::node::find_socket(data_dir, id)?))
}

pub(crate) fn access(
    data_dir: &Path,
    id: Option<u64>,
    peer: Option<&str>,
    operator: Option<&str>,
    key: Option<&Path>,
    anchors: Option<&Path>,
    domain: &str,
) -> Result<Access, String> {
    let Some(endpoint) = peer else {
        // **Operator settings without `--peer` are a contradiction**, and
        // without this line a *silent* one: the call falls back to the Unix
        // socket, succeeds -- and `local_uid` stands in the log instead of the
        // name (measured). An operator believes they acted as `dana`, and the
        // audit trail names a uid.
        //
        // That is exactly the question for whose sake ADR-0050 exists: **who
        // stands in the log.** A wrong answer to it stands out to nobody.
        for (flag, given) in [
            ("--operator", operator.is_some()),
            ("--operator-key", key.is_some()),
            ("--anchors", anchors.is_some()),
        ] {
            if given {
                return Err(format!(
                    "{flag} takes effect only with --peer <host:port>. Without it the \
                     command goes over the local admin socket, and the audit trail \
                     carries the uid instead of the operator (ADR-0050)."
                ));
            }
        }

        return socket(data_dir, id);
    };

    let operator = operator.ok_or("--peer needs --operator <name>")?;
    let key = key.ok_or("--peer needs --operator-key <file>")?;
    let anchors = anchors.ok_or(
        "--peer needs --anchors <file> — without anchors anyone who answers on \
         the port would be accepted",
    )?;

    Ok(Access::Peer {
        endpoint: endpoint.to_owned(),
        operator: operator.to_owned(),
        key: key.to_path_buf(),
        anchors: anchors.to_path_buf(),
        domain: domain.to_owned(),
    })
}

#[derive(Debug, Clone)]
pub(crate) enum Access {
    Socket(PathBuf),
    Peer {
        endpoint: String,
        operator: String,
        key: PathBuf,
        anchors: PathBuf,
        domain: String,
    },
}

impl Access {
    pub(crate) fn client(&self) -> Result<AdminClient, String> {
        match self {
            Self::Socket(path) => AdminClient::connect_unix(path),
            Self::Peer {
                endpoint,
                operator,
                key,
                anchors,
                domain,
            } => AdminClient::connect_operator(endpoint, operator, key, anchors, domain),
        }
    }

    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Socket(path) => format!("admin socket {}", path.display()),
            Self::Peer { endpoint, .. } => format!("operator port {endpoint}"),
        }
    }
}

pub(crate) async fn lint(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let answer = client
        .lints()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    // The state belongs with it: without it an operator does not know whether
    // the statement already knows their last write.
    match answer.last_applied {
        Some(index) => println!("node {}, state {index}", answer.id),
        None => println!("node {}, no state yet", answer.id),
    }

    if answer.lints.is_empty() {
        println!("no hints");
        return Ok(());
    }

    for lint in &answer.lints {
        println!("warning: {lint}");
    }
    println!("{} hint(s)", answer.lints.len());

    Ok(())
}

pub(crate) async fn volumes(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let answer = client
        .volumes()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    match answer.last_applied {
        Some(index) => println!("node {}, state {index}", answer.id),
        None => println!("node {}, no state yet", answer.id),
    }

    if answer.tombstones.is_empty() {
        println!("(no tombstone)");
        return Ok(());
    }

    let mut total = 0usize;
    for (node, volumes) in &answer.tombstones {
        total += volumes.len();
        println!("{node}: {}", volumes.join(" "));
    }
    // **The sum stands with it**, because it is the question ADR-0042 leaves
    // open: a tombstone goes away only when the same volume is declared again,
    // and it travels along in every snapshot.
    println!("tombstones: {total}");

    Ok(())
}

pub(crate) async fn trust(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let answer = client
        .trust()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    match answer.last_applied {
        Some(index) => println!("node {}, state {index}", answer.id),
        None => println!("node {}, no state yet", answer.id),
    }

    if answer.nodes.is_empty() {
        println!("(no node admitted)");
    }
    for node in &answer.nodes {
        println!("{}", node.name);
        // The SPKI **in full**: it is the public part of a key and stands that
        // way in the log. Shortened it would no longer be comparable -- and
        // comparing is exactly what an operator does after a rotation.
        println!("  key:        {}", node.spki);
        match node.ordinal {
            Some(ordinal) => println!("  ordinal:    {ordinal}"),
            None => println!("  ordinal:    none (no subnet)"),
        }
        // **"Nothing announced" means no tunnel** (ADR-0039, ADR-0042). Up to
        // here that looked like a network problem.
        match &node.underlay {
            Some((key, endpoint)) => println!("  underlay:   {endpoint} ({key})"),
            None => {
                println!("  underlay:   nothing announced (this node gets no tunnel)");
            }
        }
    }

    if answer.invitations.is_empty() {
        println!("invitations: none open");
    } else {
        let now = crate::now();
        for (node, expires_at) in &answer.invitations {
            // Expiry is **said**: a dead invitation stays lying in the state
            // until somebody tries to redeem it (ADR-0037), and an operator who
            // holds it for valid waits for a join that cannot come.
            let state = if *expires_at < now {
                "expired since"
            } else {
                "valid until"
            };
            // The unit belongs with it: an operator reckons the number against
            // their clock to decide whether the invitation still suffices --
            // and milliseconds against seconds is a factor of a thousand. The
            // twin in `node invite` has always said it.
            println!("invitation: {node} {state} {expires_at} (seconds UTC)");
        }
    }

    Ok(())
}

fn rule_line(rule: &tg_model::capacity::Rule) -> String {
    use std::fmt::Write as _;

    let mut line = format!("percent={}", rule.percent);
    if rule.subtract > 0 {
        let _ = write!(line, " subtract={}", rule.subtract);
    }
    if let Some(cap) = rule.cap {
        let _ = write!(line, " cap={cap}");
    }
    if rule.reserve > 0 {
        let _ = write!(line, " reserve={}", rule.reserve);
    }
    line
}

pub(crate) async fn secrets(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let answer = client
        .secrets()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    match answer.last_applied {
        Some(index) => println!("node {}, state {index}", answer.id),
        None => println!("node {}, no state yet", answer.id),
    }

    // **"None" is said**, not expressed by silence: an empty output is
    // indistinguishable from a tool that did not run.
    if answer.names.is_empty() {
        println!("secrets:  none stored");
    } else {
        let limit = tg_identity::secrets::MAX_SECRET_BYTES;
        for (name, size) in &answer.names {
            // **Who may read it stands beside it** — that is the line which
            // explains a refused deletion: `secret rm` is refused as long as a
            // permission stands, and its message names only **one** workload.
            let readers: Vec<&str> = answer
                .grants
                .iter()
                .filter(|(_, secret)| secret == name)
                .map(|(workload, _)| workload.as_str())
                .collect();
            if readers.is_empty() {
                println!("secret:   {name} ({size} B, nobody may read it)");
            } else {
                println!("secret:   {name} ({size} B) -> {}", readers.join(", "));
            }

            // **A secret above the limit is named**, and here: the client
            // refuses it when storing, but one from a log entry from before
            // this limit still lies there -- and costs its container at the
            // next start (ADR-0098, determination 7), without anyone seeing it
            // beforehand.
            if *size > limit {
                eprintln!(
                    "warning: '{name}' is {size} B, permitted are {limit} -- \
                     a reader's container does not start (ADR-0016)"
                );
            }
        }
    }

    if answer.registries.is_empty() {
        println!("registry: no mapping (pulls are anonymous)");
    } else {
        for (registry, secret) in &answer.registries {
            println!("registry: {registry} -> '{secret}'");
        }
    }

    Ok(())
}

pub(crate) async fn settings(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let answer = client
        .settings()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    match answer.last_applied {
        Some(index) => println!("node {}, state {index}", answer.id),
        None => println!("node {}, no state yet", answer.id),
    }

    // **"Not set" is said**, not expressed by a blank: without an address plan
    // every node reckons with **its** setting (`--cluster-cidr`), and two nodes
    // with different values arrive at different subnets -- without it standing
    // out (ADR-0069).
    match &answer.network {
        Some((cidr, prefix)) => println!("network:  {cidr} per node /{prefix}"),
        None => {
            println!("network:  not set (every node reckons with its own --cluster-cidr)");
        }
    }

    if answer.sidecar_overhead.is_empty() {
        println!("sidecar:  no surcharge (the planner books mesh members without one)");
    } else {
        let amounts = answer
            .sidecar_overhead
            .iter()
            .map(|(name, amount)| format!("{name}={amount}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("sidecar:  {amounts}");
    }

    if answer.capacity.is_empty() {
        println!("capacity policy: none (without a rule no capacity from a report)");
    } else {
        for (resource, rule) in &answer.capacity {
            println!("capacity policy: {resource}: {}", rule_line(rule));
        }
    }

    if answer.rotation.is_empty() {
        println!("rotation: none (nothing rotates by itself)");
    } else {
        for (kind, days) in &answer.rotation {
            println!("rotation: {} every {days} days", kind.as_str());
        }
    }

    Ok(())
}

pub(crate) async fn get(workload: &str, socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let answer = client
        .document(workload)
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    // The state belongs with it, and it goes to **stderr**: on stdout it would
    // stand inside the document.
    match answer.last_applied {
        Some(index) => eprintln!("node {}, state {index}", answer.id),
        None => eprintln!("node {}, no state yet", answer.id),
    }

    // **"Does not exist" is an error, not an empty output.** Whoever redirects
    // would otherwise have an empty file and take it for a result -- the same
    // consideration as at the empty range in `audit export`.
    let Some(document) = answer.document else {
        return Err(format!(
            "the cluster does not know '{workload}' — `tgctl cluster show` names what it knows"
        ));
    };

    print!("{document}");
    Ok(())
}

pub(crate) async fn traffic(
    from: &str,
    to: &str,
    allow: bool,
    socket: &Access,
) -> Result<(), String> {
    let client = socket.client()?;
    let command = if allow {
        Command::AllowTraffic {
            from: from.to_owned(),
            to: to.to_owned(),
        }
    } else {
        Command::RevokeTraffic {
            from: from.to_owned(),
            to: to.to_owned(),
        }
    };

    let what = format!("{from} -> {to}");
    match client.write(command).await {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected(&what, &outcome)?;
            println!("{what}: {}", if allow { "allowed" } else { "withdrawn" });
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("'{what}': {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

async fn warn_if_the_node_is_not_admitted(client: &AdminClient, node: &str) {
    let Ok(answer) = client.trust().await else {
        return;
    };
    if answer.nodes.iter().any(|known| known.name == node) {
        return;
    }

    eprintln!(
        "warning: '{node}' is not admitted. The tombstone will never be carried \
         out there, and it stays in the state until `tgctl node remove {node}` \
         takes it away."
    );
}

pub(crate) async fn delete_volume(
    volume: &str,
    node: &str,
    at: i64,
    socket: &Access,
) -> Result<(), String> {
    let client = socket.client()?;
    let what = format!("{volume}@{node}");

    // **A typo in the node name lays down a tombstone nobody carries out.** A
    // node that is not admitted gets no slice (ADR-0043), so the instruction
    // never reaches it -- and because it disappears only when the named node
    // reports the execution (ADR-0104), it stays in the state and in every
    // snapshot.
    //
    // **Warned and not refused**, and the reason is not caution: the same check
    // in the state machine would be more expensive than a format change.
    // `DeleteVolume` has stood in the log since phase 10b (ADR-0020), and two
    // nodes of different versions would derive different states from the same
    // entry -- one with a tombstone, one without. At `SnapshotVolume` the same
    // check is free (ADR-0099), because the command was new and there are no
    // old entries.
    warn_if_the_node_is_not_admitted(&client, node).await;

    match client
        .write(Command::DeleteVolume {
            volume: volume.to_owned(),
            node: node.to_owned(),
            at,
        })
        .await
    {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected(&what, &outcome)?;
            println!("{what}: deleted");
            eprintln!(
                "hint: the node carries the deletion out as soon as the next \
                 slice reaches it (ADR-0042). It cannot be brought back."
            );
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("'{what}': {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

pub(crate) async fn snapshot_volume(
    volume: &str,
    node: &str,
    generation: u64,
    socket: &Access,
) -> Result<(), String> {
    let client = socket.client()?;
    let what = format!("{volume}@{node}");

    match client
        .write(Command::SnapshotVolume {
            volume: volume.to_owned(),
            node: node.to_owned(),
            generation,
        })
        .await
    {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected(&what, &outcome)?;
            println!("{what}: snapshot generation {generation} decreed");
            eprintln!(
                "hint: the node creates it as soon as the next slice reaches \
                 it. It briefly freezes the file system for that and is \
                 **crash-consistent**, not application-consistent (ADR-0099)."
            );
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("'{what}': {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

pub(crate) async fn network(cidr: &str, node_prefix: u8, socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    // Not `{cidr}/{node_prefix}`: that reads like a CIDR and is none. The
    // reason names the submitted value itself anyway.
    let what = format!("cluster network {cidr} per node /{node_prefix}");

    match client
        .write(Command::SetClusterNetwork {
            cidr: cidr.to_owned(),
            node_prefix,
        })
        .await
    {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected(&what, &outcome)?;
            println!("cluster network: {cidr}, per node /{node_prefix}");
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("'{what}': {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

pub(crate) fn endpoint(raw: &str) -> Result<(String, u16, Transport), String> {
    // The transport stands behind a slash and is **optional**: without it
    // `tcp` applies. That is not guessing from the port (ADR-0092,
    // determination 6) but what a permission meant before ADR-0092 — the same
    // default as at the log entry, and for the same reason.
    let (raw, transport) = match raw.rsplit_once('/') {
        Some((left, word)) => (
            left,
            Transport::parse(word).ok_or_else(|| {
                format!(
                    "'{word}' is no transport — expected is 'tcp', 'quic' or \
                     'udp'. It is not guessed (ADR-0092)"
                )
            })?,
        ),
        None => (raw, Transport::Tcp),
    };

    let (host, port) = raw.rsplit_once(':').ok_or_else(|| {
        format!(
            "'{raw}' names no port — expected is <name>:<port>. The sidecar \
             dials exactly this port (ADR-0041/0051); assuming one would be a \
             decision you did not make"
        )
    })?;
    let port: u16 = port.parse().map_err(|_| format!("'{port}' is no port"))?;
    if host.is_empty() {
        return Err(format!("'{raw}' names no name"));
    }

    Ok((host.to_owned(), port, transport))
}

pub(crate) async fn egress(
    workload: &str,
    host: &str,
    port: u16,
    transport: Transport,
    allow: bool,
    socket: &Access,
) -> Result<(), String> {
    let client = socket.client()?;
    let command = if allow {
        Command::AllowEgress {
            workload: workload.to_owned(),
            host: host.to_owned(),
            port,
            transport,
        }
    } else {
        Command::RevokeEgress {
            workload: workload.to_owned(),
            host: host.to_owned(),
            port,
            transport,
        }
    };

    let what = format!("{workload} -> {host}:{port}/{transport}");
    match client.write(command).await {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected(&what, &outcome)?;
            println!("{what}: {}", if allow { "allowed" } else { "withdrawn" });
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("'{what}': {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

pub(crate) async fn remove(name: &str, socket: &Access) -> Result<(), String> {
    let client = socket.client()?;

    // **Look first, because the withdrawal is idempotent.** An unknown name is
    // done for the state machine, not refused — so a typo looks exactly like a
    // success. The information is expressly a **hint** and not a condition: the
    // projection is eventual and node-local (ADR-0004), so a missing name can
    // also be mere lag. That is why it is sent anyway.
    let known = match client.projection().await {
        Ok(view) => Some(view.workloads.iter().any(|w| w.name == name)),
        Err(_) => None,
    };

    match client
        .write(Command::RemoveWorkload {
            name: name.to_owned(),
        })
        .await
    {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected(name, &outcome)?;
            println!("{name}: withdrawn");

            if known == Some(false) {
                eprintln!(
                    "hint: this node did not know '{name}' — with a typo nothing \
                     happens, and that looks exactly the same"
                );
            }
            // **The hints belong to the whole set** (ADR-0009), not to this
            // workload: a withdrawal can trigger a hint at another one — an
            // edge that now points into the void, say.
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            eprintln!(
                "hint: placement, lease, may_talk edges and egress permissions \
                 went with it. A renewed `cluster apply` brings the definition \
                 back, the permissions not."
            );
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("'{name}': {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

pub(crate) async fn promote(workload: &str, instance: u32, socket: &Access) -> Result<(), String> {
    let client = socket.client()?;

    match client
        .write(Command::SetActiveInstance {
            workload: workload.to_owned(),
            instance,
        })
        .await
    {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected(workload, &outcome)?;
            println!("{workload}: instance {instance} carries the active role");
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            // **What happens now, and when.** The waiting time is not
            // sluggishness but the fence -- without this hint an operator reads
            // it as an error and intervenes.
            eprintln!(
                "hint: if another node still holds the active role, the \
                 promotion takes effect only after its lease expires. That is \
                 the fence (ADR-0064); who holds it is said by \
                 `tgctl cluster show`."
            );
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("'{workload}': {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

pub(crate) async fn restart(
    workload: &str,
    instance: Option<u32>,
    generation: u64,
    socket: &Access,
) -> Result<(), String> {
    let client = socket.client()?;

    match client
        .write(Command::SetWorkloadGeneration {
            workload: workload.to_owned(),
            instance,
            generation,
        })
        .await
    {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected(workload, &outcome)?;
            match instance {
                Some(instance) => {
                    println!("{workload}/{instance}: generation {generation} decreed");
                }
                None => println!("{workload}: generation {generation} decreed, all instances"),
            }
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            // **What happens now, and what does not.** The restart is a stop
            // with a grace period and a start from the current declaration --
            // no health gate behind it (ADR-0071).
            eprintln!(
                "hint: the node ends the instance with a grace period and \
                 starts it again from the current declaration. Whether it comes \
                 up is said by `tgctl cluster show`."
            );
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("'{workload}': {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

pub(crate) async fn sidecar_overhead(
    socket: &Access,
    resources: tg_model::command::Resources,
) -> Result<(), String> {
    let client = socket.client()?;
    let described = if resources.is_empty() {
        "withdrawn".to_owned()
    } else {
        resources
            .entries()
            .iter()
            .map(|(name, amount)| format!("{name}={amount}"))
            .collect::<Vec<_>>()
            .join(" ")
    };

    match client
        .write(Command::SetSidecarOverhead { resources })
        .await
    {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected("sidecar surcharge", &outcome)?;
            println!("sidecar surcharge: {described}");
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("sidecar surcharge: {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

fn amounts(entries: &[(String, u64)]) -> String {
    if entries.is_empty() {
        return "empty (the planner places nothing with resources here)".to_owned();
    }
    entries
        .iter()
        .map(|(name, amount)| format!("{name}={amount}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) async fn nodes(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let view = client
        .projection()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    match view.last_applied {
        Some(index) => println!("node {}, state {index}", view.id),
        None => println!("node {}, no state yet", view.id),
    }

    if view.nodes.is_empty() {
        println!("no nodes in the inventory (AdmitNode enters none, ADR-0037)");
        return Ok(());
    }

    for node in view.nodes {
        println!();
        println!("{}  {}", node.name, node.domain);
        println!(
            "  wanted:     schedulable={} mesh={} generations={}/{}",
            node.schedulable,
            if node.attached { "yes" } else { "no" },
            node.wanted_generations.0,
            node.wanted_generations.1
        );

        // **What the planner reckons with** (ADR-0034) and **what of it is not
        // there for it** (ADR-0047). Without this line a `NoRoom` rejection is
        // not reconstructable, and `tg_scheduler_domain_*` gives sums per
        // domain, not a number per node.
        println!(
            "  capacity:   {}{}",
            amounts(&node.capacity),
            if node.reserved.is_empty() {
                String::new()
            } else {
                format!("  (reserved: {})", amounts(&node.reserved))
            }
        );

        // **What the node itself reports** (ADR-0049). Separate from the
        // wanted one, as everywhere (ADR-0004) -- and the distinction counts
        // especially here: a capacity policy reckons on exactly this number,
        // and whoever writes it without seeing it writes blind.
        match &node.reported_capacity {
            Some(seen) => println!("  measured:   {}", amounts(seen)),
            None => println!("  measured:   nothing (no report)"),
        }

        // **The ordinal** (ADR-0039). Its subnet follows from it, and from that
        // every route, every nftables rule and every `AllowedIP` (phase 9a) --
        // the number an operator needs first at a network problem.
        match node.ordinal {
            Some(ordinal) => println!("  ordinal:    {ordinal}"),
            None => println!("  ordinal:    none (no subnet)"),
        }

        match node.reported_generations {
            Some((identity, underlay)) => {
                let behind = node.wanted_generations.0.saturating_sub(identity)
                    + node.wanted_generations.1.saturating_sub(underlay);
                println!(
                    "  reported:   generations={identity}/{underlay}{}",
                    if behind > 0 {
                        format!(" (behind: {behind})")
                    } else {
                        String::new()
                    }
                );
            }
            // Said, not kept quiet: "nothing heard yet" is something other
            // than "carries generation zero".
            None => println!("  reported:   nothing (no report)"),
        }

        match node.proxy_image {
            Some(image) => println!("  sidecar:    {image}"),
            None => println!("  sidecar:    none (without --proxy-image no mesh)"),
        }

        // **Which zone it serves** (ADR-0013). The metric
        // `tg_cluster_dns_zones` says how many there are; which node deviates
        // stands here.
        match node.dns_zone {
            Some(zone) => println!("  zone:       {zone}"),
            None => println!("  zone:       none (no node network)"),
        }

        // **Whether it maps** (ADR-0091). The same task as the two lines above
        // -- the metric says whether there is a skew, this line where it is.
        // And it says the consequence, because an operator would otherwise read
        // a number and not its meaning.
        match node.userns {
            Some(base) => println!("  userns:     {base} (uid 0 in the container is {base} here)"),
            None => println!("  userns:     none (uid 0 in the container is uid 0 on the node)"),
        }

        match node.last_report {
            Some(at) => println!("  last:       {at} (seconds UTC)"),
            None => println!("  last:       never"),
        }

        // **Which slice it has applied** (ADR-0040). Together with the state in
        // the head that is the number at which a node stands out that gets
        // slices and does not apply them: its report carries on, so `last` says
        // something fresh while this number stands still.
        match node.applied_slice {
            Some(index) => println!("  applied:    slice {index}"),
            None => println!("  applied:    nothing reported"),
        }

        // **What it could not classify** (ADR-0062). Empty is the normal case
        // and is not said — unlike at the settings above, where "nothing
        // reported" is to be distinguished from "none". Here both mean the
        // same: there is nothing to do here.
        if !node.isolated.is_empty() {
            println!("  isolated:   {}", node.isolated.join(", "));
        }
    }

    Ok(())
}

fn print_placement(workload: &tg_admin::ProjectedWorkload) {
    // **Where the planner put the instances** (ADR-0011) -- wanted, not
    // observed. Together with `observed` below it that is the second question
    // in operation: does it run, and where.
    //
    // **With the denominator** (ADR-0034). Without it a partly placed
    // declaration was indistinguishable from a complete one: at `replicas="6"`
    // on five racks five node names stand here, and the line said nothing --
    // `nowhere` appears only when **none at all** is placed. Whoever wanted to
    // count needed a number that stands in the definition.
    let wanted = workload.replicas;
    if workload.placed.is_empty() {
        println!("  placed:     nowhere of {wanted} (the reason stands in the leader's log)");
    } else {
        let where_ = workload
            .placed
            .iter()
            .map(|(instance, node)| format!("{instance}@{node}"))
            .collect::<Vec<_>>()
            .join(" ");
        let have = u32::try_from(workload.placed.len()).unwrap_or(u32::MAX);
        if have < wanted {
            // The missing ones are **named** and not merely counted: which
            // instance number is missing is the setting with which an operator
            // looks into the leader's log.
            let taken: std::collections::BTreeSet<u32> = workload
                .placed
                .iter()
                .map(|(instance, _)| *instance)
                .collect();
            let missing = (0..wanted)
                .filter(|instance| !taken.contains(instance))
                .map(|instance| instance.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "  placed:     {have}/{wanted} {where_} -- without a node: {missing} (the reason stands in the leader's log)"
            );
        } else {
            println!("  placed:     {have}/{wanted} {where_}");
        }
    }
}

pub(crate) async fn show(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let view = client
        .projection()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    // The same head as at `lint`, and for the same reason.
    match view.last_applied {
        Some(index) => println!("node {}, state {index}", view.id),
        None => println!("node {}, no state yet", view.id),
    }

    if view.workloads.is_empty() {
        // Said and not expressed by silence: an empty output is
        // indistinguishable from a tool that did not run (the same reason as at
        // `lint`).
        println!("no workloads in the cluster");
        return Ok(());
    }

    for workload in view.workloads {
        println!();
        println!("{}  {}", workload.name, workload.image);
        // **The class** (ADR-0010). It stands here because it makes the
        // `active role` line below readable: a replicated workload has no
        // active role, a single writer without a lease **does not write**.
        // Without it an operator would have to read the definition for that.
        if !workload.class.is_empty() {
            println!("  class: {}", workload.class);
        }

        if !workload.edges.is_empty() {
            let edges = workload
                .edges
                .iter()
                .map(|(kind, target)| format!("{kind}={target}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  edges: {edges}");
        }

        // **The other half of the authorization** (ADR-0041). `edges` says who
        // may talk to whom in the mesh; the way out was not readable. Both are
        // deny-by-default, and a permission one cannot enumerate one cannot
        // check (ADR-0020).
        if !workload.egress.is_empty() {
            let egress = workload
                .egress
                .iter()
                .map(|(host, port, transport)| format!("{host}:{port}/{transport}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  egress: {egress}");
        }

        print_placement(&workload);

        // **Who holds the active role** (ADR-0064). `tg_workload_active_role`
        // says at a node's endpoint whether **it** holds it; which one it is
        // stood nowhere. For a replicated workload `none` is the normal case --
        // it is nevertheless not said, otherwise the line would stand at every
        // one.
        if let Some((holder, epoch, until)) = &workload.lease {
            println!("  active role: {holder} (epoch {epoch}, until {until} seconds UTC)");
        }

        // **The decreed generation, if there is one** (ADR-0071). It is the
        // number an operator needs in order to name the next one; without it
        // they learned it only from a rejection. And the **effective**
        // generation of an instance is the maximum of both levels — that is why
        // both stand there and not one computed number.
        if !workload.ordered.is_empty() {
            let mut line = format!("  generation: {}", workload.ordered.all);
            if !workload.ordered.instances.is_empty() {
                use std::fmt::Write as _;
                let single = workload
                    .ordered
                    .instances
                    .iter()
                    .map(|(instance, generation)| format!("{instance}={generation}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let _ = write!(line, " (individually: {single})");
            }
            println!("{line}");
        }

        if workload.instances.is_empty() {
            println!("  observed: nothing (no report, not \"nothing runs\")");
        } else {
            let seen = workload
                .instances
                .iter()
                .map(|(number, status)| format!("{number}={status}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  observed: {seen}");
        }

        // **Where the instances are reachable** (ADR-0073). A line of its own
        // and no addition to the state, for the same reason as at `stale` below
        // it: the address is information and not a state.
        //
        // It is shown only when one was reported. An empty line would mean "no
        // address", and that is something other than "nothing reported yet" —
        // the difference `observed` beside it expressly names.
        if !workload.addresses.is_empty() {
            let where_ = workload
                .addresses
                .iter()
                .map(|(number, address)| format!("{number}={address}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  addresses:  {where_}");
        }

        annotations(&workload);
    }

    Ok(())
}

fn annotations(workload: &tg_admin::ProjectedWorkload) {
    // **Stale is a line of its own, not an addition to the state** (ADR-0070,
    // determination 5). The instance runs; it merely runs from an older
    // declaration. Written into `observed` it would be a state, and a tool that
    // reads the column would not understand it.
    if !workload.stale.is_empty() {
        let stale = workload
            .stale
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "  stale: {stale} (run from an older declaration; it takes effect \
             at the next start — `cluster restart`)"
        );
    }

    // **And which do not serve** (ADR-0080). A line of its own, no addition to
    // the state: unready is **information**, and the instance stands in
    // `observed` with `running` — it runs, it merely does not serve
    // (determination 1). A restart is expressly not the automatic answer
    // (determination 7); whoever wants it issues it.
    if !workload.unready.is_empty() {
        let unready = workload
            .unready
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "  unready: {unready} (run, but do not answer their readiness \
             probe — they are not resolved; the reason is named by the node's \
             log)"
        );
    }

    // **And why a reconcile failed** (ADR-0015) — the **class**, not the text.
    // It says *where* to look; the text is named by the node's log, for it
    // carries names out of a payload.
    //
    // That too a line of its own: the instance stands in `observed` with
    // `failed`, and the class is information beside it.
    if !workload.failures.is_empty() {
        let why = workload
            .failures
            .iter()
            .map(|(instance, class)| format!("{instance}={class}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "  failed: {why} (the class says where to look; the text is named \
             by the node's log)"
        );
    }
}

pub(crate) async fn members(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let status = client
        .status()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    match status.leader {
        Some(id) if id == status.id => println!("node {} (leads)", status.id),
        Some(id) => println!("node {} (leader is {id})", status.id),
        None => println!("node {} (no leader)", status.id),
    }

    if status.voters.is_empty() {
        // No silence: an empty output is indistinguishable from a tool that
        // did not run.
        println!("no voters — this node knows no membership");
        return Ok(());
    }

    // **An empty list does not mean "nobody".** The node always puts its own
    // identifier in as well (it reaches itself), so empty is structurally
    // impossible for an answer of this version -- it means "this version does
    // not say" (`serde(default)`). Without the distinction a new `tgctl`
    // against an old `tgd` would report **every** node as silent, and in the
    // alarming direction at that.
    let names: Vec<String> = status
        .voters
        .iter()
        .map(|id| {
            // **Whom the leader reaches stands beside it.** Without that an
            // operator cannot see before a `SetVoters` whether the future
            // majority answers -- and a change to a set whose majority is dead
            // has no way back (see `voters`).
            if status.reachable.is_empty() || status.reachable.contains(id) {
                id.to_string()
            } else {
                format!("{id}(silent)")
            }
        })
        .collect();
    println!("voters: {}", names.join(" "));

    // Only on the leader is the information complete: `metrics.replication` is
    // filled there. On a follower "silent" would be a statement about something
    // it cannot know.
    if status.reachable.is_empty() {
        println!(
            "hint: this control plane does not name reachability -- (silent) \
             then never appears."
        );
    } else if !status.is_leader {
        println!(
            "hint: only the leader knows whom it reaches -- on this node \
             (silent) means only: unknown."
        );
    }

    // **How a new node catches up** (ADR-0005, phase 5d). Both numbers stood in
    // the answer and were read by **nobody** -- and `purged`'s doc block names
    // their two consumers itself: "a node that lacks everything before it can
    // only catch up by snapshot", and "everything up to here can no longer be
    // exported from the log" (ADR-0020). Without them an operator plans a
    // replacement blind.
    match (status.purged, status.snapshot) {
        (None, _) => {
            println!("catch-up: from the log (it is complete, nothing was deleted)");
        }
        (Some(purged), Some(snapshot)) => println!(
            "catch-up: by snapshot (log deleted up to {purged}, snapshot up to \
             {snapshot})"
        ),
        (Some(purged), None) => println!(
            "catch-up: NOT POSSIBLE -- log deleted up to {purged}, and there is \
             no snapshot"
        ),
    }

    // **The promise from ADR-0031 is named, not enforced.** Five nodes carry
    // the loss of two; below that the cluster carries less, and that is a
    // situation an operator can get into deliberately (a replacement passes
    // through four). It belongs said nevertheless.
    if status.voters.len() < 5 {
        println!(
            "hint: {} voters — ADR-0031 determines five (quorum three, loss of \
             two carried).",
            status.voters.len()
        );
    }

    Ok(())
}

pub(crate) async fn learner(id: u64, socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let result = client
        .membership(MembershipChange::AddLearner {
            id,
            // **Blocking**, and that is the point of the step: the call
            // returns when the node has caught up. Without the waiting an
            // operator would have to guess when they may promote — and the
            // answer stands in no metric.
            blocking: true,
        })
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    report_membership(
        &result,
        &format!("node {id} is a learner and has caught up"),
    )
}

async fn warn_if_the_majority_is_silent(client: &AdminClient, ids: &[u64]) {
    let Ok(status) = client.status().await else {
        return;
    };
    if !status.is_leader {
        return;
    }

    // The same distinction as in `members`: empty means "does not say", not
    // "nobody" -- otherwise a new `tgctl` against an old `tgd` would warn at
    // **every** change.
    if status.reachable.is_empty() {
        return;
    }

    let silent: Vec<u64> = ids
        .iter()
        .filter(|id| !status.reachable.contains(id))
        .copied()
        .collect();
    // In integers, so that the boundary lies exactly: at five nodes three are
    // the majority, at four likewise three.
    let quorum = ids.len() / 2 + 1;
    let answering = ids.len() - silent.len();

    if answering < quorum {
        eprintln!(
            "warning: of {} named voters the leader reaches {answering}, the \
             quorum would be {quorum}. Silent: {}. A change to that has no way \
             back: a further one needs quorum, and --init is refused when a log \
             already exists.",
            ids.len(),
            silent
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
}

pub(crate) async fn voters(ids: &[u64], socket: &Access) -> Result<(), String> {
    // **The caller checks the empty set**, before the socket (`main.rs`) —
    // here it would be behind it, and an operator read "unreadable" instead of
    // the form. A second bolt here would stay without effect and would claim
    // the order is immaterial.
    debug_assert!(!ids.is_empty(), "the caller checks the empty set");

    // Named, not enforced: a replacement passes through four, and a cluster
    // with three voters has no reserve at a rolling update (ADR-0031).
    if ids.len() < 5 {
        eprintln!(
            "tgctl: {} voters — ADR-0031 determines five. Below three there is \
             no quorum any more.",
            ids.len()
        );
    }

    let client = socket.client()?;

    // **Look first at whom the leader reaches.** `change_membership` needs
    // quorum, and `initialize` is only for a fresh cluster (`NotAllowed` as
    // soon as a log is there). A change to a set whose majority does not answer
    // is thereby a **dead end**: the admin socket is the recovery path
    // (ADR-0044), but the command itself needs exactly the quorum that is
    // missing afterwards.
    //
    // Warned and **not** refused: a node can be silent this second and there
    // the next, and an operator who is repairing an outage must not hang on a
    // snapshot in time.
    warn_if_the_majority_is_silent(&client, ids).await;

    let result = client
        .membership(MembershipChange::SetVoters {
            ids: ids.to_vec(),
            // **Not kept as a learner.** Whoever takes a node out of the
            // voting set usually wants rid of it; going on supplying it costs
            // bandwidth for a state nobody wanted. Whoever wants to keep it
            // names it in the set.
            retain: false,
        })
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    report_membership(&result, "set")
}

fn report_membership(result: &MembershipResult, done: &str) -> Result<(), String> {
    match result {
        MembershipResult::Changed { voters } => {
            let names: Vec<String> = voters.iter().map(u64::to_string).collect();
            println!("{done}");
            println!("voters now: {}", names.join(" "));
            Ok(())
        }
        // The socket is node-local (ADR-0044), so `tgctl` cannot forward — the
        // information which node leads is what an operator needs.
        MembershipResult::ForwardTo { leader: Some(id) } => {
            Err(format!("this node does not lead; the leader is {id}"))
        }
        MembershipResult::ForwardTo { leader: None } => {
            Err("this node does not lead and knows no leader".to_owned())
        }
        MembershipResult::Failed { detail } => Err(format!("refused: {detail}")),
    }
}

pub(crate) fn ids(args: &[String]) -> Result<Vec<u64>, String> {
    let mut out = Vec::new();
    for arg in args {
        for part in arg.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            out.push(
                part.parse()
                    .map_err(|_| format!("'{part}' is no node identifier"))?,
            );
        }
    }
    Ok(out)
}

pub(crate) async fn put_secret(
    name: &str,
    source: &str,
    data_dir: &Path,
    socket: &Access,
) -> Result<(), String> {
    let key = read_data_key(data_dir)?;

    // **`-` reads from standard input**, so that a value need not pass through
    // a file: `pass show s3 | tgctl cluster secret put s3-key -` puts it down
    // nowhere. An argument on the command line expressly does not exist — it
    // would stand in the process list.
    let plaintext = if source == "-" {
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buffer)
            .map_err(|err| format!("standard input unreadable: {err}"))?;
        buffer
    } else {
        std::fs::read(source).map_err(|err| format!("'{source}' is unreadable: {err}"))?
    };

    // **The limit stands here**, before the sealing (ADR-0016). The reason
    // stands at `MAX_SECRET_BYTES`: `PutSecret` lies in the retained log, so a
    // check in the state machine would be a break of determinism for entries
    // from before -- and in the agent it would be too late, for then the value
    // already stands in the log forever (ADR-0020).
    let limit = tg_identity::secrets::MAX_SECRET_BYTES;
    if plaintext.len() > limit {
        return Err(format!(
            "secret '{name}' is {} bytes, permitted are {limit} -- a secret is \
             a password, a token or a key (ADR-0016), and the tmpfs in the \
             container carries no more",
            plaintext.len()
        ));
    }

    let value = key
        .seal(&plaintext)
        .map_err(|err| format!("not sealable: {err}"))?;

    submit(
        socket,
        Command::PutSecret {
            name: name.to_owned(),
            value,
        },
        &format!("secret '{name}'"),
        "stored",
    )
    .await
}

pub(crate) async fn remove_secret(name: &str, socket: &Access) -> Result<(), String> {
    submit(
        socket,
        Command::RemoveSecret {
            name: name.to_owned(),
        },
        &format!("secret '{name}'"),
        "removed",
    )
    .await
}

pub(crate) async fn enrol_operator(
    operator: &str,
    spki: &str,
    classes: &[Class],
    socket: &Access,
) -> Result<(), String> {
    let named = classes
        .iter()
        .map(|class| class.name())
        .collect::<Vec<_>>()
        .join(", ");
    submit(
        socket,
        Command::EnrolOperator {
            operator: operator.to_owned(),
            spki: spki.to_owned(),
            classes: classes.to_vec(),
        },
        &format!("operator '{operator}'"),
        &format!("registered with the classes: {named} (ADR-0105)"),
    )
    .await
}

pub(crate) async fn operators(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let answer = client
        .operators()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    match answer.last_applied {
        Some(index) => println!("node {}, state {index}", answer.id),
        None => println!("node {}, no state yet", answer.id),
    }

    // **"Nobody" is said**, not expressed by silence: an empty output is
    // indistinguishable from a tool that did not run.
    if answer.operators.is_empty() {
        println!("operators: none registered — only this node's admin socket");
        return Ok(());
    }

    let all = Class::ALL.len();
    for entry in &answer.operators {
        println!("operator: {}", entry.name);
        println!("  classes: {}", entry.classes.join(", "));
        if entry.classes.len() == all {
            println!(
                "           (the full set — at an entry from before ADR-0105 \
                 that is the default; registering anew restricts)"
            );
        }
        println!("  spki:    {}", entry.spki);
    }

    Ok(())
}

pub(crate) async fn revoke_operator(operator: &str, socket: &Access) -> Result<(), String> {
    submit(
        socket,
        Command::RevokeOperator {
            operator: operator.to_owned(),
        },
        &format!("operator '{operator}'"),
        "no longer registered — existing connections stay, for immediately: \
         restart tgd",
    )
    .await
}

pub(crate) async fn grant_secret(
    workload: &str,
    secret: &str,
    allow: bool,
    socket: &Access,
) -> Result<(), String> {
    let command = if allow {
        Command::AllowSecret {
            workload: workload.to_owned(),
            secret: secret.to_owned(),
        }
    } else {
        Command::RevokeSecret {
            workload: workload.to_owned(),
            secret: secret.to_owned(),
        }
    };

    submit(
        socket,
        command,
        &format!("{workload} -> '{secret}'"),
        if allow { "allowed" } else { "withdrawn" },
    )
    .await
}

pub(crate) async fn set_registry(
    registry: &str,
    secret: &str,
    socket: &Access,
) -> Result<(), String> {
    submit(
        socket,
        Command::SetRegistryCredential {
            registry: registry.to_owned(),
            secret: secret.to_owned(),
        },
        &format!("{registry} -> '{secret}'"),
        "mapped",
    )
    .await
}

pub(crate) async fn clear_registry(registry: &str, socket: &Access) -> Result<(), String> {
    submit(
        socket,
        Command::ClearRegistryCredential {
            registry: registry.to_owned(),
        },
        registry,
        "withdrawn",
    )
    .await
}

pub(crate) async fn rekey_secrets(data_dir: &Path, socket: &Access) -> Result<(), String> {
    let ring = read_key_ring(data_dir)?;

    let client = socket.client()?;
    let material = client
        .rekey_material()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    let mut done = 0_usize;
    for (name, sealed) in material.secrets {
        // **What already carries the primary one is skipped.** Sealing it anew
        // would be a log entry without a change -- and the log is retained
        // (ADR-0020).
        if !ring.needs_rekey(&sealed) {
            continue;
        }

        let plaintext = ring
            .open(&sealed)
            .map_err(|err| format!("'{name}' cannot be opened: {err}"))?;
        let value = ring
            .seal(&plaintext)
            .map_err(|err| format!("'{name}' cannot be sealed: {err}"))?;

        // **An abort is resumable here**, unlike at `cluster apply`:
        // `needs_rekey` decides per value, so a second run fetches exactly the
        // rest. That belongs in the message -- otherwise an operator looks for
        // a half state that does not exist.
        submit(
            socket,
            Command::PutSecret {
                name: name.clone(),
                value,
            },
            &name,
            "re-keyed",
        )
        .await
        .map_err(|err| format!("{err} — {done} re-keyed before; a second run fetches the rest"))?;
        done += 1;
    }

    // **The number stands there even when it is zero.** An operator reads from
    // it whether they may take step 5 -- and an empty output would be
    // indistinguishable from a tool that did not run.
    println!("{done} secret(s) re-keyed");
    eprintln!(
        "hint: the old key may go only once tg_cluster_secrets_previous stands \
         at zero -- a value this run did not reach would be unreadable \
         afterwards (ADR-0100)."
    );
    Ok(())
}

fn read_key_ring(data_dir: &Path) -> Result<tg_identity::secrets::KeyRing, String> {
    let primary = read_data_key(data_dir)?;
    let path = tg_identity::layout::dir(data_dir).join(tg_identity::layout::SECRETS_KEY_PREVIOUS);
    let text = std::fs::read_to_string(&path).map_err(|err| {
        format!(
            "no data key to be replaced in {}: {err}\n\
             A re-keying presupposes that the old key lies there and the new \
             one in secrets.key (ADR-0100, determination 3).",
            path.display()
        )
    })?;

    let previous = tg_identity::secrets::DataKey::from_base64(&text)
        .map_err(|err| format!("{}: {err}", path.display()))?;

    Ok(tg_identity::secrets::KeyRing::new(primary, Some(previous)))
}

fn read_data_key(data_dir: &Path) -> Result<tg_identity::secrets::DataKey, String> {
    let path = tg_identity::layout::dir(data_dir).join(tg_identity::layout::SECRETS_KEY);
    let text = std::fs::read_to_string(&path).map_err(|err| {
        format!(
            "no data key in {}: {err}\n\
             It is produced with `tgctl secret keygen` and belongs on every tgd \
             node (ADR-0095).",
            path.display()
        )
    })?;

    tg_identity::secrets::DataKey::from_base64(&text)
        .map_err(|err| format!("{}: {err}", path.display()))
}

async fn submit(socket: &Access, command: Command, what: &str, done: &str) -> Result<(), String> {
    let client = socket.client()?;

    match client.write(command).await {
        Ok(WriteResult::Applied { outcome, lints }) => {
            crate::refuse_if_rejected(what, &outcome)?;
            println!("{what}: {done}");
            for lint in lints {
                eprintln!("warning: {lint}");
            }
            Ok(())
        }
        Ok(WriteResult::ForwardTo { leader }) => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        Ok(WriteResult::Failed { detail }) => Err(format!("'{what}': {detail}")),
        Err(status) => Err(format!("{}: {status}", socket.describe())),
    }
}

pub(crate) async fn signer_refresh(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let answer = client
        .refresh_group()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    // The epoch alone on stdout — so that a script can read it without taking
    // an accompanying line along (the same separation as at the join token).
    println!("{}", answer.epoch);
    eprintln!(
        "signer shares renewed: epoch {} on node {}.\n\
         The group key is the same — certificates and chains keep applying.\n\
         The old epoch is discarded as soon as all five have reported that the \
         new one lies on their disk (ADR-0107) — only with that does the \
         refresh take effect. Whether it is through is said by \
         `tgctl cluster signer`.",
        answer.epoch, answer.id
    );

    Ok(())
}

pub(crate) async fn signer_show(socket: &Access) -> Result<(), String> {
    let client = socket.client()?;
    let answer = client
        .signer()
        .await
        .map_err(|status| format!("{}: {status}", socket.describe()))?;

    println!("node {}", answer.id);
    println!("  ca:          {}", answer.kind);

    let Some(seat) = answer.seat else {
        // **Said and not expressed by a blank:** a node without a seat is the
        // normal case in a cluster without a group, and a refresh belongs on
        // one that holds a seat (ADR-0097).
        println!("  seat:        none — a refresh belongs on a node with a seat");

        return Ok(());
    };

    println!("  seat:        {seat}");
    if let Some((seats, threshold)) = answer.shape {
        println!("  group:       {seats} seats, threshold {threshold}");
    }
    match answer.epochs.as_slice() {
        [] => println!("  epochs:      none"),
        [only] => println!("  epochs:      {only}"),
        many => println!(
            "  epochs:      {} — the old one is not discarded yet (ADR-0107)",
            many.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
    if let Some(print) = &answer.fingerprint {
        println!("  group key:   {print} (fingerprint, not a key)");
    }
    // **Including its own** — the own share is one of the `t` commitments.
    // `--signer` names only the four others, and without this addition an
    // operator reads the two numbers against each other.
    println!(
        "  links:       {} — including its own, entered and not checked reachable",
        answer
            .linked
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  admissions:  {}", answer.admitted);
    if let Some(reason) = &answer.last_failure {
        println!("  last failure while minting: {reason}");
    }

    eprintln!(
        "The fingerprint belongs the same on all seats — a seat with a foreign \
         group starts without complaint and contributes to no signature."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::pending;

    #[test]
    fn what_was_not_sent_is_named() {
        let all = ["a", "b", "c", "d", "e"];

        let said = pending(&all, 2);
        assert!(said.contains("2 of 5"), "{said}");
        assert!(said.contains("d, e"), "{said}");
        assert!(!said.contains("and "), "no addition needed: {said}");

        // The last one leaves nothing behind.
        assert_eq!(pending(&all, 4), "");
        // And a long file names five and counts the rest.
        let many: Vec<&str> = ["w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8"].to_vec();
        let said = pending(&many, 0);
        assert!(said.contains("7 of 8"), "{said}");
        assert!(said.contains("and 2 more"), "{said}");
        assert!(
            !said.contains("w8"),
            "the rest is counted, not named: {said}"
        );
    }
}
