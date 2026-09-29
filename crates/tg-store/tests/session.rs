//! A node's slice (ADR-0040).
//!
//! Written before the implementation. What is checked is the **selection** —
//! what a node gets to see and what not. It is a pure function, and that is
//! deliberate: the computation is the only place at which least privilege
//! happens at all in the path control plane → node. One that can only be checked
//! in the end-to-end setup is one whose omissions nobody has ever seen.
//!
//! The load-bearing statement from ADR-0040, determination 5: **a compromised
//! node shall not be the cluster's blueprint.**

use std::collections::BTreeMap;
use tg_model::egress::Transport;

use tg_store::session::{
    ClusterNetwork, ClusterView, Lease, RemoteEndpoint, UnderlayPeer, slice_for,
};

fn documents() -> BTreeMap<String, String> {
    ["api", "ledger", "fremd"]
        .into_iter()
        .map(|name| (name.to_owned(), format!("<workload name=\"{name}\"/>")))
        .collect()
}

fn ordinals() -> BTreeMap<String, u32> {
    [("node-a".to_owned(), 0), ("node-b".to_owned(), 1)]
        .into_iter()
        .collect()
}

fn peers() -> Vec<UnderlayPeer> {
    vec![
        UnderlayPeer {
            node: "node-a".to_owned(),
            ordinal: 0,
            key: "iOnLpv2AL2r0YKGCXpXKaVUsBpVYAyLpJvGVc0nlDXo=".to_owned(),
            endpoint: "203.0.113.10:51820".to_owned(),
        },
        UnderlayPeer {
            node: "node-b".to_owned(),
            ordinal: 1,
            key: "2GAX7Nc1YvRHNzMWFqSNXHVDp0oXBSPfKrHWaBaZ2n8=".to_owned(),
            endpoint: "203.0.113.11:51820".to_owned(),
        },
    ]
}

/// `api` and `ledger` lie on `node-a`, `fremd` on `node-b`.
fn placements() -> Vec<(String, u32, String)> {
    vec![
        ("api".to_owned(), 0, "node-a".to_owned()),
        ("ledger".to_owned(), 0, "node-a".to_owned()),
        ("fremd".to_owned(), 0, "node-b".to_owned()),
    ]
}

fn edges() -> Vec<(String, String)> {
    vec![
        ("api".to_owned(), "ledger".to_owned()),
        ("fremd".to_owned(), "ledger".to_owned()),
        ("fremd".to_owned(), "irgendwas".to_owned()),
    ]
}

fn view(index: u64) -> ClusterView {
    ClusterView {
        snapshot_generations: std::collections::BTreeMap::new(),
        secrets: Vec::new(),
        registry_credentials: Vec::new(),
        sidecar_overhead: Vec::new(),
        active_instances: std::collections::BTreeMap::new(),
        index,
        placements: placements(),
        documents: documents(),
        edges: edges(),
        egress: Vec::new(),
        peers: peers(),
        deleted_volumes: std::collections::BTreeMap::new(),
        generations: std::collections::BTreeMap::new(),
        workload_generations: std::collections::BTreeMap::new(),
        detached: std::collections::BTreeSet::new(),
        ordinals: ordinals(),
        leases: std::collections::BTreeMap::new(),
        network: Some(ClusterNetwork {
            cidr: "10.42.0.0/16".to_owned(),
            node_prefix: 24,
        }),
        endpoints: BTreeMap::new(),
    }
}

// ----------------------------------------------------- What a node sees

#[test]
fn a_node_gets_the_instances_it_is_meant_to_carry() {
    let slice = slice_for("node-a", &view(7));

    let mut carried: Vec<(&str, u32)> = slice
        .instances
        .iter()
        .map(|instance| (instance.workload.as_str(), instance.instance))
        .collect();
    carried.sort_unstable();

    assert_eq!(carried, vec![("api", 0), ("ledger", 0)]);
}

#[test]
fn the_definitions_of_those_instances_come_along() {
    let slice = slice_for("node-a", &view(7));

    for instance in &slice.instances {
        assert!(
            !instance.document.is_empty(),
            "'{}' came without a definition",
            instance.workload
        );
    }
}

#[test]
fn a_node_carries_its_own_ordinal_and_the_network_parameters() {
    let slice = slice_for("node-a", &view(7));

    assert_eq!(slice.ordinal, Some(0));
    assert_eq!(
        slice.network.as_ref().map(|net| net.cidr.as_str()),
        Some("10.42.0.0/16")
    );
    assert_eq!(slice.network.as_ref().map(|net| net.node_prefix), Some(24));
}

/// The full mesh from ADR-0012 means that every node knows every other. That is
/// the honest exception from least privilege and no negligence here.
#[test]
fn every_node_learns_every_peer() {
    let slice = slice_for("node-a", &view(7));

    let mut names: Vec<&str> = slice.peers.iter().map(|peer| peer.node.as_str()).collect();
    names.sort_unstable();

    assert_eq!(names, vec!["node-a", "node-b"]);
}

// ------------------------------------------------ What a node does *not* see

/// The statement at issue — and its exact boundary.
///
/// A foreign workload comes **not** as an instance and **not** with its
/// definition. Its *name* may nevertheless turn up, namely as the counterpart of
/// an edge that touches a workload of this node — and that is no leak but the
/// minimum: without the sender's name `ledger`'s sidecar cannot enforce who may
/// talk to it (ADR-0025).
///
/// The distinction stands here as a test of its own, because it would otherwise
/// be lost at the first "tidying" rebuild.
#[test]
fn a_node_gets_no_foreign_definition_though_it_may_learn_a_foreign_name() {
    let slice = slice_for("node-a", &view(7));

    assert!(
        slice
            .instances
            .iter()
            .all(|instance| instance.workload != "fremd"),
        "'fremd' runs on node-b and has no business on node-a"
    );
    assert!(
        slice
            .instances
            .iter()
            .all(|instance| !instance.document.contains("fremd")),
        "a foreign workload's definition came along"
    );

    // The name **may** occur — but only in an edge.
    let outside_edges = serde_json::to_string(&(&slice.instances, &slice.peers, &slice.network))
        .expect("serializable");
    assert!(
        !outside_edges.contains("fremd"),
        "'fremd' sits outside the edges in the slice: {outside_edges}"
    );
    assert!(
        slice.edges.iter().any(|(from, _)| from == "fremd"),
        "the edge that touches 'ledger' has to come along"
    );
}

/// Edges come along only if they touch a workload of this node.
///
/// `fremd → ledger` touches `ledger`, which runs here — the edge comes along,
/// because `ledger`'s sidecar needs it for enforcement (ADR-0025: **the server
/// is authoritative**). `fremd → irgendwas` touches nothing here and stays out.
#[test]
fn only_edges_that_touch_this_node_come_along() {
    let slice = slice_for("node-a", &view(7));

    let mut carried: Vec<(&str, &str)> = slice
        .edges
        .iter()
        .map(|(from, to)| (from.as_str(), to.as_str()))
        .collect();
    carried.sort_unstable();

    assert_eq!(carried, vec![("api", "ledger"), ("fremd", "ledger")]);
}

#[test]
fn a_node_without_placements_gets_an_empty_but_valid_slice() {
    let slice = slice_for("node-c", &view(7));

    assert!(slice.instances.is_empty());
    assert!(slice.edges.is_empty());
    assert_eq!(slice.ordinal, None, "node-c is not admitted");
    // It gets the peers nevertheless — it is part of the underlay as soon as it
    // is admitted, and an empty slice is no error.
    assert_eq!(slice.peers.len(), 2);
    assert_eq!(slice.index, 7);
}

// ---------------------------------------------------------- Monotonicity

/// ADR-0040, determination 4: what goes backwards is discarded. Without this
/// rule a change of conversation partner could lay an old state over a new one.
#[test]
fn a_slice_from_the_past_is_not_newer_than_what_is_already_applied() {
    let slice = slice_for("node-a", &view(7));

    assert!(slice.newer_than(6));
    assert!(!slice.newer_than(7), "the same position is no new one");
    assert!(!slice.newer_than(8));
}

// ---------------------------------------------------------- Determinism

/// Computed twice yields the same — otherwise the control plane would send a new
/// slice to every node at every change anywhere in the cluster.
#[test]
fn computing_the_slice_twice_gives_the_same_bytes() {
    let left = serde_json::to_string(&slice_for("node-a", &view(7))).expect("serializable");
    let right = serde_json::to_string(&slice_for("node-a", &view(7))).expect("serializable");

    assert_eq!(left, right);
}

/// The order of the inputs must not change the result.
#[test]
fn the_order_of_the_inputs_does_not_change_the_slice() {
    let mut scrambled = view(7);
    scrambled.placements.reverse();
    scrambled.edges.reverse();
    scrambled.peers.reverse();

    assert_eq!(
        serde_json::to_string(&slice_for("node-a", &scrambled)).expect("serializable"),
        serde_json::to_string(&slice_for("node-a", &view(7))).expect("serializable")
    );
}

// ================================================= Egress (ADR-0041, 10d)

/// **Where a foreign workload may go is none of this node's business.**
///
/// The same rule as with the edges, and for the same reason: a compromised node
/// shall not be the cluster's blueprint. Unlike with `may_talk` there is **no**
/// exception here — `api`'s sidecar does not need to know where `fremd` may
/// phone.
#[test]
fn a_node_only_learns_the_egress_of_its_own_workloads() {
    let mut view = view(7);
    view.egress = vec![
        (
            "api".to_owned(),
            "s3.example.com".to_owned(),
            443,
            Transport::Tcp,
        ),
        (
            "fremd".to_owned(),
            "geheim.example".to_owned(),
            443,
            Transport::Tcp,
        ),
    ];

    let slice = slice_for("node-a", &view);

    assert_eq!(
        slice.egress,
        vec![(
            "api".to_owned(),
            "s3.example.com".to_owned(),
            443,
            Transport::Tcp
        )]
    );

    let serialized = serde_json::to_string(&slice.egress).expect("serializable");
    assert!(
        !serialized.contains("geheim.example"),
        "a foreign workload's destination sits in the slice: {serialized}"
    );
}

#[test]
fn a_node_without_egress_gets_an_empty_list_not_an_absent_one() {
    let slice = slice_for("node-a", &view(7));
    assert!(slice.egress.is_empty());
}

// ------------------------------------------------- Tombstones (ADR-0042)

/// **A deletion reaches exactly the node on which the volume lies.**
///
/// A writable volume is node-pinned (ADR-0027); the deletion goes there and
/// nowhere else. A neighbour that got it could at most delete something it
/// should not have deleted.
#[test]
fn a_deletion_reaches_only_the_node_that_holds_the_volume() {
    let mut view = view(7);
    view.deleted_volumes = [("node-1".to_owned(), vec!["stamm".to_owned()])]
        .into_iter()
        .collect();

    assert_eq!(slice_for("node-1", &view).deleted_volumes, ["stamm"]);
    assert!(slice_for("node-2", &view).deleted_volumes.is_empty());
}

/// Without a deletion the list is empty — and empty means "delete nothing", not
/// "delete everything".
#[test]
fn without_a_deletion_the_list_is_empty() {
    assert!(slice_for("node-1", &view(7)).deleted_volumes.is_empty());
}

/// The list is sorted and without repetition — like everything in the slice.
///
/// A slice whose order changes would look like a change at every pass, and the
/// agent would rewrite its files without cause.
#[test]
fn the_deletions_are_sorted_and_deduplicated() {
    let mut view = view(7);
    view.deleted_volumes = [(
        "node-1".to_owned(),
        vec!["zebra".to_owned(), "alpha".to_owned(), "zebra".to_owned()],
    )]
    .into_iter()
    .collect();

    assert_eq!(
        slice_for("node-1", &view).deleted_volumes,
        ["alpha", "zebra"]
    );
}

// ------------------------------------------------ Detach (ADR-0054)

/// A view in which `node-b` is detached.
fn with_detached(node: &str) -> ClusterView {
    ClusterView {
        secrets: Vec::new(),
        registry_credentials: Vec::new(),
        sidecar_overhead: Vec::new(),
        active_instances: std::collections::BTreeMap::new(),
        detached: [node.to_owned()].into_iter().collect(),
        ..view(7)
    }
}

/// **A detached node disappears from the others' peer lists.**
///
/// That is the convergence that happens **without** its participation: the peers
/// stop calling it (ADR-0054, determination 2).
#[test]
fn a_detached_node_leaves_the_peer_lists_of_the_others() {
    let slice = slice_for("node-a", &with_detached("node-b"));

    let names: Vec<&str> = slice.peers.iter().map(|peer| peer.node.as_str()).collect();

    assert_eq!(names, vec!["node-a"], "the detached peer is still there");
}

/// **A detached node sees only itself.**
///
/// Enough for the comparison from ADR-0042 — otherwise it would wake its renewer
/// endlessly because it would not find its own announcement — and too little for
/// a tunnel: `wireguard::peers` leaves itself out, so the list in the kernel
/// stays empty.
#[test]
fn a_detached_node_sees_only_itself() {
    let slice = slice_for("node-b", &with_detached("node-b"));

    let names: Vec<&str> = slice.peers.iter().map(|peer| peer.node.as_str()).collect();

    assert_eq!(
        names,
        vec!["node-b"],
        "a detached node has to still see itself"
    );
}

/// The counter-check: without a detachment the full mesh stays what it is.
///
/// Without it the two tests above would only prove that something is filtered.
#[test]
fn without_a_detachment_nothing_is_filtered() {
    let slice = slice_for("node-a", &view(7));

    assert_eq!(slice.peers.len(), 2, "the full mesh was trimmed");
}

// ------------------------------------------------------- The active-role lease

/// **A node learns its own lease** (ADR-0064, determination 3).
///
/// Without it it never knows whether it has the active role — and ADR-0010's
/// "activation needs a lease grant from the quorum" would have nothing to hang
/// on.
#[test]
fn a_node_learns_its_own_lease() {
    let mut view = view(7);
    view.leases = vec![(
        "api".to_owned(),
        Lease {
            holder: "node-a".to_owned(),
            epoch: 3,
            expires_at: 16_000,
        },
    )]
    .into_iter()
    .collect();

    let slice = slice_for("node-a", &view);

    assert_eq!(
        slice.leases,
        vec![("api".to_owned(), 3_u64, 16_000_u64)],
        "{:?}",
        slice.leases
    );
}

/// **And no foreign one** — the same omission as everywhere (ADR-0040).
///
/// Who holds the active role elsewhere is none of this node's business. A node
/// that knew it could derive no action from it that is its own — but it would
/// know where the writer sits.
///
/// **And it would consider itself the writer.** That is this filter's second
/// promise, and it is a security statement: a warm standby's sidecar gets the
/// same command line as the holder's (`mesh::build` produces **one** definition
/// with `replicas`, and `--single-writer` hangs on the class), so it asks for the
/// same name. What reins it in (ADR-0066) is the missing line alone — if it
/// stood there, two sidecars would serve for one single writer. The other half
/// of the chain is guarded by `a_standby_node_gets_no_active_role` in
/// `tg_agent::session`.
#[test]
fn a_node_learns_no_foreign_lease() {
    let mut view = view(7);
    view.leases = vec![(
        "api".to_owned(),
        Lease {
            holder: "node-b".to_owned(),
            epoch: 3,
            expires_at: 16_000,
        },
    )]
    .into_iter()
    .collect();

    let slice = slice_for("node-a", &view);

    assert!(slice.leases.is_empty(), "{:?}", slice.leases);
    let serialized = serde_json::to_string(&slice).expect("serializable");
    assert!(
        !serialized.contains("16000"),
        "the foreign lease sits in the slice: {serialized}"
    );
}

/// **The decreed generation travels with the instance** (ADR-0071).
///
/// And namely the **effective** one: the maximum of the decree for all and the
/// one for this instance. The node does not compute itself — it compares the
/// number with the mark in its bundle.
#[test]
fn the_ordered_generation_travels_with_the_instance() {
    let mut view = view(7);
    let mut generations = tg_model::rollout::Generations::default();
    generations.set(None, 2);
    generations.set(Some(0), 5);
    view.workload_generations
        .insert("api".to_owned(), generations);
    // And one that is none of this node's business.
    let mut foreign = tg_model::rollout::Generations::default();
    foreign.set(None, 9);
    view.workload_generations
        .insert("fremd".to_owned(), foreign);

    let slice = slice_for("node-a", &view);

    let api = slice
        .instances
        .iter()
        .find(|instance| instance.workload == "api")
        .expect("api runs here");
    assert_eq!(api.generation, 5, "the effective generation is the maximum");

    let ledger = slice
        .instances
        .iter()
        .find(|instance| instance.workload == "ledger")
        .expect("ledger runs here");
    assert_eq!(
        ledger.generation, 0,
        "without a decree the generation is zero — otherwise it would restart \
         without cause"
    );

    // The foreign workload does not occur at all; its generation therefore
    // neither.
    assert!(
        !slice
            .instances
            .iter()
            .any(|instance| instance.workload == "fremd"),
        "the slice carries only its own instances (ADR-0040)"
    );
}

// =========================== The endpoints of foreign workloads (ADR-0073)

/// The view with endpoints: `fremd` runs on `node-b` and may dial `ledger`;
/// `api` on `node-a` may too.
fn view_with_endpoints() -> ClusterView {
    let mut view = view(9);
    view.endpoints.insert(
        "node-b".to_owned(),
        vec![RemoteEndpoint {
            workload: "fremd".to_owned(),
            instance: 0,
            address: "10.42.2.5".parse().expect("address"),
            healthy: true,
        }],
    );
    view.endpoints.insert(
        "node-a".to_owned(),
        vec![RemoteEndpoint {
            workload: "ledger".to_owned(),
            instance: 0,
            address: "10.42.1.6".parse().expect("address"),
            healthy: true,
        }],
    );
    view
}

/// **Whoever may dial gets the address.**
///
/// The core of ADR-0073. Until then the slice carried no address, and the
/// resolver's registry came from the node-local stock alone — a workload on
/// another node resolved `NXDOMAIN`, although the cluster runs it.
#[test]
fn a_node_learns_the_endpoints_its_workloads_may_dial() {
    let mut view = view_with_endpoints();
    // `api` (on node-a) may dial `fremd` (on node-b).
    view.edges.push(("api".to_owned(), "fremd".to_owned()));

    let slice = slice_for("node-a", &view);

    let endpoint = slice
        .endpoints
        .iter()
        .find(|endpoint| endpoint.workload == "fremd")
        .expect("the slice does not carry the foreign endpoint");

    assert_eq!(endpoint.address.to_string(), "10.42.2.5");
    assert!(endpoint.healthy);
}

/// **Only this direction.**
///
/// `node-b` carries `fremd`, and `fremd → ledger` is an edge — but `ledger` runs
/// on `node-a`, so `node-b` needs its address. The other way round it does not
/// hold: `node-a` learns `fremd`'s address **only** if one of its workloads may
/// dial it.
#[test]
fn the_target_of_an_edge_does_not_learn_the_callers_address() {
    let slice = slice_for("node-a", &view_with_endpoints());

    assert!(
        slice.endpoints.is_empty(),
        "the target of an edge learned the caller's address: {:?}",
        slice.endpoints
    );
    // The counter-check to the counter-check: the **edge** very much arrives
    // (the target's sidecar needs it for enforcement). Without it the test would
    // only show that this node gets nothing at all.
    assert!(
        slice
            .edges
            .contains(&("fremd".to_owned(), "ledger".to_owned())),
        "{:?}",
        slice.edges
    );
}

/// **And whoever may dial gets it across the node boundary too.**
///
/// The opposite direction of the same setup: `node-b` carries `fremd`,
/// `fremd → ledger` is an edge, `ledger` runs on `node-a`.
#[test]
fn the_caller_gets_the_address_across_the_node_boundary() {
    let slice = slice_for("node-b", &view_with_endpoints());

    let endpoint = slice
        .endpoints
        .iter()
        .find(|endpoint| endpoint.workload == "ledger")
        .expect("the caller did not get its target's address");

    assert_eq!(endpoint.address.to_string(), "10.42.1.6");
}

/// **Without an edge no address** — deny-by-default applies here too (ADR-0025).
#[test]
fn without_an_edge_no_endpoint_travels() {
    let mut view = view_with_endpoints();
    view.edges.clear();

    assert!(
        slice_for("node-b", &view).endpoints.is_empty(),
        "an endpoint travelled without an edge"
    );
}

/// **Its own endpoints do not come back.**
///
/// The node assigned them and knows them better (phase 9a). Sending them along
/// would be a second source for the same fact — and with a workload with
/// instances here **and** there the same address would stand twice in the
/// registry.
#[test]
fn a_node_does_not_get_its_own_endpoints_back() {
    let mut view = view_with_endpoints();
    // `ledger` also runs on node-b, and `fremd` may dial it.
    view.placements
        .push(("ledger".to_owned(), 1, "node-b".to_owned()));
    view.endpoints
        .get_mut("node-b")
        .expect("node-b")
        .push(RemoteEndpoint {
            workload: "ledger".to_owned(),
            instance: 1,
            address: "10.42.2.6".parse().expect("address"),
            healthy: true,
        });

    let slice = slice_for("node-b", &view);

    let carried: Vec<(&str, u32)> = slice
        .endpoints
        .iter()
        .map(|endpoint| (endpoint.workload.as_str(), endpoint.instance))
        .collect();
    assert_eq!(carried, vec![("ledger", 0)], "its own instance came back");
}

/// **An unhealthy endpoint travels along** (ADR-0073, determination 4).
///
/// Leaving it out would mean `NXDOMAIN` instead of `NODATA` — and phase 9a made
/// two answers out of that for good reason: a client that caches the negative
/// result would stay blind until the instance runs again.
#[test]
fn an_unhealthy_endpoint_still_travels() {
    let mut view = view_with_endpoints();
    view.endpoints
        .get_mut("node-a")
        .expect("node-a")
        .iter_mut()
        .for_each(|endpoint| endpoint.healthy = false);

    let slice = slice_for("node-b", &view);

    let endpoint = slice.endpoints.first().expect("no endpoint");
    assert!(!endpoint.healthy, "the health does not travel along");
}

/// **A node learns only the secrets of its own workloads** (ADR-0016).
///
/// And here **without** the exception the edges have: with `may_talk` the
/// counterpart's name has to come along so that the sidecar can enforce
/// (ADR-0025). A foreign workload's secret is under no aspect this node's
/// business.
///
/// It is additionally checked on the **serialized** slice: an assertion on the
/// field alone says nothing about what really goes over the wire.
#[test]
fn a_node_only_learns_the_secrets_of_its_own_workloads() {
    let mut view = view(7);
    view.secrets = vec![
        (
            "api".to_owned(),
            "s3-key".to_owned(),
            tg_identity::secrets::Sealed {
                ciphertext: vec![1, 2, 3],
                nonce: vec![4, 5, 6],
            },
        ),
        (
            "fremd".to_owned(),
            "db-passwort".to_owned(),
            tg_identity::secrets::Sealed {
                ciphertext: vec![9, 9, 9],
                nonce: vec![8, 8, 8],
            },
        ),
    ];

    let slice = slice_for("node-a", &view);

    let names: Vec<&str> = slice
        .secrets
        .iter()
        .map(|(_, name, _)| name.as_str())
        .collect();
    assert_eq!(names, vec!["s3-key"]);

    let serialized = serde_json::to_string(&slice).expect("serializable");
    assert!(
        !serialized.contains("db-passwort"),
        "a foreign workload's secret travels along: {serialized}"
    );

    // **And the contrast stands beside it**, because it describes the boundary
    // of the omission: the name `fremd` **may** occur in the slice — as the
    // counterpart of a `may_talk` edge, without which the sidecar cannot enforce
    // who may talk to it (ADR-0025). Its secret may not. Without this assertion
    // a reader would take the first for a statement about the **name**, and it
    // is one about the **value**.
    assert!(
        serialized.contains("fremd"),
        "the edge to a foreign workload is missing — then the assertion above \
         checks something other than what it claims"
    );
}

/// **A node learns only the mappings whose secret arrives at it** (ADR-0096,
/// determination 2).
///
/// The complete list would be a directory of the cluster's private registries —
/// information a node does not need in order to pull its own image, and that a
/// compromised one shall not have.
///
/// The counter-check stands **in the same test**: its own mapping arrives.
/// Without it a filter that discards everything would be green too — and then
/// every node would pull anonymously.
#[test]
fn a_node_only_learns_the_registries_it_can_use() {
    let mut view = view(7);
    view.secrets = vec![(
        "api".to_owned(),
        "s3-key".to_owned(),
        tg_identity::secrets::Sealed {
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        },
    )];
    view.registry_credentials = vec![
        ("registry.test".to_owned(), "s3-key".to_owned()),
        ("fremde-registry.test".to_owned(), "db-passwort".to_owned()),
    ];

    let slice = slice_for("node-a", &view);

    assert_eq!(
        slice.registry_credentials,
        vec![("registry.test".to_owned(), "s3-key".to_owned())],
        "its own mapping is missing or a foreign one came along"
    );

    let serialized = serde_json::to_string(&slice).expect("serializable");
    assert!(
        !serialized.contains("fremde-registry.test"),
        "a registry whose secret never arrives here travels along: {serialized}"
    );
}

/// **Only its own snapshot decrees** (ADR-0099).
///
/// Which snapshots another node shall make is none of this one's business — and
/// it could not make them anyway: a writable volume lies on exactly one node
/// (ADR-0027). Unlike with `may_talk`, where the counterpart's name **has to**
/// travel along so that the sidecar can enforce.
#[test]
fn a_node_only_learns_the_snapshot_verdicts_for_its_own_volumes() {
    let mut view = view(7);
    view.snapshot_generations = [
        (
            "node-a".to_owned(),
            [("daten-0".to_owned(), 4u64)].into_iter().collect(),
        ),
        (
            "node-b".to_owned(),
            [("fremd-0".to_owned(), 9u64)].into_iter().collect(),
        ),
    ]
    .into_iter()
    .collect();

    let slice = slice_for("node-a", &view);

    assert_eq!(
        slice.snapshot_generations,
        vec![("daten-0".to_owned(), 4)],
        "only this node's decrees"
    );

    // **And not serialized either.** A field that is empty in the type and turns
    // up on the wire nonetheless would be the same leak -- the assertion on that
    // is the one that counts.
    let serialized = serde_json::to_string(&slice).expect("serializable");
    assert!(
        !serialized.contains("fremd-0"),
        "the slice names a foreign volume: {serialized}"
    );
}

/// And the opposite direction: without a decree the list stays empty.
///
/// Without this half a slice that carries **all** decrees would be
/// indistinguishable at the test above — it would name `fremd-0` only if there
/// is one.
#[test]
fn without_a_verdict_the_slice_carries_none() {
    let view = view(7);
    let slice = slice_for("node-a", &view);
    assert!(slice.snapshot_generations.is_empty());
}

// ------------------------------------------------------- The active instance

/// **A node learns which instance carries the active role** (ADR-0111).
///
/// Without the number it knows only the default, and a promotion would never
/// reach it: its instance 0 would keep waiting for a lease that goes to another
/// instance.
#[test]
fn a_node_learns_which_instance_is_active() {
    let mut view = view(7);
    view.active_instances = vec![("api".to_owned(), 2)].into_iter().collect();

    let slice = slice_for("node-a", &view);

    assert_eq!(slice.active_instances, vec![("api".to_owned(), 2)]);
}

/// **Even when the active instance lies elsewhere** — and that is the difference
/// from the filter of the leases beside it.
///
/// A lease is given only to its holder (ADR-0064, determination 3). The
/// **number** is also needed by the node whose instance is *not* the active one:
/// only from it does it recognize that it is a warm standby and may run without
/// a lease (ADR-0010). Without the entry it would consider itself the designated
/// active one and wait for a lease that never comes — the workload would run
/// **nowhere**.
#[test]
fn a_node_learns_it_even_when_the_active_instance_is_elsewhere() {
    let mut view = view(7);
    // `api` lies with instance 0 on node-a; active is instance 1.
    view.active_instances = vec![("api".to_owned(), 1)].into_iter().collect();

    let slice = slice_for("node-a", &view);

    assert_eq!(
        slice.active_instances,
        vec![("api".to_owned(), 1)],
        "the standby node needs the number to recognize itself as a standby"
    );
}

/// **But not that of a foreign workload** — the same omission as everywhere
/// (ADR-0040, determination 5).
///
/// `fremd` lies on `node-b`. Where its active role sits is none of `node-a`'s
/// business, and from the number one could derive how many instances it has.
#[test]
fn a_node_learns_no_foreign_active_instance() {
    let mut view = view(7);
    view.active_instances = vec![("fremd".to_owned(), 3)].into_iter().collect();

    let slice = slice_for("node-a", &view);

    assert!(
        slice.active_instances.is_empty(),
        "{:?}",
        slice.active_instances
    );
    let serialized = serde_json::to_string(&slice).expect("serializable");
    assert!(
        !serialized.contains("fremd\",3"),
        "the foreign active instance stands on the wire: {serialized}"
    );
}

/// **Without a decree the list stays empty** — and that means instance 0.
///
/// The default is not sent along: it stands in the reader (ADR-0064,
/// determination 8), and a list that carried a zero for every workload would be
/// ballast in every slice — and indistinguishable from "no decree" for a server
/// with an old state.
#[test]
fn without_a_decree_the_list_stays_empty() {
    let slice = slice_for("node-a", &view(7));

    assert!(slice.active_instances.is_empty());
}
