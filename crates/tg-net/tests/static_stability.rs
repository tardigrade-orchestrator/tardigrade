//! Addresses and names without a control plane.
//!
//! This is a deliberate test axis: behaviour in the absence of the control
//! plane. For the network that means something concrete and checkable — a
//! node that restarts while the control plane is away must
//!
//! 1. find **the same addresses** again that stand in the kernel on the
//!    interfaces of its running containers, and
//! 2. still be able to resolve what it sees itself.
//!
//! Neither may require a question to anybody. The second part of this file
//! also shows that `tg-net` and `tg-store` **fit together without knowing
//! about each other**: the registry is built here from a real projection,
//! and `tg-net` nevertheless does not depend on `tg-store`.

use tg_net::discovery::{Answer, Domain, Endpoint, Health, Registry};
use tg_net::ipam::{ClusterNet, LeaseTable, Leases};
use tg_store::{ActualStatus, Projection};

const DEFINITION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="example.com/api:1"/>
  </workload>
  <workload name="ledger" kind="service">
    <image reference="example.com/ledger:1"/>
  </workload>
</workloads>"#;

/// Builds the fixture node subnet used across this test file.
///
/// # Returns
/// The subnet for ordinal 5 in a `10.42.0.0/16` cluster network.
fn subnet() -> tg_net::ipam::NodeSubnet {
    ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24)
        .expect("valid")
        .subnet(5)
        .expect("valid")
}

/// The translation from the observed state into "accepts traffic".
///
/// It stands here and not in `tg-net`: there the network crate would otherwise
/// depend on the projection. For resolution "stopped" and "failed" are the
/// same — neither accepts traffic.
///
/// # Parameters
/// - `status`: the observed status of an instance.
///
/// # Returns
/// The health to report for that instance.
fn health(status: ActualStatus) -> Health {
    match status {
        ActualStatus::Running => Health::Healthy,
        ActualStatus::Stopped | ActualStatus::Failed | ActualStatus::Unknown => Health::Unhealthy,
    }
}

/// Builds the resolvable view from what the node knows locally.
///
/// # Parameters
/// - `projection`: the local projection carrying the observed instance states.
/// - `leases`: the local address ledger.
///
/// # Returns
/// A registry combining each leased address with its instance's health.
fn registry(projection: &Projection, leases: &Leases) -> Registry {
    let actual = projection.actual_states();

    let endpoints = leases
        .entries()
        .into_iter()
        .map(|lease| Endpoint {
            health: actual
                .get(&(lease.workload.clone(), lease.instance))
                .copied()
                .map_or(Health::Unhealthy, health),
            workload: lease.workload,
            instance: lease.instance,
            address: lease.address,
        })
        .collect();

    Registry::new(
        Domain::new("tardigrade.internal").expect("valid"),
        endpoints,
    )
}

/// The normal case, so that the failure test beside it means something.
/// Reports instances as **one** report of a node.
///
/// `report_instances` replaces the whole report for a node: two calls in
/// succession are not two reports but the second one. What holds together
/// therefore belongs in one call.
///
/// # Parameters
/// - `projection`: the projection to report into.
/// - `states`: the workload/instance/status triples to report as one batch.
fn report(projection: &Projection, states: &[(&str, u32, ActualStatus)]) {
    projection.report_instances(
        "n1",
        states
            .iter()
            .map(|(workload, instance, status)| ((*workload).to_owned(), *instance, *status))
            .collect(),
    );
}

/// The registry is built correctly from a real projection and real leases.
#[test]
fn the_registry_is_built_from_a_real_projection() {
    let set = tg_defs::from_str(DEFINITION).expect("fixture must parse");
    let projection = Projection::new();
    projection.materialize(set.workloads());
    report(
        &projection,
        &[
            ("api", 0, ActualStatus::Running),
            ("ledger", 0, ActualStatus::Running),
        ],
    );

    let mut leases = Leases::new(subnet());
    let api = leases.lease("api", 0).expect("room enough");
    let ledger = leases.lease("ledger", 0).expect("room enough");

    let registry = registry(&projection, &leases);

    assert_eq!(
        registry.resolve("api.tardigrade.internal"),
        Answer::Addresses(vec![api])
    );
    assert_eq!(
        registry.resolve("ledger.tardigrade.internal"),
        Answer::Addresses(vec![ledger])
    );
}

/// The test for static stability: behaviour without a control plane.
///
/// The node restarts, the control plane is not there. It has exactly two
/// sources: its address ledger on disk and its own desired-state cache. Both
/// belong to it, both survive.
///
/// The decisive part is the **equality of the addresses**: if the container got
/// a different one after the restart, the old one would still stand in the
/// kernel on its interface — and the agent would talk over an address nobody
/// carries.
#[test]
fn a_restarted_node_keeps_its_addresses_and_its_names_without_the_control_plane() {
    // --- before the restart ---
    let set = tg_defs::from_str(DEFINITION).expect("fixture must parse");
    let before_projection = Projection::new();
    before_projection.materialize(set.workloads());
    report(&before_projection, &[("api", 0, ActualStatus::Running)]);

    let mut before_leases = Leases::new(subnet());
    let api_address = before_leases.lease("api", 0).expect("room enough");
    let ledger_address = before_leases.lease("ledger", 0).expect("room enough");

    let on_disk = serde_json::to_string(&before_leases.snapshot()).expect("serializable");

    // --- Restart. Nobody is reachable. ---
    let restored: LeaseTable = serde_json::from_str(&on_disk).expect("readable");
    let after_leases = Leases::restore(subnet(), restored).expect("own ledger");

    // The desired state comes from the local cache, not from the cluster:
    // the agent is locally authoritative for what it runs.
    let after_projection = Projection::new();
    after_projection.materialize(set.workloads());
    report(&after_projection, &[("api", 0, ActualStatus::Running)]);

    assert_eq!(
        after_leases.get("api", 0),
        Some(api_address),
        "the address of a running container must not change"
    );
    assert_eq!(after_leases.get("ledger", 0), Some(ledger_address));

    let registry = registry(&after_projection, &after_leases);
    assert_eq!(
        registry.resolve("api.tardigrade.internal"),
        Answer::Addresses(vec![api_address]),
        "the node still resolves what it sees itself"
    );
}

/// What the node **cannot** do without the control plane — and what is right
/// about that.
///
/// It knows nothing about containers on other nodes. A resolution that returned
/// a stale address of a foreign node would be worse than NODATA: the client
/// would get an address nobody carries instead of trying again right away. The
/// mTLS handshake does catch the case, but only one delivery later.
#[test]
fn a_node_alone_answers_only_for_what_it_hosts() {
    let set = tg_defs::from_str(DEFINITION).expect("fixture must parse");
    let projection = Projection::new();
    projection.materialize(set.workloads());
    report(&projection, &[("api", 0, ActualStatus::Running)]);

    // `ledger` runs elsewhere — this node has no address for it.
    let mut leases = Leases::new(subnet());
    leases.lease("api", 0).expect("room enough");

    let registry = registry(&projection, &leases);

    assert_eq!(
        registry.resolve("ledger.tardigrade.internal"),
        Answer::NxDomain
    );
    assert!(matches!(
        registry.resolve("api.tardigrade.internal"),
        Answer::Addresses(_)
    ));
}

/// A reported failure takes the endpoint out of resolution — even when nobody
/// can confirm it.
#[test]
fn an_unhealthy_workload_drops_out_even_with_nobody_to_ask() {
    let set = tg_defs::from_str(DEFINITION).expect("fixture must parse");
    let projection = Projection::new();
    projection.materialize(set.workloads());
    report(&projection, &[("api", 0, ActualStatus::Failed)]);

    let mut leases = Leases::new(subnet());
    leases.lease("api", 0).expect("room enough");

    assert_eq!(
        registry(&projection, &leases).resolve("api.tardigrade.internal"),
        Answer::NoData,
        "failed means NODATA, not NXDOMAIN — the name exists"
    );
}

/// A workload without a reported state is not healthy.
///
/// `Unknown` means "never seen". Treating it as healthy would be the more
/// dangerous default: then a client would get the address of a container nobody
/// knows to be alive. Fail-static means holding the last **known** state — not
/// guessing the unknown.
#[test]
fn a_workload_never_seen_is_not_healthy() {
    let set = tg_defs::from_str(DEFINITION).expect("fixture must parse");
    let projection = Projection::new();
    projection.materialize(set.workloads());

    let mut leases = Leases::new(subnet());
    leases.lease("api", 0).expect("room enough");

    assert_eq!(
        registry(&projection, &leases).resolve("api.tardigrade.internal"),
        Answer::NoData
    );
}

/// **A downed instance does not take its siblings with it** — and a running one
/// does not keep them in.
///
/// That is the gain from the instance-precise projection. Until then it kept
/// **one** actual state per workload; several instances on one node had to be
/// summarized, and the summary was wrong in both directions:
///
/// - Taking the **best** state, a dead address kept resolving.
/// - Taking the **worst**, healthy addresses disappeared along with it.
///
/// Both are gone now: every address carries the health of its own instance. The
/// address belongs to an instance — so its health must come from it.
#[test]
fn one_failed_instance_does_not_take_its_siblings_out_of_dns() {
    let set = tg_defs::from_str(DEFINITION).expect("fixture must parse");
    let projection = Projection::new();
    projection.materialize(set.workloads());

    let mut leases = Leases::new(subnet());
    let first = leases.lease("api", 0).expect("room enough");
    let second = leases.lease("api", 1).expect("room enough");
    let third = leases.lease("api", 2).expect("room enough");
    assert_ne!(first, second);

    report(
        &projection,
        &[
            ("api", 0, ActualStatus::Running),
            ("api", 1, ActualStatus::Failed),
            ("api", 2, ActualStatus::Running),
        ],
    );

    let registry = registry(&projection, &leases);

    assert_eq!(
        registry.resolve("api.tardigrade.internal"),
        Answer::Addresses(vec![first, third]),
        "the healthy instances have to resolve, the failed one must not"
    );
    assert!(
        !matches!(
            registry.resolve("api.tardigrade.internal"),
            Answer::Addresses(ref addresses) if addresses.contains(&second)
        ),
        "the failed instance's address stands in the answer"
    );
}

/// And if **all** instances are down, it is NODATA — not NXDOMAIN.
///
/// The name exists, only nobody accepts traffic right now. An NXDOMAIN would
/// make a client hold the name itself to be wrong, not merely unreachable.
#[test]
fn all_instances_down_is_nodata_not_nxdomain() {
    let set = tg_defs::from_str(DEFINITION).expect("fixture must parse");
    let projection = Projection::new();
    projection.materialize(set.workloads());

    let mut leases = Leases::new(subnet());
    let _ = leases.lease("api", 0).expect("room enough");
    let _ = leases.lease("api", 1).expect("room enough");

    report(
        &projection,
        &[
            ("api", 0, ActualStatus::Failed),
            ("api", 1, ActualStatus::Stopped),
        ],
    );

    let registry = registry(&projection, &leases);

    assert_eq!(registry.resolve("api.tardigrade.internal"), Answer::NoData);
}
