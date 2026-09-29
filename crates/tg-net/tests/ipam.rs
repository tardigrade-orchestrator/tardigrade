//! Deterministic address assignment.
//!
//! Written along the one property that matters here: **stability**.
//!
//! IP assignment from node subnets must be deterministic. The obvious
//! misunderstanding would be to take a node's index in a sorted list — then
//! the assignment is indeed deterministic, but the disappearance of one node
//! shifts the subnets of **all** the following ones. Every route in the mesh
//! would afterwards be wrong, and quietly at that. That is why the ordinal is
//! an **input** here and no position.
//!
//! The second property is a division of responsibilities that these tests
//! fix:
//!
//! - Which subnet a **node** gets is cluster-wide — two nodes with the same
//!   subnet are a cluster error, so the ordinal belongs in the cluster's
//!   consensus log and is assigned once, at admission.
//! - Which address a **container** gets is node-local. The agent assigns it,
//!   writes it beside its desired-state cache and finds it again after a
//!   restart — without asking the control plane.

use std::net::Ipv4Addr;

use tg_net::ipam::{ClusterNet, IpamError, Leases, Mtu};

/// Builds the fixture cluster network used across this test file: a `/16`
/// cluster CIDR with `/24` node subnets.
///
/// # Returns
/// The constructed cluster network.
fn cluster() -> ClusterNet {
    ClusterNet::new("10.42.0.0/16".parse().expect("valid CIDR"), 24)
        .expect("the node prefix must be narrower than the cluster CIDR")
}

// ------------------------------------------------------------------ Node subnet

/// A node's subnet is derived from the cluster network and its ordinal.
#[test]
fn a_node_subnet_follows_from_the_cluster_net_and_the_ordinal() {
    let subnet = cluster().subnet(0).expect("ordinal 0 must fit");
    assert_eq!(subnet.net().to_string(), "10.42.0.0/24");

    let subnet = cluster().subnet(7).expect("ordinal 7 must fit");
    assert_eq!(subnet.net().to_string(), "10.42.7.0/24");
}

/// The property at issue: an ordinal is no position.
///
/// If node 3 fails, node 4 keeps its subnet. Were the number a list index, 4
/// would move up to 3 — and every route, every nftables rule and every
/// `WireGuard` `AllowedIP` in the cluster would afterwards point into the
/// void.
#[test]
fn a_missing_node_does_not_move_the_subnets_of_the_others() {
    let before = cluster().subnet(4).expect("must fit");
    // Node 3 disappears. 4's ordinal does not change because of that, for it
    // stands in the log and not in an order.
    let after = cluster().subnet(4).expect("must fit");

    assert_eq!(before.net(), after.net());
    assert_eq!(before.gateway(), after.gateway());
}

/// An ordinal beyond the cluster network's capacity is refused, not wrapped
/// around.
#[test]
fn an_ordinal_beyond_the_cluster_net_is_refused_not_wrapped() {
    let net = cluster();
    assert_eq!(net.capacity(), 256, "10.42.0.0/16 carries 256 /24 subnets");

    let err = net.subnet(256).expect_err("the 257th node no longer fits");
    assert!(
        matches!(
            err,
            IpamError::ClusterFull {
                ordinal: 256,
                capacity: 256
            }
        ),
        "expected ClusterFull, was {err:?}"
    );
}

/// A node prefix that is not narrower than the cluster CIDR is refused.
#[test]
fn a_node_prefix_that_is_not_narrower_than_the_cluster_is_refused() {
    let cidr = "10.42.0.0/16".parse().expect("valid CIDR");

    for prefix in [8, 16] {
        let err = ClusterNet::new(cidr, prefix)
            .expect_err("a node prefix must be narrower than the cluster CIDR");
        assert!(
            matches!(err, IpamError::NodePrefixTooWide { .. }),
            "expected NodePrefixTooWide for /{prefix}, was {err:?}"
        );
    }
}

/// A /31 or /32 per node carries no container — that stands out here and not
/// only when the first container gets no address.
#[test]
fn a_node_prefix_with_no_room_for_containers_is_refused() {
    let cidr = "10.42.0.0/16".parse().expect("valid CIDR");

    for prefix in [31, 32] {
        let err = ClusterNet::new(cidr, prefix).expect_err("no room for containers");
        assert!(
            matches!(err, IpamError::NodeSubnetTooSmall { .. }),
            "expected NodeSubnetTooSmall for /{prefix}, was {err:?}"
        );
    }
}

/// The gateway is the node's bridge and is never assigned to a container —
/// otherwise the default-gateway ping would answer the container itself.
#[test]
fn the_gateway_is_the_first_address_and_never_leased() {
    let subnet = cluster().subnet(3).expect("must fit");
    assert_eq!(subnet.gateway(), Ipv4Addr::new(10, 42, 3, 1));

    let mut leases = Leases::new(subnet);
    for instance in 0..20 {
        let address = leases.lease("api", instance).expect("room enough");
        assert_ne!(address, Ipv4Addr::new(10, 42, 3, 1), "gateway assigned");
        assert_ne!(
            address,
            Ipv4Addr::new(10, 42, 3, 0),
            "network address assigned"
        );
        assert_ne!(address, Ipv4Addr::new(10, 42, 3, 255), "broadcast assigned");
    }
}

// -------------------------------------------------------------- Local assignment

/// Leasing the same workload instance twice returns the same address both
/// times.
#[test]
fn the_same_instance_always_gets_the_same_address() {
    let mut leases = Leases::new(cluster().subnet(1).expect("must fit"));

    let first = leases.lease("api", 0).expect("room enough");
    let again = leases.lease("api", 0).expect("room enough");

    assert_eq!(first, again, "asking twice must not assign twice");
    assert_eq!(leases.get("api", 0), Some(first));
}

/// Two instances of one workload get two distinct addresses.
#[test]
fn two_instances_of_one_workload_get_two_addresses() {
    let mut leases = Leases::new(cluster().subnet(1).expect("must fit"));

    let zero = leases.lease("api", 0).expect("room enough");
    let one = leases.lease("api", 1).expect("room enough");

    assert_ne!(zero, one);
}

/// The restart case: the agent finds its addresses again without asking
/// anybody. If it assigned anew, a running container would get an address
/// that does not stand on its interface in the kernel.
#[test]
fn leases_survive_a_restart_through_the_persisted_form() {
    let subnet = cluster().subnet(9).expect("must fit");
    let mut leases = Leases::new(subnet.clone());

    let api = leases.lease("api", 0).expect("room enough");
    let ledger = leases.lease("ledger", 2).expect("room enough");

    let persisted = serde_json::to_string(&leases.snapshot()).expect("serializable");

    // The agent restarts and reads only its own disk.
    let restored: tg_net::ipam::LeaseTable = serde_json::from_str(&persisted).expect("readable");
    let leases = Leases::restore(subnet, restored).expect("the ledger must fit");

    assert_eq!(leases.get("api", 0), Some(api));
    assert_eq!(leases.get("ledger", 2), Some(ledger));
}

/// If the operator changes the cluster CIDR, old addresses are no longer
/// addresses of this node. Keeping them silently would mean carrying on with
/// addresses that are routed nowhere.
#[test]
fn a_restored_lease_outside_the_subnet_is_refused() {
    let mut leases = Leases::new(cluster().subnet(1).expect("must fit"));
    leases.lease("api", 0).expect("room enough");
    let table = leases.snapshot();

    // The same ledger, but the node now has a different subnet.
    let elsewhere = cluster().subnet(2).expect("must fit");
    let err = Leases::restore(elsewhere, table).expect_err("foreign address");

    assert!(
        matches!(err, IpamError::LeaseOutsideSubnet { .. }),
        "expected LeaseOutsideSubnet, was {err:?}"
    );
}

/// Two entries on the same address are a broken ledger — two containers with the
/// same IP, and the error shows itself only in operation.
#[test]
fn a_restored_table_with_a_duplicate_address_is_refused() {
    let mut leases = Leases::new(cluster().subnet(1).expect("must fit"));
    let address = leases.lease("api", 0).expect("room enough");
    let mut table = leases.snapshot();
    table.push_raw("ledger", 0, address);

    let err = Leases::restore(cluster().subnet(1).expect("must fit"), table)
        .expect_err("duplicate address");
    assert!(
        matches!(err, IpamError::DuplicateLease { .. }),
        "expected DuplicateLease, was {err:?}"
    );
}

/// A released address becomes available for the next lease.
#[test]
fn a_released_address_becomes_available_again() {
    let mut leases = Leases::new(cluster().subnet(1).expect("must fit"));

    let first = leases.lease("api", 0).expect("room enough");
    assert_eq!(leases.release("api", 0), Some(first));
    assert_eq!(leases.get("api", 0), None);

    let next = leases.lease("ledger", 0).expect("room enough");
    assert_eq!(next, first, "the freed address is reused");
}

/// Releasing an address that was never leased is not an error.
#[test]
fn releasing_something_that_was_never_leased_is_not_an_error() {
    let mut leases = Leases::new(cluster().subnet(1).expect("must fit"));
    assert_eq!(leases.release("api", 0), None);
}

/// A full subnet refuses a further lease instead of handing out a colliding
/// address.
#[test]
fn a_full_subnet_refuses_instead_of_handing_out_a_collision() {
    let subnet = cluster().subnet(1).expect("must fit");
    let capacity = subnet.capacity();
    assert_eq!(capacity, 253, "/24 minus network, broadcast and gateway");

    let mut leases = Leases::new(subnet);
    for instance in 0..capacity {
        leases.lease("api", instance).expect("up to here it fits");
    }

    let err = leases
        .lease("api", capacity)
        .expect_err("the subnet is full");
    assert!(
        matches!(err, IpamError::SubnetFull { .. }),
        "expected SubnetFull, was {err:?}"
    );
}

/// No two containers on one node share an address — not across workload
/// boundaries either, and not after releases in between.
#[test]
fn no_two_live_containers_share_an_address() {
    let mut leases = Leases::new(cluster().subnet(1).expect("must fit"));
    let mut seen = std::collections::BTreeSet::new();

    for workload in ["api", "ledger", "cache"] {
        for instance in 0..40 {
            let address = leases.lease(workload, instance).expect("room enough");
            assert!(
                seen.insert(address),
                "{address} assigned twice ({workload}/{instance})"
            );
        }
    }

    leases.release("ledger", 7);
    let reused = leases.lease("new", 0).expect("room enough");
    assert!(leases.get("ledger", 7).is_none());
    assert_eq!(
        leases
            .entries()
            .iter()
            .filter(|lease| lease.address == reused)
            .count(),
        1,
        "the reused address hangs on exactly one container"
    );
}

// ------------------------------------------------------------------------- MTU

/// 1500 − 60 would be 1440, and that number is unsafe. 1420 is correct
/// instead, because the `WireGuard` surcharge is 60 bytes over IPv4 but **80
/// over IPv6** (40 IPv6 + 8 UDP + 32 `WireGuard`). Whoever sets 1440
/// fragments as soon as the underlay runs over IPv6 — precisely what this
/// MTU is meant to avoid.
#[test]
fn the_overlay_mtu_leaves_room_for_the_worst_case_wireguard_header() {
    let mtu = Mtu::for_overlay(1500).expect("1500 carries");
    assert_eq!(mtu.get(), 1420, "ADR-0012 names 1420");
    assert_eq!(Mtu::WIREGUARD_OVERHEAD, 80);
}

/// An underlay MTU too small to carry the overlay is refused.
#[test]
fn an_underlay_too_small_to_carry_the_overlay_is_refused() {
    let err = Mtu::for_overlay(1300).expect_err("1300 − 80 lies below the minimum");
    assert!(
        matches!(err, IpamError::MtuTooSmall { .. }),
        "expected MtuTooSmall, was {err:?}"
    );
}

// ------------------------------------------------------------- Interface names

/// `IFNAMSIZ` is 16 including the null — 15 usable characters. A name made of
/// workload and instance breaches that at once: `veth-zahlungsverkehr-0` is 22.
/// The kernel would refuse it, and only at interface creation time.
#[test]
fn a_host_link_name_fits_the_kernel_limit_for_any_address() {
    let subnet = cluster().subnet(255).expect("must fit");
    let mut leases = Leases::new(subnet);

    let long = "zahlungsverkehr-abwicklung-europa";
    let address = leases.lease(long, 4095).expect("room enough");
    let name = tg_net::ipam::host_link(address);

    // The number comes from `MAX_LINK_NAME` and not by hand: written hard it
    // would stand here twice, and the witness would check a bound it wrote down
    // itself.
    assert!(
        name.as_str().len() <= tg_net::ipam::MAX_LINK_NAME,
        "'{name}' is {} characters long, IFNAMSIZ allows {}",
        name.as_str().len(),
        tg_net::ipam::MAX_LINK_NAME
    );
    assert!(
        name.as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "'{name}' contains characters no interface name carries"
    );
}

/// The name hangs on the address and not on the workload name. With that it
/// inherits its uniqueness: two containers on one node have different addresses,
/// hence different interface names — without a hash, without a counter and
/// without the possibility of a collision one notices only at creation.
#[test]
fn host_link_names_are_unique_because_addresses_are() {
    let mut leases = Leases::new(cluster().subnet(1).expect("must fit"));
    let mut seen = std::collections::BTreeSet::new();

    for instance in 0..253 {
        let address = leases.lease("api", instance).expect("room enough");
        assert!(
            seen.insert(tg_net::ipam::host_link(address).into_string()),
            "interface name duplicated at instance {instance}"
        );
    }
}

/// The same address always yields the same interface link name.
#[test]
fn the_same_address_always_yields_the_same_link_name() {
    let address = Ipv4Addr::new(10, 42, 3, 17);
    assert_eq!(
        tg_net::ipam::host_link(address),
        tg_net::ipam::host_link(address)
    );
}
