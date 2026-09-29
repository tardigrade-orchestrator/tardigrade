//! The underlay: keys and peer derivation.
//!
//! The core is a **pure function**: from what consensus knows about the
//! nodes follows this node's peer list — and the `AllowedIPs` follow from the
//! ordinal, not from the log.
//!
//! That is a load-bearing property, and it is checkable here: if somebody
//! later changes the derivation so that the permitted networks came from a
//! second source, it stands out. Two sources for the same fact produce a
//! network that tunnels packets to the wrong place without an error appearing
//! anywhere.

use tg_net::ipam::ClusterNet;
use tg_net::wireguard::{Keypair, Member, WgError, peers};

const KEY_A: &str = "iOnLpv2AL2r0YKGCXpXKaVUsBpVYAyLpJvGVc0nlDXo=";
const KEY_B: &str = "2GAX7Nc1YvRHNzMWFqSNXHVDp0oXBSPfKrHWaBaZ2n8=";

/// Builds the fixture cluster network `10.42.0.0/16` with /24 node subnets.
///
/// # Returns
/// The constructed cluster network.
fn cluster() -> ClusterNet {
    ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24).expect("valid")
}

/// Builds a fixture cluster member.
///
/// # Parameters
/// - `name`: the member's name.
/// - `ordinal`: the member's node ordinal.
/// - `key`: the member's announced public key, if it has announced yet.
///
/// # Returns
/// The constructed member, with a fixture endpoint derived from `ordinal`
/// when `key` is `Some`.
fn member(name: &'static str, ordinal: u32, key: Option<&'static str>) -> Member<'static> {
    Member {
        name,
        ordinal,
        key,
        endpoint: key.map(|_| match ordinal {
            0 => "203.0.113.10:51820",
            1 => "203.0.113.11:51820",
            _ => "203.0.113.12:51820",
        }),
    }
}

// -------------------------------------------------------------------- Keys

/// A generated keypair's public key differs from its private key and has the
/// expected base64 shape.
#[test]
fn a_generated_keypair_has_a_public_key_that_is_not_the_private_one() {
    let pair = Keypair::generate();

    assert_ne!(pair.private_base64(), pair.public_base64());
    assert_eq!(
        pair.public_base64().len(),
        44,
        "32 bytes of base64 are 44 characters"
    );
    assert!(pair.public_base64().ends_with('='));
}

/// Two separately generated keypairs have different private keys.
#[test]
fn two_generated_keypairs_differ() {
    assert_ne!(
        Keypair::generate().private_base64(),
        Keypair::generate().private_base64()
    );
}

/// The private key lies on the node's disk and is read back from there — the
/// same way a node's long-lived identity key is persisted and reloaded.
#[test]
fn a_keypair_survives_the_round_trip_through_base64() {
    let original = Keypair::generate();
    let restored = Keypair::from_private_base64(&original.private_base64()).expect("readable");

    assert_eq!(restored.private_base64(), original.private_base64());
    assert_eq!(
        restored.public_base64(),
        original.public_base64(),
        "the public part has to follow from the private one"
    );
}

/// A private key that is not valid base64 or the wrong length is refused.
#[test]
fn a_key_of_the_wrong_length_is_refused() {
    for bad in [
        "",
        "short",
        "iOnLpv2AL2r0YKGCXpXKaVUsBpVYAyLpJvGVc0nlDXo",
        "!!!!",
    ] {
        assert!(
            Keypair::from_private_base64(bad).is_err(),
            "'{}' was accepted",
            bad.escape_debug()
        );
    }
}

// ---------------------------------------------------------- Peer derivation

/// The load-bearing assurance: the permitted networks follow from the **ordinal**.
#[test]
fn the_allowed_networks_are_computed_from_the_ordinal() {
    let members = [
        member("alpha", 0, Some(KEY_A)),
        member("beta", 1, Some(KEY_B)),
    ];

    let derived = peers(&cluster(), &members, "alpha").expect("derivable");

    assert_eq!(derived.len(), 1);
    assert_eq!(derived[0].key, KEY_B);
    assert_eq!(
        derived[0].allowed.to_string(),
        "10.42.1.0/24",
        "beta's network follows from its ordinal 1"
    );
}

/// One is not one's own peer. A node that took itself into the list would tunnel
/// its own traffic to itself.
#[test]
fn a_node_is_never_its_own_peer() {
    let members = [
        member("alpha", 0, Some(KEY_A)),
        member("beta", 1, Some(KEY_B)),
    ];

    for me in ["alpha", "beta"] {
        let derived = peers(&cluster(), &members, me).expect("derivable");
        assert!(
            derived.iter().all(|peer| peer.name != me),
            "'{me}' stands in its own peer list"
        );
    }
}

/// A node that is admitted but has announced nothing yet is no peer — one knows
/// neither its key nor its endpoint. Taking it in with empty settings would
/// yield a peer that never answers.
#[test]
fn a_member_that_has_not_announced_yet_is_not_a_peer() {
    let members = [
        member("alpha", 0, Some(KEY_A)),
        member("beta", 1, None),
        member("gamma", 2, Some(KEY_B)),
    ];

    let derived = peers(&cluster(), &members, "alpha").expect("derivable");

    assert_eq!(derived.len(), 1);
    assert_eq!(derived[0].name, "gamma");
}

/// The derived peer list is ordered deterministically, regardless of input
/// order.
#[test]
fn the_peer_list_is_ordered_deterministically() {
    let members = [
        member("gamma", 2, Some(KEY_B)),
        member("alpha", 0, Some(KEY_A)),
        member("beta", 1, Some(KEY_B)),
    ];

    let derived = peers(&cluster(), &members, "alpha").expect("derivable");
    let names: Vec<&str> = derived.iter().map(|peer| peer.name.as_str()).collect();

    assert_eq!(names, vec!["beta", "gamma"]);
}

/// An ordinal outside the cluster CIDR is a cluster error and no peer one omits.
/// Staying silent would mean that a node stays unreachable and nobody learns
/// why.
#[test]
fn an_ordinal_outside_the_cluster_net_is_a_loud_error() {
    let members = [
        member("alpha", 0, Some(KEY_A)),
        member("far-away", 9_999, Some(KEY_B)),
    ];

    let err = peers(&cluster(), &members, "alpha").expect_err("must not pass");
    assert!(
        matches!(err, WgError::Ordinal { .. }),
        "expected Ordinal, was {err:?}"
    );
}

/// A member with a malformed endpoint produces a loud error, not a silently
/// dropped peer.
#[test]
fn a_malformed_endpoint_is_a_loud_error() {
    let members = [
        member("alpha", 0, Some(KEY_A)),
        Member {
            name: "broken",
            ordinal: 1,
            key: Some(KEY_B),
            endpoint: Some("no-endpoint"),
        },
    ];

    let err = peers(&cluster(), &members, "alpha").expect_err("must not pass");
    assert!(
        matches!(err, WgError::Endpoint { .. }),
        "expected Endpoint, was {err:?}"
    );
}

/// A member with a malformed key produces a loud error, not a silently
/// dropped peer.
#[test]
fn a_malformed_key_is_a_loud_error() {
    let members = [
        member("alpha", 0, Some(KEY_A)),
        Member {
            name: "broken",
            ordinal: 1,
            key: Some("not-a-key"),
            endpoint: Some("203.0.113.11:51820"),
        },
    ];

    let err = peers(&cluster(), &members, "alpha").expect_err("must not pass");
    assert!(
        matches!(err, WgError::Key { .. }),
        "expected Key, was {err:?}"
    );
}

/// A node alone has no peers — and that is no error but a cluster's first
/// day.
#[test]
fn the_first_node_of_a_cluster_has_no_peers() {
    let members = [member("alpha", 0, Some(KEY_A))];
    assert!(
        peers(&cluster(), &members, "alpha")
            .expect("derivable")
            .is_empty()
    );
}
