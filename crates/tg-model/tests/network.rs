//! The cluster's address plan (ADR-0012, ADR-0039).
//!
//! Written before the implementation. What is checked is the **pure
//! computation** ordinal → subnet and its bounds — none of it needs a kernel, a
//! network or a cluster.
//!
//! # Why it lies here and not in `tg-net`
//!
//! It has **two** readers with different tasks. Consensus hands out the ordinal
//! at admission (ADR-0039) and for that has to know how many there are at all;
//! the node computes its subnet from it. Were it to lie only at the node,
//! consensus could hand out a number from which no network ever follows — and
//! that is exactly what it did: it admitted the node, reported `Applied`, and
//! the error appeared only on the node, fail-soft there.
//!
//! The consensus core must not link `tg-net` (netlink, nftables). So the
//! computation belongs under both, and the rule stands there **once**.

use tg_model::network::{Plan, PlanError};

fn net(cidr: &str) -> ipnet::Ipv4Net {
    cidr.parse().expect("valid network")
}

/// The normal case: a /16 with a /24 per node carries 256 nodes.
#[test]
fn a_sixteen_holds_two_hundred_fifty_six_node_subnets() {
    let plan = Plan::new(net("10.42.0.0/16"), 24).expect("valid");

    assert_eq!(plan.capacity(), 256);
}

/// **The ordinal is no position but a computation.**
///
/// The same number gives the same subnet on every node and at every time — on
/// that rest every route, every nftables rule and every `AllowedIP`.
#[test]
fn the_same_ordinal_always_yields_the_same_subnet() {
    let plan = Plan::new(net("10.42.0.0/16"), 24).expect("valid");

    assert_eq!(plan.subnet_of(0).expect("0"), net("10.42.0.0/24"));
    assert_eq!(plan.subnet_of(1).expect("1"), net("10.42.1.0/24"));
    assert_eq!(plan.subnet_of(255).expect("255"), net("10.42.255.0/24"));
}

/// **The last ordinal carries, the first one above it does not.**
///
/// The overflow is refused and not wrapped: a node that silently got another's
/// subnet would be the worst possible outcome.
#[test]
fn the_ordinal_past_the_last_subnet_is_refused() {
    let plan = Plan::new(net("10.42.0.0/16"), 24).expect("valid");

    assert!(plan.subnet_of(255).is_ok());
    assert!(matches!(
        plan.subnet_of(256),
        Err(PlanError::ClusterFull { .. })
    ));
    assert!(matches!(
        plan.subnet_of(u32::MAX),
        Err(PlanError::ClusterFull { .. })
    ));
}

/// **A node prefix that is not narrower than the cluster CIDR yields no
/// subnet.**
#[test]
fn a_node_prefix_no_narrower_than_the_cluster_is_refused() {
    for prefix in [8, 15, 16] {
        assert!(
            matches!(
                Plan::new(net("10.42.0.0/16"), prefix),
                Err(PlanError::NodePrefixTooWide { .. })
            ),
            "/{prefix}"
        );
    }
}

/// **And one narrower than `/30` carries no container.**
///
/// A `/31` would have two addresses (network and broadcast), a `/32` one —
/// after deducting the gateway nothing would remain.
#[test]
fn a_node_prefix_narrower_than_thirty_is_refused() {
    for prefix in [31, 32] {
        assert!(
            matches!(
                Plan::new(net("10.42.0.0/16"), prefix),
                Err(PlanError::NodeSubnetTooSmall { .. })
            ),
            "/{prefix}"
        );
    }
}

/// The counter-check to both: `/30` and `/17` carry.
///
/// Without it a check that refuses every prefix would be just as green.
#[test]
fn the_boundary_prefixes_are_accepted() {
    assert!(Plan::new(net("10.42.0.0/16"), 30).is_ok());
    assert!(Plan::new(net("10.42.0.0/16"), 17).is_ok());
}

/// **A network is trimmed back to its boundary.**
///
/// `10.42.7.0/16` and `10.42.0.0/16` are the same network. Without the trimming
/// the ordinal 0 would yield two different subnets, depending on how an operator
/// wrote it down.
#[test]
fn a_cidr_is_truncated_to_its_network() {
    let sloppy = Plan::new(net("10.42.7.9/16"), 24).expect("valid");
    let exact = Plan::new(net("10.42.0.0/16"), 24).expect("valid");

    assert_eq!(sloppy.subnet_of(3), exact.subnet_of(3));
}

/// **A plan carries an ordinal, or it does not** — the question consensus asks
/// before an admission.
#[test]
fn the_plan_answers_whether_it_holds_an_ordinal() {
    let plan = Plan::new(net("10.42.0.0/24"), 25).expect("valid");

    assert_eq!(plan.capacity(), 2);
    assert!(plan.holds(0));
    assert!(plan.holds(1));
    assert!(!plan.holds(2));
}

/// **A text that is no CIDR is named as such.**
///
/// `Plan::parse` is the one function the client and the state machine use for
/// the same question (ADR-0069). Its two outcomes are two different statements,
/// and an operator looks in different places: "that is no CIDR" means *look at
/// your input*, "the computation does not work out" means *look at the
/// prefix*.
#[test]
fn a_text_that_is_no_cidr_is_named_as_such() {
    use tg_model::network::{ParseError, Plan, PlanError};

    for bad in ["", "rubbish", "10.42.0.0", "10.42.0.0/33", "10.42.0.0/16 "] {
        assert!(
            matches!(Plan::parse(bad, 24), Err(ParseError::NotACidr { cidr }) if cidr == bad),
            "'{bad}' was read as a CIDR"
        );
    }

    // The other half: a **valid** CIDR with a computation that does not work
    // out is no parse error. Without it a `parse` that refuses everything as
    // `NotACidr` would be just as green — and no operator would ever get
    // through.
    assert!(matches!(
        Plan::parse("10.42.0.0/16", 8),
        Err(ParseError::Plan(PlanError::NodePrefixTooWide { .. }))
    ));

    // And the third: what carries, carries.
    let plan = Plan::parse("10.42.0.0/16", 24).expect("valid plan");
    assert_eq!(plan, Plan::new(net("10.42.0.0/16"), 24).expect("valid"));
}
