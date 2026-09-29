//! The rule set as a value.
//!
//! What is checked here is the **shape** of the rule set, not its effect — the
//! effect is checked by `kernel_path.rs` on real packets. Both are needed: a
//! rule set the kernel accepts can still do the wrong thing, and one that
//! would do the right thing is of no use if `nft` refuses it.
//!
//! The four properties nailed down here are all ones whose violation is noticed
//! only late in operation:
//!
//! 1. **Order in the namespace.** The exception for the sidecar stands before
//!    the redirect. The other way round the sidecar redirects its own traffic
//!    onto itself — a loop that appears as a timeout.
//! 2. **The host stays the host.** The rule set decides only about traffic that
//!    touches our own bridge. An orchestrator that seizes the host's forwarding
//!    policy locks foreign services out when tidying up.
//! 3. **Never `flush ruleset`.** Flushing the whole rule set would clear away
//!    tables that belong to other software sharing the same nftables instance.
//! 4. **No BPF.** Nothing produced here may ever load a BPF program, checked
//!    at the level where a BPF expression could first sneak in.

use tg_net::ipam::{ClusterNet, NodeSubnet};
use tg_net::rules::{self, HostRules, NetnsRules};

/// Builds the fixture cluster network `10.42.0.0/16` with /24 node subnets.
///
/// # Returns
/// The constructed cluster network.
fn cluster() -> ClusterNet {
    ClusterNet::new("10.42.0.0/16".parse().expect("valid"), 24).expect("valid")
}

/// Builds the fixture subnet for node ordinal 1 within [`cluster`].
///
/// # Returns
/// The constructed node subnet.
fn subnet() -> NodeSubnet {
    cluster().subnet(1).expect("valid")
}

/// Renders the host-level rule set for the fixture cluster and subnet as JSON.
///
/// # Returns
/// The serialized rule set.
fn host_json() -> String {
    rules::to_json(&HostRules::new(&cluster(), &subnet()).render()).expect("serializable")
}

/// Renders the namespace-level rule set for the fixture cluster and subnet as
/// JSON, with a fixed sidecar UID.
///
/// # Returns
/// The serialized rule set.
fn netns_json() -> String {
    rules::to_json(&NetnsRules::new(&cluster(), &subnet(), 4711).render()).expect("serializable")
}

// ------------------------------------------------------ Order in the netns

/// This file's most important assurance.
///
/// The sidecar connects outwards itself. Were the redirect to come before its
/// exception, that connection would land back at it — and the error would show
/// up as a hanging connection, not as a rule error.
#[test]
fn the_sidecar_exemption_comes_before_the_redirect() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711).outbound_statements();

    let exemption = statements
        .iter()
        .position(|line| line.contains("skuid"))
        .expect("the exception for the sidecar is missing");
    let redirect = statements
        .iter()
        .position(|line| line.contains("redirect"))
        .expect("the redirect is missing");

    assert!(
        exemption < redirect,
        "the exception stands behind the redirect: {statements:#?}"
    );
}

/// Loopback is not redirected. The sidecar addresses its workload over
/// `127.0.0.1`; were that redirected, it would talk to itself.
#[test]
fn loopback_is_never_redirected() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711).outbound_statements();

    let loopback = statements
        .iter()
        .position(|line| line.contains(r#""addr":"127.0.0.0","len":8"#))
        .expect("the loopback exception is missing");
    let redirect = statements
        .iter()
        .position(|line| line.contains("redirect"))
        .expect("the redirect is missing");

    assert!(loopback < redirect, "{statements:#?}");
}

/// Only what goes into the cluster is redirected.
///
/// **Without `with_egress` only mesh traffic is redirected.**
///
/// Egress traffic is deny-by-default, with the sidecar as the only way out.
/// That is a **behaviour change** relative to plain TCP forwarding: a
/// definition without `<mesh>` loses its way out. That is why egress has to
/// be given explicitly, and without the setting outbound traffic stays
/// exactly at what this test records — redirected only into the cluster.
#[test]
fn only_traffic_into_the_cluster_is_redirected() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711).outbound_statements();
    let redirect = statements
        .iter()
        .find(|line| line.contains("redirect"))
        .expect("the redirect is missing");

    assert!(
        redirect.contains(r#""addr":"10.42.0.0","len":16"#),
        "the redirect is not restricted to the cluster CIDR: {redirect}"
    );
}

/// The node itself is no mesh target: the node's own resolver listens there,
/// and DNS over TCP must not land in the sidecar.
#[test]
fn traffic_to_the_node_itself_is_exempt() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711).outbound_statements();

    let gateway = statements
        .iter()
        .position(|line| line.contains("10.42.1.1"))
        .expect("the exception for the gateway is missing");
    let redirect = statements
        .iter()
        .position(|line| line.contains("redirect"))
        .expect("the redirect is missing");

    assert!(gateway < redirect, "{statements:#?}");
}

/// The sidecar ports produced by the renderer match the documented constants.
#[test]
fn the_sidecar_ports_are_the_documented_ones() {
    let json = netns_json();
    assert!(json.contains(&rules::SIDECAR_OUTBOUND.to_string()));
    assert!(json.contains(&rules::SIDECAR_INBOUND.to_string()));
    assert_ne!(rules::SIDECAR_INBOUND, rules::SIDECAR_OUTBOUND);
}

/// Both ports have to lie outside the ephemeral range, otherwise the kernel
/// hands them out to a client socket at some point — and the sidecar finds its
/// own port occupied.
#[test]
fn the_sidecar_ports_are_outside_the_ephemeral_range() {
    for port in [rules::SIDECAR_INBOUND, rules::SIDECAR_OUTBOUND] {
        assert!(port > 1024, "{port} lies in the privileged range");
        assert!(port < 32768, "{port} lies in the ephemeral range");
    }
}

// --------------------------------------------------- The host stays the host

/// Traffic that does not touch our own bridge is let through before any
/// decision falls.
#[test]
fn traffic_that_does_not_touch_our_bridge_is_returned_first() {
    let statements = HostRules::new(&cluster(), &subnet()).forward_statements();

    let first = statements.first().expect("the chain is empty");
    assert!(
        first.contains("tg0") && first.contains("return"),
        "the first rule does not release foreign traffic: {first}"
    );
}

/// The chain has `policy accept` and refuses **expressly**, instead of relying
/// on a default.
///
/// `policy drop` on a `forward` hook applies to **all** of the host's forwarded
/// traffic, not only to ours. A VM bridge beside it would be dead, and nobody
/// would look for the error at the container orchestrator.
#[test]
fn the_forward_chain_does_not_seize_the_hosts_policy() {
    assert_eq!(
        HostRules::new(&cluster(), &subnet()).forward_policy(),
        "accept"
    );

    let statements = HostRules::new(&cluster(), &subnet()).forward_statements();
    assert!(
        statements.iter().any(|line| line.contains("drop")),
        "without an express drop the chain would be without effect: {statements:#?}"
    );
}

/// **Traffic from the tunnel may enter the bridge.**
///
/// Measured on real packets between two nodes (`two_nodes`): without this rule
/// every packet that arrived on `tgwg0` and went to one of our own containers
/// fell into the `drop` at the end of the chain — the return direction was
/// allowed (`iifname "tg0"`), the outward one not. With that **no** container
/// reached a container on another node, although the scheduler's default
/// spread across racks distributes exactly there.
///
/// That the tunnel is not "outside" in the process is the core: WireGuard
/// authenticates the peer and checks its `AllowedIPs`, so the source is a
/// container of a node the cluster knows. Who **may** talk to whom is still
/// decided by the certificate in the sidecar and not by the packet filter.
#[test]
fn traffic_from_the_tunnel_may_enter_the_bridge() {
    let statements = HostRules::new(&cluster(), &subnet()).forward_statements();

    let accept = statements
        .iter()
        .position(|line| line.contains("tgwg0") && line.contains("tg0") && line.contains("accept"))
        .expect("no rule lets traffic from the tunnel into the bridge");
    let drop = statements
        .iter()
        .position(|line| line.contains("drop"))
        .expect("no drop");

    assert!(
        accept < drop,
        "the rule stands behind the drop and is thereby without effect: {statements:#?}"
    );
}

/// Containers on the same node may reach each other over the bridge.
#[test]
fn containers_on_the_same_node_may_reach_each_other() {
    let statements = HostRules::new(&cluster(), &subnet()).forward_statements();

    let accept = statements
        .iter()
        .position(|line| line.contains("tg0") && line.contains("accept"))
        .expect("no rule lets containers through to each other");
    let drop = statements
        .iter()
        .position(|line| line.contains("drop"))
        .expect("no drop");

    assert!(accept < drop, "{statements:#?}");
}

/// Traffic leaving the cluster CIDR is masqueraded.
#[test]
fn traffic_leaving_the_cluster_is_masqueraded() {
    let json = host_json();
    assert!(json.contains("masquerade"), "{json}");
    assert!(json.contains(r#""addr":"10.42.0.0","len":16"#), "{json}");
}

// ------------------------------------------------- Hard assurances on the rule set

/// Never the whole rule set: a flush would clear away tables belonging to
/// other software sharing the same nftables instance.
#[test]
fn nothing_ever_flushes_the_whole_ruleset() {
    for json in [host_json(), netns_json()] {
        assert!(
            !json.contains("\"flush\":{\"ruleset\""),
            "the rule set clears foreign tables away: {json}"
        );
    }
}

/// Only our own table is touched, under its fixed, documented name.
#[test]
fn only_our_own_table_is_named() {
    for json in [host_json(), netns_json()] {
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let mut tables = std::collections::BTreeSet::new();
        collect_tables(&parsed, &mut tables);

        assert_eq!(
            tables,
            [rules::TABLE.to_owned()].into_iter().collect(),
            "foreign table in the rule set: {tables:?}"
        );
    }
}

/// Recursively collects every `table` name referenced anywhere in a rendered
/// rule set, to check that no foreign table is touched.
///
/// # Parameters
/// - `value`: the JSON value to search.
/// - `into`: the set to add discovered table names to.
fn collect_tables(value: &serde_json::Value, into: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                if key == "table"
                    && let Some(name) = nested.as_str()
                {
                    into.insert(name.to_owned());
                }
                collect_tables(nested, into);
            }
            if let Some(table) = map.get("table").and_then(|t| t.get("name"))
                && let Some(name) = table.as_str()
            {
                into.insert(name.to_owned());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_tables(item, into);
            }
        }
        _ => {}
    }
}

/// The point at which eBPF would first sneak into the rule set, if it ever
/// did.
///
/// nftables knows expressions that load BPF (`meta bpf`, `xt` compatibility).
/// None of them may ever stand in the produced rule set — and because that is
/// an assurance about **everything** this module ever produces, it stands here
/// and not in an integration test.
#[test]
fn the_generated_ruleset_never_carries_a_bpf_expression() {
    for json in [host_json(), netns_json()] {
        let lowered = json.to_ascii_lowercase();
        for forbidden in ["bpf", "\"xt\"", "ebpf"] {
            assert!(
                !lowered.contains(forbidden),
                "'{forbidden}' in the produced rule set: {json}"
            );
        }
    }
}

/// A rule set is only usable if it yields the same thing twice — otherwise
/// every reconcile produces a change, and the table is rebuilt on every pass.
#[test]
fn rendering_twice_gives_the_same_bytes() {
    assert_eq!(host_json(), host_json());
    assert_eq!(netns_json(), netns_json());
}

// ------------------------------------------------------- Egress

/// **With `with_egress` the way out goes through the sidecar too.**
///
/// The egress redirect is the last rule — what goes into the mesh is already
/// redirected beforehand and no longer arrives here.
#[test]
fn with_egress_everything_else_goes_to_the_sidecar_too() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711)
        .with_egress(tg_net::rules::SIDECAR_EGRESS)
        .outbound_statements();

    let last = statements.last().expect("rules");

    assert!(last.contains("redirect"), "{last}");
    assert!(
        last.contains(&tg_net::rules::SIDECAR_EGRESS.to_string()),
        "{last}"
    );
    assert!(
        !last.contains("10.42.0.0"),
        "the egress redirect must not be restricted to the cluster CIDR: {last}"
    );
}

/// **The mesh redirect stands before it.**
///
/// The other way round all traffic — the one into the mesh too — would go to
/// the egress port, and the sidecar does **not** terminate TLS there. The
/// mesh would lose its mTLS, and silently at that: the connection would come
/// about.
#[test]
fn the_mesh_redirect_comes_before_the_egress_redirect() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711)
        .with_egress(tg_net::rules::SIDECAR_EGRESS)
        .outbound_statements();

    let mesh = statements
        .iter()
        .position(|line| line.contains("10.42.0.0"))
        .expect("the mesh redirect is missing");
    let egress = statements
        .iter()
        .position(|line| line.contains(&tg_net::rules::SIDECAR_EGRESS.to_string()))
        .expect("the egress redirect is missing");

    assert!(mesh < egress, "{statements:#?}");
}

/// **The exception for the sidecar itself stands before both.**
///
/// Otherwise its own call outwards would redirect back onto it — a loop that
/// appears as a timeout and not as a rule error.
#[test]
fn the_sidecars_own_traffic_is_exempt_from_the_egress_redirect() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711)
        .with_egress(tg_net::rules::SIDECAR_EGRESS)
        .outbound_statements();

    let own = statements
        .iter()
        .position(|line| line.contains("4711"))
        .expect("the exception for the sidecar is missing");
    let egress = statements
        .iter()
        .position(|line| line.contains(&tg_net::rules::SIDECAR_EGRESS.to_string()))
        .expect("the egress redirect is missing");

    assert!(own < egress, "{statements:#?}");
}

/// **The node itself stays exempt — with egress too.**
///
/// The node's own resolver listens there. Were DNS over TCP to go into the
/// egress port, the sidecar would read an SNI that does not exist and refuse
/// the query — the container could then resolve no name at all any more.
#[test]
fn the_node_itself_stays_exempt_with_egress() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711)
        .with_egress(tg_net::rules::SIDECAR_EGRESS)
        .outbound_statements();

    let gateway = statements
        .iter()
        .position(|line| line.contains("10.42.1.1"))
        .expect("the exception for the gateway is missing");
    let egress = statements
        .iter()
        .position(|line| line.contains(&tg_net::rules::SIDECAR_EGRESS.to_string()))
        .expect("the egress redirect is missing");

    assert!(gateway < egress, "{statements:#?}");
}

/// The two sidecar ports are **distinct**.
///
/// On the one it terminates TLS, on the other it splices through without
/// terminating. A shared port would force it to guess from the first byte
/// which role is meant.
#[test]
fn the_two_sidecar_ports_are_distinct() {
    assert_ne!(
        tg_net::rules::SIDECAR_OUTBOUND,
        tg_net::rules::SIDECAR_EGRESS
    );
    assert_ne!(
        tg_net::rules::SIDECAR_INBOUND,
        tg_net::rules::SIDECAR_EGRESS
    );
}

// ============ The baseline: out only through the sidecar

/// **Nothing leaves a namespace except through the sidecar.**
///
/// The baseline discards **all** outbound traffic unconditionally, and only
/// the enumerated exceptions may pass — not merely UDP, so a rule set that
/// let TCP past the sidecar would fail this test.
///
/// **The order is half the assurance.** Every exception has to stand
/// **before** the discard, otherwise it is without effect — that applies to
/// the resolver (otherwise no container resolves a name any more), to the
/// redirect's target and to the sidecar's identifier.
#[test]
fn nothing_leaves_a_namespace_except_through_the_sidecar() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711).filter_out_statements();

    let drop = statements
        .iter()
        .position(|line| line.contains("drop"))
        .unwrap_or_else(|| panic!("no discarding rule: {statements:#?}"));

    // **And it discards unconditionally**: the last rule must match nothing,
    // otherwise there would be a way past it.
    assert!(
        !statements[drop].contains("\"match\""),
        "the discarding rule is tied to a condition — then there is a way past \
         it: {}",
        statements[drop]
    );

    for (what, needle) in [
        ("the resolver (ADR-0013)", subnet().gateway().to_string()),
        ("the redirect's target (ADR-0060)", "127.0.0.0".to_owned()),
        ("the sidecar's identifier (ADR-0093)", "skuid".to_owned()),
    ] {
        let position = statements
            .iter()
            .position(|line| line.contains(&needle))
            .unwrap_or_else(|| panic!("{what} is not excepted: {statements:#?}"));
        assert!(
            position < drop,
            "{what} stands behind the drop and is thereby without effect: {statements:#?}"
        );
    }
}

/// **And nothing enters a namespace except over the sidecar.**
///
/// The mTLS **server** side is authoritative for authorization, and without a
/// sidecar there is no authorization — so a workload without a sidecar is not
/// reachable either.
///
/// The exception for `established` carries more than it looks: without it the
/// **sidecar would not get its own answers**, and the error would look like a
/// network problem.
#[test]
fn nothing_enters_a_namespace_except_through_the_sidecar() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711).filter_in_statements();

    let drop = statements
        .iter()
        .position(|line| line.contains("drop"))
        .unwrap_or_else(|| panic!("no discarding rule: {statements:#?}"));

    assert!(
        !statements[drop].contains("\"match\""),
        "the discarding rule is tied to a condition: {}",
        statements[drop]
    );

    for (what, needle) in [
        ("answers to what is permitted", "established".to_owned()),
        (
            "the sidecar's port",
            tg_net::rules::SIDECAR_INBOUND.to_string(),
        ),
        ("the resolver (ADR-0013)", subnet().gateway().to_string()),
    ] {
        let position = statements
            .iter()
            .position(|line| line.contains(&needle))
            .unwrap_or_else(|| panic!("{what} is not excepted: {statements:#?}"));
        assert!(
            position < drop,
            "{what} stands behind the drop: {statements:#?}"
        );
    }
}

/// **ICMP is discarded along from here on** — and that is a deliberate change
/// from an earlier design that allowed `ping` unconditionally, on the
/// reasoning that it carries no payload that demands authorization and is the
/// tool an operator uses to check a network. That reasoning held as long as
/// the chain discarded only **UDP** and let everything else through.
///
/// The chain now discards unconditionally, and the exceptions are enumerated.
/// A baseline that reads "everything except through the sidecar" cannot make
/// an exception for a protocol that does not pass through the sidecar —
/// otherwise it would be a perimeter with a hole again.
///
/// **What remains:** `ping` to our own node. That is the exception for the
/// resolver, and it carries every protocol — an operator still checks with it
/// whether the instance hangs on the network.
///
/// The old test is thereby replaced and not lost; it was called
/// `icmp_is_not_dropped` and stood for the decision superseded here.
#[test]
fn icmp_reaches_the_node_and_nothing_else() {
    let statements = NetnsRules::new(&cluster(), &subnet(), 4711).filter_out_statements();

    // There is **no** ICMP-specific exception any more ...
    assert!(
        !statements.iter().any(|line| line.contains("icmp")),
        "an ICMP-specific rule would be a hole in the baseline: {statements:#?}"
    );

    // ... and the exception for the node names no protocol, so it carries ICMP
    // too. **That is the counter-check**: without it this test would be green
    // for a rule set that no longer permits `ping` at all.
    let gateway = statements
        .iter()
        .find(|line| line.contains(&subnet().gateway().to_string()))
        .unwrap_or_else(|| panic!("the node is not excepted: {statements:#?}"));
    assert!(
        !gateway.contains("l4proto"),
        "the exception for the node is tied to a protocol — then `ping` no \
         longer reaches it: {gateway}"
    );
}

/// **What is discarded is counted.**
///
/// Discarding happens without ICMP: an operator sees **silence**, and silence
/// is the most expensive diagnosis. The counter is the only place at which "my
/// workload does not reach its target" can be told apart from a network problem
/// without giving the container a channel.
///
/// # Why the order counts
///
/// The counter has to stand **before** the discard. `nft` executes a rule's
/// statements in order, and after a `drop` none follows — a counter after it
/// would never count. The same trap as with the order of redirect rules,
/// only within one rule.
#[test]
fn a_dropped_packet_is_counted() {
    for statements in [
        NetnsRules::new(&cluster(), &subnet(), 4711).filter_out_statements(),
        NetnsRules::new(&cluster(), &subnet(), 4711).filter_in_statements(),
    ] {
        let line = statements
            .iter()
            .find(|line| line.contains("drop"))
            .unwrap_or_else(|| panic!("no discarding rule: {statements:#?}"));

        let counter = line
            .find("counter")
            .unwrap_or_else(|| panic!("the discarding rule does not count: {line}"));
        let drop = line.find("drop").expect("found above");
        assert!(
            counter < drop,
            "the counter has to stand **before** the discard — after it, it \
             never counts: {line}"
        );
    }
}

/// **The baseline does not carry the redirect.**
///
/// That is the separation at issue: the filters may lie early, because they
/// need no listener; the redirect may **not**, for a redirection without
/// anybody listening would take every connection from the workload and would
/// look like a network problem.
///
/// Both directions, and the second carries half the assurance: without it a
/// `render()` that **never** lays the redirect would be just as green — and no
/// mesh traffic would ever find its sidecar.
#[test]
fn the_baseline_carries_the_filters_but_not_the_redirect() {
    let rules =
        NetnsRules::new(&cluster(), &subnet(), 4711).with_egress(tg_net::rules::SIDECAR_EGRESS);

    let baseline = tg_net::rules::to_json(&rules.render_baseline()).expect("JSON");
    assert!(
        baseline.contains("drop"),
        "the baseline does not discard: {baseline}"
    );
    assert!(
        !baseline.contains("redirect"),
        "the baseline carries a redirection before anybody listens: {baseline}"
    );

    let full = tg_net::rules::to_json(&rules.render()).expect("JSON");
    assert!(
        full.contains("redirect") && full.contains("drop"),
        "the full rule set has to carry both: {full}"
    );
}

// ============================================= QUIC outwards

/// **Without a QUIC permission nothing redirects UDP.**
///
/// The default, and it is half the assurance: the discard then applies to all
/// UDP except to the node. Without this test a rule that always arises would
/// be just as green — and it would take the discard's counter from it.
#[test]
fn without_a_quic_permission_no_udp_is_redirected() {
    let rules = NetnsRules::new(&cluster(), &subnet(), tg_model::mesh::SIDECAR_UID);
    let statements = rules.outbound_statements();

    assert!(
        !statements.iter().any(|rule| rule.contains("udp")),
        "without a permission no UDP redirection may arise: {statements:?}"
    );
}

/// **One redirection per permitted port — and without a port setting.**
///
/// Without a port setting the redirect keeps the container's port; only that
/// way does the sidecar learn over `IP_RECVORIGDSTADDR` where it wanted to
/// go. With a port setting the ancillary message carries, measured, the port
/// **after** the DNAT.
#[test]
fn each_permitted_quic_port_gets_a_redirect_without_a_port() {
    let rules = NetnsRules::new(&cluster(), &subnet(), tg_model::mesh::SIDECAR_UID)
        .with_quic(&[443, 8443, 443]);
    let statements = rules.outbound_statements();

    let udp: Vec<&String> = statements
        .iter()
        .filter(|rule| rule.contains("udp"))
        .collect();

    assert_eq!(udp.len(), 2, "one port twice yields one rule: {udp:?}");
    for rule in udp {
        assert!(
            rule.contains("\"redirect\":null"),
            "the redirection names a port — then the original target is lost \
             (ADR-0094): {rule}"
        );
    }
}

// ================================ Plain UDP by address

/// **Without a permission no UDP goes out** — the counter-check to everything
/// else.
#[test]
fn without_a_udp_permission_no_address_is_accepted() {
    let rules = NetnsRules::new(&cluster(), &subnet(), 65532);

    assert!(
        !rules
            .filter_out_statements()
            .iter()
            .any(|rule| rule.contains("\"udp\"")),
        "without a permission no UDP rule may arise: {:?}",
        rules.filter_out_statements()
    );
}

/// Every permitted address gets its rule — **address and port together**.
///
/// Only the address would mean permitting every service on that machine; only
/// the port would mean permitting it everywhere. The name from which both
/// come stands in the permission.
#[test]
fn each_permitted_address_gets_its_own_rule() {
    let rules = NetnsRules::new(&cluster(), &subnet(), 65532).with_udp(&[
        ("203.0.113.7".parse().expect("address"), 123),
        ("198.51.100.9".parse().expect("address"), 514),
    ]);

    let out = rules.filter_out_statements();
    for (address, port) in [("203.0.113.7", 123), ("198.51.100.9", 514)] {
        assert!(
            out.iter().any(|rule| rule.contains(address)
                && rule.contains(&port.to_string())
                && rule.contains("accept")),
            "no rule for {address}:{port}: {out:?}"
        );
    }
}

/// **Before the discard**, otherwise the permission is without effect.
///
/// `nft` executes a chain's rules in order; after the unconditional `drop`
/// none follows. A permission behind it would look from outside like none —
/// and the counter at the discarding rule would point at it.
#[test]
fn a_udp_permission_stands_before_the_drop() {
    let rules = NetnsRules::new(&cluster(), &subnet(), 65532)
        .with_udp(&[("203.0.113.7".parse().expect("address"), 123)]);

    let out = rules.filter_out_statements();
    let allowed = out
        .iter()
        .position(|rule| rule.contains("203.0.113.7"))
        .expect("the permission stands");
    let dropped = out
        .iter()
        .position(|rule| rule.contains("drop"))
        .expect("the discarding rule stands");

    assert!(
        allowed < dropped,
        "the permission stands behind the discard and is thereby without effect: {out:?}"
    );
}

/// And it applies to UDP **only**: the same machine over TCP stays at the
/// sidecar.
#[test]
fn a_udp_permission_does_not_open_tcp() {
    let rules = NetnsRules::new(&cluster(), &subnet(), 65532)
        .with_udp(&[("203.0.113.7".parse().expect("address"), 123)]);

    let rule = rules
        .filter_out_statements()
        .into_iter()
        .find(|rule| rule.contains("203.0.113.7"))
        .expect("the permission stands");

    assert!(
        rule.contains("\"udp\""),
        "a permission without a protocol opens TCP too: {rule}"
    );
}

// ================================ UDP in the mesh

/// **Without peers no redirection** — the default, and it is half the
/// assurance.
///
/// Without this witness a rule set that always lays a redirection would be
/// green too: then nothing would die at the discarding rule any more, and its
/// counter would count nothing.
#[test]
fn without_mesh_peers_no_udp_is_redirected_into_the_cluster() {
    let rules = NetnsRules::new(&cluster(), &subnet(), tg_model::mesh::SIDECAR_UID);

    assert!(
        !rules
            .outbound_statements()
            .iter()
            .any(|rule| rule.contains("udp")),
        "without peers no mesh UDP redirection may arise"
    );
}

/// **One redirection per peer — and this time *with* a port setting.**
///
/// The difference from the QUIC egress beside it is the whole point: there
/// the redirect keeps the port, **because it is the information**. Here it is
/// not — the information would be the destination address, and with UDP that
/// survives no redirect (measured: `IP_RECVORIGDSTADDR` names `127.0.0.1`
/// afterwards). So the local port carries **which** peer was meant, and for
/// that every one needs its own.
#[test]
fn each_mesh_peer_gets_its_own_local_port() {
    let peers = [
        ("10.42.1.5".parse().expect("address"), 15100),
        ("10.42.2.7".parse().expect("address"), 15101),
        // Named twice — one rule.
        ("10.42.1.5".parse().expect("address"), 15100),
    ];
    let rules =
        NetnsRules::new(&cluster(), &subnet(), tg_model::mesh::SIDECAR_UID).with_mesh_udp(&peers);

    let statements = rules.outbound_statements();
    let udp: Vec<&String> = statements
        .iter()
        .filter(|rule| rule.contains("udp"))
        .collect();

    assert_eq!(udp.len(), 2, "one peer twice yields one rule: {udp:?}");
    assert!(
        udp.iter()
            .any(|rule| rule.contains("10.42.1.5") && rule.contains("15100")),
        "the rule has to name peer and local port: {udp:?}"
    );
    for rule in &udp {
        assert!(
            !rule.contains("\"redirect\":null"),
            "without a port setting every peer would land on the same listener, \
             and which one was meant would be lost: {rule}"
        );
    }
}

/// **The mesh redirection stands before the QUIC egress one — and behind the
/// exception for the sidecar.**
///
/// # Which order really counts
///
/// Not the one to the **egress** redirect: it carries `l4proto == tcp` and
/// cannot hit a datagram at all. This witness's first attempt checked exactly
/// that and was red although nothing was broken — an asserted order that the
/// matter does not demand.
///
/// What counts is the one to the **QUIC egress** redirection, for that is UDP
/// too: a peer in the cluster on a port that is permitted outwards (`:443`,
/// say) would otherwise go out instead of into the mesh — and the egress way
/// splices by an SNI that a QUIC datagram in the mesh does not carry.
///
/// And behind the exception for the sidecar, otherwise its own call would
/// redirect back onto itself.
#[test]
fn the_mesh_udp_redirect_comes_before_the_quic_egress_one() {
    let rules = NetnsRules::new(&cluster(), &subnet(), tg_model::mesh::SIDECAR_UID)
        .with_quic(&[443])
        .with_mesh_udp(&[("10.42.1.5".parse().expect("address"), 15100)]);
    let statements = rules.outbound_statements();

    let own = statements
        .iter()
        .position(|rule| rule.contains("skuid"))
        .expect("the exception for the sidecar");
    let mesh = statements
        .iter()
        .position(|rule| rule.contains("10.42.1.5"))
        .expect("the mesh redirection");
    let quic = statements
        .iter()
        .position(|rule| rule.contains("\"redirect\":null"))
        .expect("the QUIC egress redirection");

    assert!(
        own < mesh,
        "the sidecar has to stand before the redirection"
    );
    assert!(
        mesh < quic,
        "a peer in the cluster on a port permitted outwards would otherwise go \
         out instead of into the mesh: {statements:?}"
    );
}
