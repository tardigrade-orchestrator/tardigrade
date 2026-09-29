//! The node's rule set is reconciled, not set once.
//!
//! The comparison is a pure function and therefore needs no kernel: `nft`
//! returns the expressions byte for byte as it got them — measured on all six
//! rules of the node's rule set. This comparison rests exactly on that.
//!
//! What it **cannot** do stands at the function: a rule somebody bends in
//! content without changing count and order stands out to it — one they change
//! while at the same time forging `nft`'s return does not. The rule set is a
//! defence-in-depth layer on top of the identity-based authorization enforced
//! by the mesh sidecar.

use tg_net::ipam::{ClusterNet, NodeSubnet};
use tg_net::rules::{HostRules, is_applied, to_json};

const ZONE: &str = "10.42.0.0/16";

/// Builds the fixture cluster network used by this file's tests.
///
/// # Returns
/// The cluster network for `10.42.0.0/16`, split into `/24` node subnets.
fn cluster() -> ClusterNet {
    ClusterNet::new(ZONE.parse().expect("valid"), 24).expect("valid")
}

/// Builds the fixture node subnet used by this file's tests.
///
/// # Returns
/// Node subnet 1 of the fixture cluster network.
fn subnet() -> NodeSubnet {
    cluster().subnet(1).expect("valid")
}

/// Renders the fixture node's host rule set.
///
/// # Returns
/// The rendered `nftables` ruleset.
fn rendered() -> nftables::schema::Nftables<'static> {
    HostRules::new(&cluster(), &subnet()).render()
}

/// What `nft -j list table inet tardigrade` returns after our rule set was
/// applied — **measured** and held fast here as a string, together with the
/// `handle` numbers the kernel assigns and which must not go into the
/// comparison.
///
/// # Parameters
/// - `rules`: the rendered ruleset to simulate a kernel listing for.
///
/// # Returns
/// The simulated `nft -j list table` JSON output.
fn listed_from(rules: &nftables::schema::Nftables<'_>) -> String {
    let json = to_json(rules).expect("serializable");
    let sent: serde_json::Value = serde_json::from_str(&json).expect("readable");

    // Out of the `add` instructions comes what `nft` reports as state: the same
    // objects without the envelope, plus a `metainfo` and one `handle` each.
    let mut objects = vec![serde_json::json!({
        "metainfo": { "version": "1.1.6", "release_name": "test", "json_schema_version": 1 }
    })];
    let mut handle = 1_u64;
    for object in sent["nftables"].as_array().expect("list") {
        let Some(add) = object.get("add") else {
            continue;
        };
        let mut entry = add.clone();
        if let Some(inner) = entry
            .as_object_mut()
            .and_then(|map| map.values_mut().next())
            && let Some(fields) = inner.as_object_mut()
        {
            fields.insert("handle".to_owned(), serde_json::json!(handle));
            handle += 1;
        }
        objects.push(entry);
    }

    serde_json::json!({ "nftables": objects }).to_string()
}

/// **What was applied counts as applied** — the counter-check to everything
/// else. Without it a comparison that always says `false` would be green: it
/// would let the agent set anew on every pass, and nobody would notice except
/// from the load.
#[test]
fn the_ruleset_we_applied_counts_as_applied() {
    let rules = rendered();

    assert!(is_applied(&rules, &listed_from(&rules)));
}

/// **A `handle` is no deviation.** The kernel assigns them, and they stand in
/// none of our instructions — if they went in, the rule set would drift on every
/// pass.
#[test]
fn kernel_assigned_handles_are_not_drift() {
    let rules = rendered();
    let listed = listed_from(&rules);

    assert!(
        listed.contains("handle"),
        "the fixture has to carry handles"
    );
    assert!(is_applied(&rules, &listed));
}

/// A missing table is the case for whose sake the reconcile exists: an `nft
/// flush ruleset` from some script next door.
#[test]
fn a_missing_table_is_drift() {
    assert!(!is_applied(&rendered(), r#"{"nftables":[]}"#));
}

/// **A removed rule is a deviation.** Exactly one is missing — the rest is
/// right.
#[test]
fn a_removed_rule_is_drift() {
    let rules = rendered();
    let listed = listed_from(&rules);
    let mut parsed: serde_json::Value = serde_json::from_str(&listed).expect("readable");
    let objects = parsed["nftables"].as_array_mut().expect("list");
    let position = objects
        .iter()
        .position(|object| object.get("rule").is_some())
        .expect("at least one rule");
    objects.remove(position);

    assert!(!is_applied(&rules, &parsed.to_string()));
}

/// **An added rule is a deviation.** The table belongs to us; what does not
/// stem from our representation does not belong in it.
#[test]
fn an_added_rule_is_drift() {
    let rules = rendered();
    let listed = listed_from(&rules);
    let mut parsed: serde_json::Value = serde_json::from_str(&listed).expect("readable");
    let objects = parsed["nftables"].as_array_mut().expect("list");
    let extra = objects
        .iter()
        .find(|object| object.get("rule").is_some())
        .cloned()
        .expect("at least one rule");
    objects.push(extra);

    assert!(!is_applied(&rules, &parsed.to_string()));
}

/// **Swapped rules are a deviation**, although count and content are right.
///
/// "The order of the rules is the whole security" — the same statement as with
/// the sidecar rules: the forwarding chain's first rule releases everything that
/// does not touch the bridge, and therefore stands first.
#[test]
fn reordered_rules_are_drift() {
    let rules = rendered();
    let listed = listed_from(&rules);
    let mut parsed: serde_json::Value = serde_json::from_str(&listed).expect("readable");
    let objects = parsed["nftables"].as_array_mut().expect("list");
    let positions: Vec<usize> = objects
        .iter()
        .enumerate()
        .filter(|(_, object)| object.get("rule").is_some())
        .map(|(index, _)| index)
        .collect();
    assert!(positions.len() >= 2, "the test needs two rules");
    objects.swap(positions[0], positions[1]);

    assert!(!is_applied(&rules, &parsed.to_string()));
}

/// An output that cannot be read counts as a deviation — the safe direction:
/// setting anew is idempotent and atomic, doing nothing would be a
/// conjecture.
#[test]
fn unreadable_output_is_drift() {
    assert!(!is_applied(&rendered(), "not JSON"));
}

// ======================================= What `nft` returns is normalized
//
// The two properties stand here as witnesses because the kernel test **cannot**
// show them: there the counter stands at zero, and without traffic a normalized
// counter looks like an unchanged one. Both are measured on a namespace's rule
// set.

/// A counter's value is **state, not form**.
///
/// That is the sharper of the two: if it went into the comparison, the rule set
/// would be deviating after the **first discarded packet** — and the reconcile
/// would set it anew on every pass, forever, without anybody noticing anything
/// other than the load.
#[test]
fn a_counter_that_has_counted_is_not_drift() {
    let rules = tg_net::rules::NetnsRules::new(&cluster(), &subnet(), 65532).render();
    let listed = listed_from(&rules);

    // That is how a counting rule really comes back after it has counted.
    let counted = listed.replace(
        r#""counter":null"#,
        r#""counter":{"bytes":1234567,"packets":4711}"#,
    );
    assert_ne!(counted, listed, "the replacement did not take");

    assert!(
        is_applied(&rules, &counted),
        "a counter with a value must be no deviation"
    );
}

/// A `meta l4proto == P` falls away if a payload of the same protocol stands
/// beside it — `nft` strikes the explicit dependency.
///
/// Without this half the agent set every namespace's rule set anew on every
/// pass: it is sent **with**, it comes back **without**.
#[test]
fn an_elided_protocol_dependency_is_not_drift() {
    let rules = tg_net::rules::NetnsRules::new(&cluster(), &subnet(), 65532).render();
    let listed = listed_from(&rules);

    // `tcp dport 15006` already carries the dependency.
    let elided = listed.replace(
        r#"{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":"tcp"}},{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}}"#,
        r#"{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}}"#,
    );
    assert_ne!(elided, listed, "the replacement did not take");

    assert!(
        is_applied(&rules, &elided),
        "a struck protocol dependency must be no deviation"
    );
}

/// **And the counter-check:** the normalization only takes away what is no
/// deviation. A counter somebody replaces by something else stays one —
/// otherwise the comparison would be blind to counting rules.
#[test]
fn a_counter_replaced_by_something_else_is_still_drift() {
    let rules = tg_net::rules::NetnsRules::new(&cluster(), &subnet(), 65532).render();
    let listed = listed_from(&rules);

    let tampered = listed.replace(r#"{"counter":null},{"drop":null}"#, r#"{"accept":null}"#);
    assert_ne!(tampered, listed, "the replacement did not take");

    assert!(
        !is_applied(&rules, &tampered),
        "turning a discarding counter into an `accept` is a deviation"
    );
}
