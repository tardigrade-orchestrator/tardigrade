//! The sidecar coupling (ADR-0007, ADR-0009, ADR-0025 — phase 8a).
//!
//! A workload that takes part in the mesh gets a sidecar. The sidecar is no
//! appendage but a **unit of its own** in the same graph: it is placed, started
//! and stopped like any other workload. Precisely that is why it is derived as
//! such here and sent through the same validation — a derived unit that
//! violates the schema would be one nobody has ever seen until it stands out in
//! operation.

use tg_defs::{ImageExt as _, PlacementExt, WorkloadExt, from_str};
use tg_model::mesh::{MeshError, SidecarSpec, expand, members, sidecar_name};
use tg_model::{DependencyGraph, Inactivity};

const PROXY: &str = "registry.example.com/tg-proxy:1.0";

/// **Not `cluster.local`**, and that is deliberate: the sidecar's default is
/// exactly the value that would apply silently without this setting. A fixture
/// with the default could not show that the line really comes from the node.
const DOMAIN: &str = "acme.internal";

fn spec() -> SidecarSpec {
    SidecarSpec::new(PROXY, DOMAIN).expect("image reference")
}

fn definition(body: &str) -> Vec<tg_defs::generated::WorkloadType> {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n{body}</workloads>\n"
    );

    from_str(&xml)
        .expect("a valid definition")
        .workloads()
        .to_vec()
}

fn one_member() -> Vec<tg_defs::generated::WorkloadType> {
    definition(
        "  <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n",
    )
}

/// **Whoever has no mesh element does not take part** (ADR-0025) — and
/// consequently gets no sidecar either.
#[test]
fn only_declared_members_get_a_sidecar() {
    let workloads = definition(
        "  <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n\
         \x20 <workload name=\"batch\" kind=\"job\">\n\
         \x20   <image reference=\"registry.example.com/batch:1.0\"/>\n\
         \x20 </workload>\n",
    );

    assert_eq!(members(&workloads), vec!["api"]);

    let expanded = expand(&workloads, &spec()).expect("derivable");
    let names: Vec<&str> = expanded.iter().map(WorkloadExt::name).collect();

    assert_eq!(names, vec!["api", "api-proxy", "batch"]);
}

/// The derived name is deterministic — it has to be the same on every node,
/// otherwise an edge points into the void.
#[test]
fn the_derived_name_is_deterministic() {
    assert_eq!(sidecar_name("api"), "api-proxy");
    assert_eq!(sidecar_name("ledger-write"), "ledger-write-proxy");
}

/// **The sidecar is `bindsTo` + `after` of its workload** (ADR-0009), and the
/// effect is checked at the graph, not at the edges.
///
/// An edge that stands only in the document is a claim. What counts is the
/// start order and the cascade.
#[test]
fn the_sidecar_starts_after_its_workload_and_stops_with_it() {
    let expanded = expand(&one_member(), &spec()).expect("derivable");
    let graph = DependencyGraph::from_workloads(&expanded).expect("graph");

    let order = graph.start_order();
    let workload = order.iter().position(|name| *name == "api").expect("api");
    let sidecar = order
        .iter()
        .position(|name| *name == "api-proxy")
        .expect("api-proxy");
    assert!(
        workload < sidecar,
        "the sidecar has nothing to proxy as long as the workload is not running: {order:?}"
    );

    let stopped = graph.cascade_stop(&[("api", Inactivity::Stopped)]);
    assert!(
        stopped.contains("api-proxy"),
        "a sidecar without its workload is pointless and has to go along"
    );
}

/// The coupling does **not** go in the other direction: the workload does not
/// hang on the sidecar.
///
/// That is deliberate and no oversight. A workload that the failure of its
/// sidecar dragged along would be less available than one without a mesh — and
/// ADR-0019 decouples workload availability precisely from everything that lies
/// above it. Reachable it is nevertheless not without a sidecar: the traffic is
/// directed through it in phase 9, so there is no way past it.
#[test]
fn the_workload_does_not_depend_on_its_sidecar() {
    let expanded = expand(&one_member(), &spec()).expect("derivable");
    let graph = DependencyGraph::from_workloads(&expanded).expect("graph");

    let stopped = graph.cascade_stop(&[("api-proxy", Inactivity::Failed)]);

    assert!(
        !stopped.contains("api"),
        "the sidecar's failure must not drag the workload along (ADR-0019)"
    );
}

/// The sidecar inherits its workload's placement — it has to run on the same
/// node, otherwise it proxies over the network to a loopback port that does not
/// exist there.
#[test]
fn the_sidecar_is_pinned_to_the_same_node_as_its_workload() {
    let workloads = definition(
        "  <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20   <placement><pin node=\"node-7\"/></placement>\n\
         \x20 </workload>\n",
    );

    let expanded = expand(&workloads, &spec()).expect("derivable");
    let sidecar = expanded
        .iter()
        .find(|workload| workload.name() == "api-proxy")
        .expect("sidecar");

    assert_eq!(
        sidecar.placement().and_then(PlacementExt::pin),
        Some("node-7"),
        "the sidecar has to go where its workload is"
    );
}

/// **The derived unit is self-contained:** it carries what it proxies for,
/// where it passes through to and where it reads its settings from.
///
/// Without that the sidecar process would have to look up its own definition —
/// and would hang on a source that can be gone in a partition (ADR-0019).
///
/// The four paths are **container-side** (ADR-0059, determination 5): they lie
/// in a file system we build and are therefore the same on every node. What
/// lies behind them on the node is mounted by the agent.
#[test]
fn the_sidecar_carries_what_it_proxies_and_where_to() {
    let expanded = expand(&one_member(), &spec()).expect("derivable");
    let sidecar = expanded
        .iter()
        .find(|workload| workload.name() == "api-proxy")
        .expect("sidecar");

    assert_eq!(
        sidecar.command(),
        vec![
            tg_model::mesh::PROGRAM_IN_CONTAINER,
            "--workload",
            "api",
            "--upstream-port",
            "8443",
            "--socket",
            tg_model::mesh::SOCKET_IN_CONTAINER,
            "--policy",
            tg_model::mesh::EDGES_IN_CONTAINER,
            "--egress",
            tg_model::mesh::EGRESS_IN_CONTAINER,
            "--active-role",
            tg_model::mesh::ROLE_IN_CONTAINER,
            "--listen",
            "0.0.0.0:15006",
            "--mesh-listen",
            "0.0.0.0:15001",
            "--egress-listen",
            "0.0.0.0:15002",
            // **The node's trust domain** and not the sidecar's default. It
            // did not stand here, and that was a hole: the sidecar searches for
            // its anchor with it, took `cluster.local` without the line and
            // ended in every cluster with a different domain with "no anchor
            // for cluster.local" — the only setting an operator does **not**
            // reach by hand, because this line is fixed (ADR-0059).
            "--trust-domain",
            DOMAIN,
        ]
    );
}

/// **All three ports stand in the line** — and each means a chain in the rule
/// set (ADR-0012, ADR-0041, ADR-0060).
///
/// The outgoing mesh port was **missing** here for a time, with a test of its
/// own that recorded the absence as a statement: behind a redirect it no longer
/// stood there which peer was meant. ADR-0060 decided it — the setting comes
/// from the kernel —, and with that the gap becomes a line.
#[test]
fn the_call_line_names_all_three_redirect_ports() {
    let expanded = expand(&one_member(), &spec()).expect("derivable");
    let sidecar = expanded
        .iter()
        .find(|workload| workload.name() == "api-proxy")
        .expect("sidecar");

    let command = sidecar.command();
    for (flag, port) in [
        ("--listen", "15006"),
        ("--mesh-listen", "15001"),
        ("--egress-listen", "15002"),
    ] {
        let at = command
            .iter()
            .position(|arg| *arg == flag)
            .unwrap_or_else(|| panic!("{flag} is missing from {command:?}"));
        assert!(
            command[at + 1].ends_with(port),
            "{flag} does not point at {port}: {command:?}"
        );
    }
}

/// The sidecar is itself **no** mesh member. Otherwise it would get a sidecar,
/// and that one another.
#[test]
fn a_sidecar_is_not_itself_a_mesh_member() {
    let expanded = expand(&one_member(), &spec()).expect("derivable");
    let sidecar = expanded
        .iter()
        .find(|workload| workload.name() == "api-proxy")
        .expect("sidecar");

    assert!(sidecar.mesh().is_none());

    // And the derivation is idempotent: a second run adds nothing.
    let twice = expand(&expanded, &spec()).expect("derivable");
    assert_eq!(twice.len(), expanded.len());
}

/// A name that is already taken is **reported**, not overwritten.
///
/// Without this check a derivation would silently replace a hand-written
/// definition — and the operator would see their workload vanish without an
/// error standing anywhere.
#[test]
fn a_name_collision_is_reported_instead_of_overwriting() {
    let workloads = definition(
        "  <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n\
         \x20 <workload name=\"api-proxy\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/something:1.0\"/>\n\
         \x20 </workload>\n",
    );

    let err = expand(&workloads, &spec()).expect_err("the collision has to stand out");

    assert!(
        matches!(err, MeshError::NameTaken { .. }),
        "wrong error: {err}"
    );
    assert!(err.to_string().contains("api-proxy"));
}

/// A name whose derived form no longer fits the schema is refused at ingest —
/// not shortened.
///
/// Shortening would be the worse choice: two long names that differ only in the
/// last character would yield the same sidecar.
#[test]
fn a_name_that_no_longer_fits_the_schema_is_refused() {
    let long = "a".repeat(60);
    let workloads = definition(&format!(
        "  <workload name=\"{long}\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n"
    ));

    let err = expand(&workloads, &spec()).expect_err("too long");

    assert!(
        matches!(err, MeshError::NameTooLong { .. }),
        "wrong error: {err}"
    );
}

/// The derived sidecar is **schema-valid**. It goes through the same loader as
/// a hand-written definition.
///
/// That is the actual reason why the derivation runs over XML and not over
/// hand-built structures: a derived unit that violates the schema would
/// otherwise stand out only in operation.
#[test]
fn the_derived_sidecar_passes_the_same_validation_as_a_written_one() {
    let expanded = expand(&one_member(), &spec()).expect("derivable");
    let sidecar = expanded
        .iter()
        .find(|workload| workload.name() == "api-proxy")
        .expect("sidecar");

    let xml = tg_defs::workload_to_xml(sidecar).expect("serializable");
    let back = from_str(&xml).expect("and readable again");

    assert_eq!(back.workloads()[0].name(), "api-proxy");
    assert_eq!(
        back.workloads()[0].image().reference(),
        PROXY,
        "the sidecar runs from the configured proxy image"
    );
}

/// A proxy image the schema does not accept stands out when the configuration
/// is set up — not at the first workload that uses it.
#[test]
fn an_unusable_proxy_image_is_refused_when_the_spec_is_built() {
    assert!(SidecarSpec::new("", DOMAIN).is_err());
    assert!(SidecarSpec::new("x".repeat(513), DOMAIN).is_err());
}

/// And the same for the trust domain.
///
/// It goes into an `<arg>` line; an XML special character in it would yield a
/// document the loader no longer reads — and the error would show up as a
/// schema violation on a **derived** unit nobody wrote.
#[test]
fn an_unusable_trust_domain_is_refused_when_the_spec_is_built() {
    assert!(SidecarSpec::new(PROXY, "").is_err());
    assert!(SidecarSpec::new(PROXY, "x".repeat(256)).is_err());
    assert!(SidecarSpec::new(PROXY, "a<b").is_err());
    assert!(SidecarSpec::new(PROXY, DOMAIN).is_ok());
}

// --------------------------------------------------------------- Delegation

/// **The derived sidecar gets its workload's identity delegated** (ADR-0036).
#[test]
fn a_derived_sidecar_is_delegated_its_workloads_identity() {
    use tg_model::mesh::delegations;

    let expanded = expand(&one_member(), &spec()).expect("derivable");
    let map = delegations(&expanded, &spec());

    assert_eq!(map.get("api-proxy").map(String::as_str), Some("api"));
    assert_eq!(map.len(), 1, "and nobody else");
}

/// **The name alone delegates nothing.**
///
/// That is the attack against which ADR-0036 bound the mapping to the desired
/// state instead of to the name suffix: a hand-written workload called
/// `…-proxy` does not speak for the workload before it.
#[test]
fn a_hand_written_workload_named_like_a_sidecar_gets_nothing() {
    use tg_model::mesh::delegations;

    let workloads = definition(
        "  <workload name=\"stranger\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/stranger:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n\
         \x20 <workload name=\"stranger-proxy\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/attacker:1.0\"/>\n\
         \x20 </workload>\n",
    );

    assert!(
        delegations(&workloads, &spec()).is_empty(),
        "neither the proxy image nor the edges — so no sidecar"
    );
}

/// The right image does not suffice either: **both edges** have to be there.
///
/// They are what bind the sidecar to its workload (ADR-0009). Without them the
/// candidate is a workload that happens to use the same image.
#[test]
fn the_proxy_image_alone_does_not_delegate() {
    use tg_model::mesh::delegations;

    let workloads = definition(&format!(
        "  <workload name=\"stranger\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/stranger:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n\
         \x20 <workload name=\"stranger-proxy\" kind=\"service\">\n\
         \x20   <image reference=\"{PROXY}\"/>\n\
         \x20   <dependencies><after ref=\"stranger\"/></dependencies>\n\
         \x20 </workload>\n"
    ));

    assert!(
        delegations(&workloads, &spec()).is_empty(),
        "`after` alone is no binding — `bindsTo` is missing"
    );
}

/// **A target that does not take part in the mesh delegates nothing** — even if
/// somebody writes a complete-looking sidecar for it.
///
/// Without this condition a workload could give itself a sidecar without its
/// target ever having become a mesh member — and thereby receive that one's
/// identity without anything having been declared at the target.
#[test]
fn a_target_outside_the_mesh_delegates_nothing() {
    use tg_model::mesh::delegations;

    let workloads = definition(&format!(
        "  <workload name=\"stranger\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/stranger:1.0\"/>\n\
         \x20 </workload>\n\
         \x20 <workload name=\"stranger-proxy\" kind=\"service\">\n\
         \x20   <image reference=\"{PROXY}\"/>\n\
         \x20   <dependencies>\n\
         \x20     <after ref=\"stranger\"/>\n\
         \x20     <bindsTo ref=\"stranger\"/>\n\
         \x20   </dependencies>\n\
         \x20 </workload>\n"
    ));

    assert!(
        delegations(&workloads, &spec()).is_empty(),
        "`stranger` declared no <mesh> — there is nothing to delegate"
    );
}

/// **Who is affected stands at the sidecar — not in the file** (ADR-0066,
/// determination 2).
///
/// That is the difference between fail-closed and fail-open: were the
/// affectedness to stand in the active-role file, a missing file would mean
/// "nobody is affected", and a read error would lift the active role for
/// everyone. This way it means "no active role".
#[test]
fn only_a_single_writer_carries_the_active_role_flag() {
    let single = definition(
        "  <workload name=\"api\" kind=\"service\" class=\"single-writer\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n",
    );
    let expanded = expand(&single, &spec()).expect("derivable");
    let sidecar = expanded
        .iter()
        .find(|workload| workload.name() == "api-proxy")
        .expect("sidecar");

    assert!(
        sidecar.command().contains(&"--single-writer"),
        "{:?}",
        sidecar.command()
    );

    // The counter-check, and it is half the assurance: without it a version
    // that reins **every** sidecar in would be green too — and then every
    // replicated workload would stand still as soon as nobody granted it a
    // lease.
    let replicated = expand(&one_member(), &spec()).expect("derivable");
    let plain = replicated
        .iter()
        .find(|workload| workload.name() == "api-proxy")
        .expect("sidecar");

    assert!(
        !plain.command().contains(&"--single-writer"),
        "a replicated workload has no active role: {:?}",
        plain.command()
    );
}

/// **The pinning stands at the node, not at the workload** (ADR-0114,
/// determination 3).
///
/// The counter-check is the actual assurance here: the default is **off**. A
/// version that always pinned would be green if only the positive case were
/// checked — and it would take from every sidecar the possibility of moving
/// aside from an occupied core, on every node nobody has partitioned.
///
/// That the setting hangs on the `SidecarSpec` and not on the declaration is
/// the core: **the same** workload yields two different invocation lines on two
/// differently configured nodes, and precisely that is wanted — whether a
/// machine has partitioned its CPUs no XML knows.
#[test]
fn only_a_node_that_asks_for_it_pins_its_sidecar_shards() {
    let plain = expand(&one_member(), &spec()).expect("derivable");
    let unpinned = plain
        .iter()
        .find(|workload| workload.name() == "api-proxy")
        .expect("sidecar");

    assert!(
        !unpinned.command().contains(&"--pin-shards"),
        "the default is off (ADR-0114 D3): {:?}",
        unpinned.command()
    );

    let pinned_spec = SidecarSpec::new(PROXY, DOMAIN)
        .expect("image reference")
        .pinned_shards(true);
    let pinned = expand(&one_member(), &pinned_spec).expect("derivable");
    let sidecar = pinned
        .iter()
        .find(|workload| workload.name() == "api-proxy")
        .expect("sidecar");

    assert!(
        sidecar.command().contains(&"--pin-shards"),
        "{:?}",
        sidecar.command()
    );
}

/// **The derived unit is itself never a single writer** — otherwise it would
/// never start.
///
/// The place is inconspicuous and carries a lot. `tg_model::lease::role_of`
/// reins instance 0 of a single writer in to an active-role lease (ADR-0064);
/// those are granted only for workloads that stand in the log. The sidecar does
/// **not** stand there: it arises on the node (ADR-0059). Were it to inherit
/// the class, it would wait for a lease nobody ever grants — and a single
/// writer with `<mesh>` would forever have a sidecar in the state "waiting".
///
/// That the unit does not inherit the class today is a consequence of `build`
/// not writing it. That is exactly the sort of silent property that gets lost
/// at the next "the derived unit should mirror its workload".
#[test]
fn the_derived_sidecar_is_never_a_single_writer() {
    let single = definition(
        "  <workload name=\"api\" kind=\"service\" class=\"single-writer\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n",
    );
    let expanded = expand(&single, &spec()).expect("derivable");

    let workload = expanded
        .iter()
        .find(|entry| entry.name() == "api")
        .expect("workload");
    let sidecar = expanded
        .iter()
        .find(|entry| entry.name() == "api-proxy")
        .expect("sidecar");

    // The counter-check sits in the test itself: the workload **is** one, the
    // sidecar is not. Without the first assurance the test would be green too
    // if the class arrived nowhere.
    assert_eq!(workload.class(), tg_defs::WorkloadClass::SingleWriter);
    assert_eq!(
        sidecar.class(),
        tg_defs::WorkloadClass::Replicated,
        "the sidecar must not wait for a lease that never exists (ADR-0064)"
    );
}

/// **The module head no longer presents the identity question as open**
/// (ADR-0036).
///
/// # Why a test over a piece of documentation
///
/// Because this file's head described the question as **open** for a year and a
/// half although ADR-0036 answers it: *"This file does not decide that … it
/// belongs decided before phase 8b and stands as an open point in the plan."*
/// Phase 8b has long been finished, and the ADR is `accepted`.
///
/// That is the reverse of the case this tree otherwise finds: not an intent
/// that stands there as a fact, but a **decision that stands there as a
/// question**. It costs the same — a reader took the name suffix for a possibly
/// security-relevant property while the file assures the opposite two hundred
/// lines further on (four conditions in [`tg_model::mesh::delegations`], the
/// suffix is one of them).
///
/// The same construction as the guard over the Raft port in `tg-consensus`: it
/// demands the assurance that **applies**, and that the old sentence does not
/// come back.
#[test]
fn the_module_head_does_not_present_a_decided_question_as_open() {
    let source = include_str!("../src/mesh.rs");
    let head: String = source
        .lines()
        .take_while(|line| line.starts_with("//!") || line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    // Without this assurance the test would check nothing as soon as the head
    // looks different: an empty text contains no false claim.
    assert!(
        head.len() > 500,
        "the module head was not read: {} characters",
        head.len()
    );

    // The assurance that applies — in its substance and not at a common word
    // (the finding at the Raft port guard).
    for promise in [
        "ADR-0036",
        "delegated SVID",
        "address and not the credential",
    ] {
        assert!(
            head.contains(promise),
            "the head has to carry the decision ('{promise}' is missing):\n{head}"
        );
    }

    // And the sentences that must not come back. The head **may** describe the
    // tension between ADR-0006 and ADR-0025 — it is the reason why ADR-0036
    // exists. What it must not do is call it open.
    for stale in [
        "An open question that becomes visible here",
        "This file decides that",
        "decided before phase 8b",
        "Both at once does not work",
    ] {
        assert!(
            !head.contains(stale),
            "a withdrawn sentence is back: '{stale}'"
        );
    }
}

/// **The name check names the mesh member, not the name bearer** (ADR-0084,
/// determination 1).
///
/// It is the same rule as in [`tg_model::mesh::expand`], only without a
/// [`SidecarSpec`] — and therefore usable where there is none: in the state
/// machine (which image a sidecar carries is a setting per node, ADR-0059) and
/// in the client.
///
/// The counter-direction is half the assurance: a set without a collision has
/// to carry. Without it a check that refuses everything would be just as green
/// — and no workload would get into the cluster any more.
#[test]
fn a_declared_name_that_blocks_a_derivation_is_a_finding() {
    let clean = definition(
        "  <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n\
         \x20 <workload name=\"harmless\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/harmless:1.0\"/>\n\
         \x20 </workload>\n",
    );
    assert!(
        tg_model::mesh::validate_names(&clean).is_ok(),
        "a set without a collision has to carry"
    );

    let colliding = definition(
        "  <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20   <mesh port=\"8443\"/>\n\
         \x20 </workload>\n\
         \x20 <workload name=\"api-proxy\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/own:1.0\"/>\n\
         \x20 </workload>\n",
    );
    let err = tg_model::mesh::validate_names(&colliding).expect_err("collision");

    // **`api`, not `api-proxy`.** The latter's definition is complete in
    // itself; `api` demands a derivation that cannot take place.
    assert_eq!(
        err.workload(),
        Some("api"),
        "the rejection has to name the mesh member: {err}"
    );
    assert!(
        err.to_string().contains("api-proxy"),
        "and the taken name: {err}"
    );
}

/// **Without a mesh element there is nothing to collide with.**
///
/// A workload `api-proxy` beside an `api` **without** `<mesh>` is an ordinary
/// choice of name — nothing is derived, so it blocks nothing. Without this
/// counter-check a rule that forbade the suffix as such would be just as
/// green.
#[test]
fn the_suffix_alone_is_not_a_collision() {
    let set = definition(
        "  <workload name=\"api\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/api:1.0\"/>\n\
         \x20 </workload>\n\
         \x20 <workload name=\"api-proxy\" kind=\"service\">\n\
         \x20   <image reference=\"registry.example.com/own:1.0\"/>\n\
         \x20 </workload>\n",
    );
    assert!(
        tg_model::mesh::validate_names(&set).is_ok(),
        "without `<mesh>` nothing is derived, so the name blocks nothing"
    );
}

// ------------------------------------------------------- Name form ---
//
// The check stood rebuilt by hand five times in the tree (four crates, two
// variants, four bodies byte for byte the same). What it assures thereby had no
// witness in one place — only one each at its callers, and those checked their
// own version in each case.

/// **The form ADR-0036 gives the name part of a SPIFFE identifier.**
///
/// Both directions, for a check that refuses everything would be just as green
/// for the rejections — and would let no workload start up any more.
#[test]
fn the_spiffe_name_form_holds_in_both_directions() {
    use tg_model::names::{MAX_NAME, is_plausible};

    for good in [
        "a",
        "api",
        "api-proxy",
        "a1",
        "node-11",
        &"a".repeat(MAX_NAME),
    ] {
        assert!(is_plausible(good), "{good:?} has to get through");
    }

    for bad in [
        "",                        // empty
        "1api",                    // a digit as the head
        "-api",                    // a hyphen as the head
        "Api",                     // upper case
        "api_proxy",               // underscore
        "api.example",             // a dot: that is the secret form
        "api/proxy",               // path separator
        "api proxy",               // space
        &"a".repeat(MAX_NAME + 1), // one too many
    ] {
        assert!(!is_plausible(bad), "{bad:?} must not get through");
    }
}

/// **A secret name may carry a dot and nothing more** (ADR-0098).
///
/// The dot is the whole difference from the name form above, and it is the
/// reason why there are **two** functions: `db.password` is an ordinary secret
/// name and no workload.
///
/// What it does **not** open is the path: `.`, `..` and everything with `/`
/// stay excluded — the name becomes a file name at the privileged agent's hand,
/// and a `../etc/passwd` would be an escape as root there.
#[test]
fn a_secret_name_may_carry_a_dot_and_nothing_more() {
    use tg_model::names::{is_plausible, is_plausible_secret};

    for good in ["db.password", "s3.access.key", "api"] {
        assert!(is_plausible_secret(good), "{good:?} has to get through");
    }
    assert!(
        !is_plausible("db.password"),
        "the dot is the difference from the name form — otherwise there would \
         not be two functions"
    );

    for bad in [".", "..", "...", "a/b", "a..b/c", "/etc", "a\0b"] {
        assert!(
            !is_plausible_secret(bad),
            "{bad:?} must not be a secret name"
        );
    }
}

/// **The schema's facet has to fit into the name form.**
///
/// The ordering condition from the head of `tg_model::names`:
///
/// > XSD facet **≤** `MAX_NAME`
///
/// It stood there as a sentence and had no witness with the **real** constant.
/// The neighbour in `tg-defs` (`the_workload_name_fits_a_dns_label`) holds the
/// same relation against a **local** 63 — it has to, for `tg-defs` lies beneath
/// `tg-model` and cannot read `MAX_NAME`. Here it is the other way round: both
/// are reachable, so what really applies is compared here.
///
/// What a skew costs stands in both heads: a workload name that may become
/// longer than a SPIFFE identifier carries yields a container without an SVID
/// (ADR-0006) — and the error shows up at the first connection.
#[test]
fn the_schema_facet_fits_the_spiffe_name_form() {
    let schema = std::fs::read_to_string("../../schema/workload.xsd").expect("schema");

    let start = schema
        .find("<xs:simpleType name=\"WorkloadName\">")
        .expect("the type WorkloadName has to stand in the schema");
    let block = &schema[start..];
    let block = &block[..block.find("</xs:simpleType>").expect("the type ends")];
    let repeats: usize = block
        .lines()
        .find(|line| line.contains("<xs:pattern"))
        .and_then(|line| line.split_once("{0,"))
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(digits, _)| digits.parse().expect("a number"))
        .expect("the pattern has to have the form [..][..]{0,N}");

    // One head character plus N repetitions.
    let longest = 1 + repeats;
    assert!(
        longest <= tg_model::names::MAX_NAME,
        "the facet leaves {longest} characters, a SPIFFE identifier carries {} \
         — such a workload runs and gets no SVID",
        tg_model::names::MAX_NAME
    );

    // And the counter-direction: a name **on** the facet is a valid identifier.
    // Without it the condition would be satisfied by `MAX_NAME = usize::MAX`
    // too, and then it would say nothing about the form.
    assert!(
        tg_model::names::is_plausible(&format!("a{}", "b".repeat(repeats))),
        "a name on the facet has to satisfy the name form"
    );
}
