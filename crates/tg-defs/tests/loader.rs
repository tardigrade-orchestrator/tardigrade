//! Integration tests of the definition loader (ADR-0008, phase 1).
//!
//! Two axes that map the phase's acceptance criterion:
//!
//! - valid fixtures parse and yield the expected typed values,
//! - invalid fixtures fail **typed** — every facet class of the XSD gets a case
//!   of its own, so that a silent failure of the validation is exposed (see the
//!   comment on the optimizer flag in xtask/src/codegen.rs).

use std::fs;
use std::path::{Path, PathBuf};

use tg_defs::{
    DependencyKind, ImageExt as _, Kind, LoadError, MeshExt, PullPolicy, ResourcesExt as _,
    WorkloadClass, WorkloadExt as _, from_str,
};

fn fixture(kind: &str, name: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(kind)
        .join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("fixture {} missing: {err}", path.display()))
}

// ------------------------------------------------------------------ valid ---

/// **The element is the opt-in** (ADR-0025): whoever does not have it does not
/// participate. There is no `enabled="false"` — a switch one can flip would be
/// a second way of saying the same thing.
#[test]
fn mesh_membership_is_the_presence_of_the_element() {
    let set = from_str(&fixture("valid", "mesh.xml")).expect("mesh.xml must parse");

    let api = &set.workloads()[0];
    assert_eq!(api.name(), "api");
    assert_eq!(
        api.mesh().map(MeshExt::port),
        Some(8443),
        "the port is the only setting the sidecar needs"
    );

    let batch = &set.workloads()[1];
    assert_eq!(batch.name(), "batch");
    assert!(
        batch.mesh().is_none(),
        "without the element no participation (ADR-0025)"
    );
}

#[test]
fn minimal_definition_parses_with_expected_values() {
    let set = from_str(&fixture("valid", "minimal.xml")).expect("minimal.xml must parse");

    assert_eq!(set.workloads().len(), 1);

    let workload = &set.workloads()[0];
    assert_eq!(workload.name(), "api");
    assert_eq!(workload.kind(), Kind::Service);
    assert_eq!(
        workload.image().reference(),
        "registry.example.com/api:1.4.2"
    );
    assert!(workload.resources().is_none());
    assert!(workload.dependencies().is_empty());
}

#[test]
fn optional_pull_policy_defaults_to_none_when_absent() {
    let set = from_str(&fixture("valid", "minimal.xml")).expect("minimal.xml must parse");

    assert_eq!(set.workloads()[0].image().pull_policy(), None);
}

#[test]
fn full_definition_parses_resources_and_pull_policy() {
    let set = from_str(&fixture("valid", "full.xml")).expect("full.xml must parse");

    assert_eq!(set.workloads().len(), 2);

    let db = &set.workloads()[0];
    assert_eq!(db.name(), "db");
    assert_eq!(db.image().pull_policy(), Some(PullPolicy::IfNotPresent));

    let resources = db.resources().expect("db has resources");
    assert_eq!(resources.millicores(), Some(2000));
    assert_eq!(resources.memory_bytes(), Some(4_294_967_296));

    let api = &set.workloads()[1];
    assert_eq!(api.image().pull_policy(), Some(PullPolicy::Always));
}

/// All six edge kinds from ADR-0009 must survive — and separated by axis.
/// Ordering and requirement must not be mixed; that is precisely the point of
/// the decision.
#[test]
fn all_six_dependency_kinds_survive_the_round_trip() {
    let set = from_str(&fixture("valid", "full.xml")).expect("full.xml must parse");
    let deps = set.workloads()[1].dependencies();

    let found: Vec<(DependencyKind, &str)> =
        deps.iter().map(|dep| (dep.kind(), dep.target())).collect();

    assert_eq!(
        found,
        vec![
            (DependencyKind::After, "db"),
            (DependencyKind::Requires, "db"),
            (DependencyKind::Wants, "cache"),
            (DependencyKind::BindsTo, "api-sidecar"),
            (DependencyKind::Before, "batch"),
            (DependencyKind::Conflicts, "api-legacy"),
        ]
    );
}

#[test]
fn ordering_and_requirement_axes_stay_separable() {
    let set = from_str(&fixture("valid", "full.xml")).expect("full.xml must parse");
    let deps = set.workloads()[1].dependencies();

    let ordering: Vec<&str> = deps
        .iter()
        .filter(|dep| dep.kind().is_ordering())
        .map(|dep| dep.target())
        .collect();
    let requirement: Vec<&str> = deps
        .iter()
        .filter(|dep| dep.kind().is_requirement())
        .map(|dep| dep.target())
        .collect();

    assert_eq!(ordering, vec!["db", "batch"]);
    assert_eq!(
        requirement,
        vec!["db", "cache", "api-sidecar", "api-legacy"]
    );
}

/// The start command is an argument list, not a string — it must not be folded
/// into a shell line along the way. An argument with a space stays **one**
/// argument.
#[test]
fn command_is_a_list_of_arguments_not_a_shell_line() {
    let set = from_str(&fixture("valid", "command.xml")).expect("command.xml must parse");

    assert_eq!(
        set.workloads()[0].command(),
        vec!["/bin/sh", "-c", "echo hello && sleep 5"]
    );
}

#[test]
fn workload_without_command_element_yields_an_empty_command() {
    let set = from_str(&fixture("valid", "minimal.xml")).expect("minimal.xml must parse");

    assert!(
        set.workloads()[0].command().is_empty(),
        "without <command> the image's entrypoint/cmd applies"
    );
}

/// The workload class from ADR-0010 decides whether there may be more than one
/// active instance cluster-wide. If the attribute is missing, `replicated`
/// applies — the safe default, because it may keep running without quorum.
#[test]
fn workload_class_defaults_to_replicated_when_absent() {
    let set = from_str(&fixture("valid", "workload-class.xml")).expect("must parse");

    let classes: Vec<(&str, WorkloadClass)> = set
        .workloads()
        .iter()
        .map(|w| (w.name(), w.class()))
        .collect();

    assert_eq!(
        classes,
        vec![
            ("ledger", WorkloadClass::SingleWriter),
            ("frontend", WorkloadClass::Replicated),
            ("unspecified", WorkloadClass::Replicated),
        ]
    );
}

/// Single-writer is opt-in. A workload that says nothing must not be fenced by
/// accident.
#[test]
fn single_writer_is_opt_in_only() {
    let set = from_str(&fixture("valid", "minimal.xml")).expect("must parse");

    assert!(!set.workloads()[0].class().is_single_writer());
}

/// `kind` and `class` are independent axes: a long-runner may be a
/// single-writer.
#[test]
fn kind_and_class_are_independent() {
    let set = from_str(&fixture("valid", "workload-class.xml")).expect("must parse");
    let ledger = &set.workloads()[0];

    assert_eq!(ledger.kind(), Kind::Service);
    assert_eq!(ledger.class(), WorkloadClass::SingleWriter);
}

// ---------------------------------------------------------------- invalid ---

/// Every line is a facet class of the XSD. If the validation fails silently in
/// the codegen, more than one case tips here at once.
#[test]
fn invalid_fixtures_are_rejected() {
    let cases = [
        ("name-pattern.xml", "xs:pattern on WorkloadName"),
        (
            "dependency-ref-pattern.xml",
            "xs:pattern on DependencyRef/@ref",
        ),
        ("unknown-kind.xml", "xs:enumeration on Kind"),
        ("unknown-class.xml", "xs:enumeration on WorkloadClass"),
        ("volume-unknown-mode.xml", "xs:enumeration on VolumeMode"),
        (
            "volume-relative-path.xml",
            "xs:pattern on MountPath (absolute)",
        ),
        (
            "volume-path-traversal.xml",
            "xs:pattern on MountPath ('..')",
        ),
        ("volume-no-volume.xml", "<volumes> without <volume>"),
        ("volume-source-too-long.xml", "xs:maxLength on @source"),
        ("missing-attribute.xml", "use=\"required\" on @kind"),
        ("missing-element.xml", "required element <image>"),
        ("cpu-below-range.xml", "xs:minInclusive on Millicores"),
        ("cpu-above-range.xml", "xs:maxInclusive on Millicores"),
        ("memory-below-range.xml", "xs:minInclusive on MemoryBytes"),
        ("image-empty.xml", "xs:minLength on ImageReference"),
        ("image-too-long.xml", "xs:maxLength on ImageReference"),
        ("command-empty-arg.xml", "xs:minLength on Arg"),
        ("pull-policy-unknown.xml", "xs:enumeration on PullPolicy"),
        ("volume-below-minimum.xml", "xs:minInclusive on VolumeBytes"),
        (
            "command-no-args.xml",
            "<command> without <arg> (maxOccurs sequence)",
        ),
    ];

    for (file, facet) in cases {
        let result = from_str(&fixture("invalid", file));
        assert!(
            matches!(result, Err(LoadError::Invalid { .. })),
            "{file} should have failed at '{facet}', but yielded {result:?}"
        );
    }
}

/// The error message must name the location, otherwise it is worthless in
/// operation — the acceptance criterion expressly demands a "clear error
/// message".
#[test]
fn error_message_names_the_offending_input() {
    let err =
        from_str(&fixture("invalid", "name-pattern.xml")).expect_err("name-pattern.xml must fail");

    let message = err.to_string();
    assert!(
        message.contains("Web_Server")
            || message.contains("pattern")
            || message.contains("Pattern"),
        "the error message names neither the value nor the facet: {message}"
    );
}

#[test]
fn malformed_xml_is_rejected_before_validation() {
    let result = from_str("<workloads xmlns=\"urn:tardigrade:workload:v1\"><workload>");

    assert!(matches!(result, Err(LoadError::Invalid { .. })));
}

#[test]
fn wrong_namespace_is_rejected() {
    let result = from_str(
        "<?xml version=\"1.0\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v2\">\n\
           <workload name=\"api\" kind=\"service\">\n\
             <image reference=\"registry.example.com/api:1\"/>\n\
           </workload>\n\
         </workloads>",
    );

    assert!(result.is_err(), "a foreign namespace must not pass as v1");
}

// ------------------------------------------------- placement (ADR-0011) ---

/// Without `<placement>` the domain layer's defaults apply: one instance,
/// anti-affinity at rack level.
///
/// They stand there and not in the schema — `schema/README.md` forbids
/// `xs:default` on attributes, because the codegen yields `Option<T>` anyway
/// and a default value would otherwise stand in two places.
#[test]
fn a_workload_without_placement_uses_the_domain_defaults() {
    let set = from_str(&fixture("valid", "placement.xml")).expect("must parse");
    let plain = &set.workloads()[0];

    assert!(plain.placement().is_none());
}

#[test]
fn a_full_placement_parses_with_expected_values() {
    use tg_defs::{DomainLevel, PlacementExt as _};

    let set = from_str(&fixture("valid", "placement.xml")).expect("must parse");
    let placement = set.workloads()[1].placement().expect("placement");

    assert_eq!(placement.replicas(), 3);
    assert_eq!(placement.spread(), DomainLevel::Hall);
    assert_eq!(placement.pin(), None);

    let domains = placement.domains();
    assert_eq!(domains.len(), 3);
    assert_eq!(domains[0].level, DomainLevel::Site);
    assert_eq!(domains[0].value, "fra");
    assert_eq!(domains[1].value, "r1");
    assert_eq!(domains[2].value, "r2");
}

#[test]
fn a_pin_parses_and_leaves_the_other_defaults_alone() {
    use tg_defs::{DomainLevel, PlacementExt as _};

    let set = from_str(&fixture("valid", "placement.xml")).expect("must parse");
    let placement = set.workloads()[2].placement().expect("placement");

    assert_eq!(placement.pin(), Some("node-7"));
    assert_eq!(placement.replicas(), 1);
    assert_eq!(placement.spread(), DomainLevel::Rack);
}

/// The placement's facets bite — one class each.
#[test]
fn invalid_placement_fixtures_are_rejected() {
    for name in [
        "placement-replicas-zero.xml",
        // The **upper bound** is the counter-check to the lower one: a facet of
        // which only one side is checked is one whose other side a `codegen`
        // accident can take away.
        "placement-replicas-above-range.xml",
        "placement-unknown-level.xml",
        "placement-domain-label.xml",
    ] {
        let result = from_str(&fixture("invalid", name));
        assert!(
            matches!(result, Err(LoadError::Invalid { .. })),
            "{name} was accepted"
        );
    }
}

/// The readiness probe's facets bite (ADR-0080).
///
/// `readiness-port-zero.xml` checks the **facet** at a new use of `Port`: every
/// one is a new place at which it can silently disappear (the pitfall from
/// `schema/README.md`). `readiness-before-mesh.xml` checks the **order** of the
/// `xs:sequence` — it is part of the format an operator types, and a document
/// that fails on it shall do so with a message that names the reason.
///
/// The two path cases check `ProbePath` (ADR-0102), and the first has
/// **security weight**: the path goes into an HTTP request line, and a space in
/// it turns the rest into a setting of its own (request splitting). The second
/// is the form: an origin-form target begins with '/', and silently adding it
/// would be a correction to an operator's setting.
#[test]
fn invalid_readiness_fixtures_are_rejected() {
    for name in [
        "readiness-port-zero.xml",
        "readiness-before-mesh.xml",
        "readiness-path-with-space.xml",
        "readiness-path-relative.xml",
        "readiness-path-with-crlf.xml",
    ] {
        let result = from_str(&fixture("invalid", name));
        assert!(
            matches!(result, Err(LoadError::Invalid { .. })),
            "{name} was accepted"
        );
    }
}

/// The readiness survives canonicalization.
///
/// The same reason as with `mesh_survives_canonicalization`: into the log goes
/// what the loader understood (ADR-0008), and if the probe fell on the floor in
/// the process, a workload would silently be without readiness — it would be
/// resolved although it does not serve. And the digest from ADR-0070 covers
/// exactly this document: a vanished probe would not even be visible there as a
/// change.
#[test]
fn readiness_survives_canonicalization() {
    let set = from_str(&fixture("valid", "readiness.xml")).expect("readiness.xml must parse");

    // **Both** workloads: `api` with mesh, `batch` without. The second half
    // carries the assurance from ADR-0080 determination 2 — a probe without a
    // mesh is permitted, and it must not hang on a mesh element standing beside
    // it.
    for (index, port) in [(0_usize, 8080), (1, 9100)] {
        let workload = &set.workloads()[index];
        assert_eq!(
            workload
                .content
                .readiness
                .as_ref()
                .map(|probe| probe.port.0),
            Some(port),
            "the probe is already missing from the parsed document"
        );

        let xml = tg_defs::workload_to_xml(workload).expect("serializable");
        let again = from_str(&xml).expect("the canonical document must parse");
        assert_eq!(
            again.workloads()[0]
                .content
                .readiness
                .as_ref()
                .map(|probe| probe.port.0),
            Some(port),
            "the probe did not survive canonicalization: {xml}"
        );
    }
}

/// The port facet bites in both directions.
#[test]
fn invalid_mesh_fixtures_are_rejected() {
    for name in [
        "mesh-port-zero.xml",
        "mesh-port-too-large.xml",
        "mesh-udp-zero.xml",
    ] {
        let result = from_str(&fixture("invalid", name));
        assert!(
            matches!(result, Err(LoadError::Invalid { .. })),
            "{name} was accepted"
        );
    }
}

/// **The device requirement arrives, and its facets bite** (ADR-0143).
///
/// Three cases, and the two rejections carry the point:
///
/// - **`DeviceKind` without a dot in the vendor part.** The `kind` becomes the
///   resource name `device:<kind>` and travels into consensus (determination
///   5); without the facet a file on **one** node would determine what a key in
///   the log is called.
/// - **`DeviceCount` zero.** Demanding zero devices achieves nothing and would
///   look as if it achieved something — the finding from ADR-0124 in a new
///   shape.
#[test]
fn devices_are_read_and_their_facets_bite() {
    let set = from_str(&fixture("valid", "devices.xml")).expect("valid");
    let devices = set.workloads()[0].devices();
    assert_eq!(devices.len(), 2, "both entries belong in the declaration");
    assert_eq!(devices[0].kind.0, "nvidia.com/gpu");
    assert_eq!(devices[0].count.0, 1);
    // **The seam is not GPU-specific** (ADR-0028): the same way carries FPGA,
    // SmartNIC and prospectively an HSM for ADR-0014.
    assert_eq!(devices[1].kind.0, "example.com/fpga");
    assert_eq!(devices[1].count.0, 2);

    for name in ["device-kind-without-dot.xml", "device-count-zero.xml"] {
        let result = from_str(&fixture("invalid", name));
        assert!(
            matches!(result, Err(LoadError::Invalid { .. })),
            "{name} was accepted — then the facet (DeviceKind or DeviceCount) \
             no longer carries"
        );
    }
}

/// **The UDP port is optional, and its absence is a statement** (ADR-0142,
/// determination 3).
///
/// Three cases in one fixture, and the third carries the other two: without a
/// workload **without** `@udp`, a loader that invented a port for everyone
/// would be green too — and then ADR-0074 would hold nowhere any more.
#[test]
fn the_udp_port_is_optional_and_its_absence_is_a_statement() {
    use tg_defs::{MeshExt as _, WorkloadExt as _};

    let set = from_str(&fixture("valid", "mesh-udp.xml")).expect("mesh-udp.xml must parse");
    let seen: Vec<(String, u16, Option<u16>)> = set
        .workloads()
        .iter()
        .filter_map(|workload| {
            workload
                .mesh()
                .map(|mesh| (workload.name().to_owned(), mesh.port(), mesh.udp()))
        })
        .collect();

    assert_eq!(
        seen,
        vec![
            // The same number on both transports — separate port spaces.
            ("mixed".to_owned(), 8080, Some(8080)),
            ("separate".to_owned(), 8443, Some(9000)),
            // **No `@udp`, hence no UDP way** (ADR-0074 still applies).
            ("tcp-only".to_owned(), 8443, None),
        ]
    );
}

/// **The UDP port survives canonicalization.**
///
/// The same concern as with the element itself one line further: if it were
/// lost at the first upsert, a workload would **silently** fall out of the UDP
/// mesh — its datagrams would afterwards die at the discarding rule, and the
/// definition would look right.
#[test]
fn the_udp_port_survives_canonicalization() {
    let set = from_str(&fixture("valid", "mesh-udp.xml")).expect("mesh-udp.xml must parse");
    let xml = tg_defs::workload_to_xml(&set.workloads()[1]).expect("serializable");
    let back = from_str(&xml).expect("readable again");

    assert_eq!(
        back.workloads()[0].content.mesh.as_ref().map(MeshExt::udp),
        Some(Some(9000)),
        "the UDP port did not survive canonicalization: {xml}"
    );
}

/// The mesh element survives canonicalization — otherwise the first upsert into
/// the state machine would lose the membership, and a workload would silently
/// have fallen out of the mesh (phase 5a canonicalizes there).
#[test]
fn mesh_survives_canonicalization() {
    let set = from_str(&fixture("valid", "mesh.xml")).expect("mesh.xml must parse");
    let xml = tg_defs::workload_to_xml(&set.workloads()[0]).expect("serializable");
    let back = from_str(&xml).expect("readable again");

    assert_eq!(back.workloads()[0].mesh().map(MeshExt::port), Some(8443));
}

/// The placement survives canonicalization — otherwise it would be lost at the
/// first upsert into the state machine (phase 5a canonicalizes there).
#[test]
fn placement_survives_canonicalization() {
    use tg_defs::{DomainLevel, PlacementExt as _};

    let set = from_str(&fixture("valid", "placement.xml")).expect("must parse");
    let xml = tg_defs::workload_to_xml(&set.workloads()[1]).expect("serializable");
    let restored = from_str(&xml).expect("readable again");
    let placement = restored.workloads()[0].placement().expect("placement");

    assert_eq!(placement.replicas(), 3);
    assert_eq!(placement.spread(), DomainLevel::Hall);
    assert_eq!(placement.domains().len(), 3);
}

/// **Both modes from ADR-0027 read typed.**
///
/// The schema checks structure and value range. That a writable volume is
/// exclusive and a shared one read-only is a statement about the set of all
/// workloads and therefore stands in `tg-model` — the same separation as with
/// the dependency edges (schema/README.md).
#[test]
fn volumes_are_read_with_their_mode_and_path() {
    use tg_defs::{VolumeExt as _, VolumeMode};

    let set = from_str(&fixture("valid", "volumes.xml")).expect("must parse");
    let ledger = &set.workloads()[0];
    let volumes = ledger.volumes();

    assert_eq!(volumes.len(), 2);

    assert_eq!(volumes[0].name(), "ledger-data");
    assert_eq!(volumes[0].path(), "/var/lib/ledger");
    assert_eq!(volumes[0].mode(), VolumeMode::ReadWrite);

    assert_eq!(volumes[1].name(), "reference-data");
    assert_eq!(volumes[1].path(), "/opt/reference");
    assert_eq!(volumes[1].mode(), VolumeMode::ReadOnly);
    // Only read-only volumes carry their provenance (ADR-0027, phase 10c).
    assert_eq!(volumes[1].source(), Some("registry.example.com/stamm:1"));
    assert_eq!(volumes[0].source(), None, "what is written has no source");
}

/// A workload without <volumes> has none — and that is no special case.
#[test]
fn a_workload_without_volumes_has_none() {
    let set = from_str(&fixture("valid", "minimal.xml")).expect("must parse");
    assert!(tg_defs::WorkloadExt::volumes(&set.workloads()[0]).is_empty());
}

// -------------------------------------------------------------- guards ---

/// Every fixture is named by a test.
///
/// # Why this guard exists
///
/// `schema/README.md` demands: "extensions belong together with a fixture in
/// `crates/tg-defs/tests/fixtures/`." Measured, that was half the assurance —
/// the fixtures are enumerated **by name** and not read from the directory, and
/// whoever files one without writing it into a test gets nothing red. It then
/// lies there and checks nothing.
///
/// It stood out at a fixture I had filed myself while building ADR-0080: the
/// counter-check (making a **valid** fixture invalid) stayed green. The same
/// pattern as "built, checked, unused", only on test material — and the guard
/// immediately delivered a second find that was older: `unknown-class.xml`
/// checks the facet that separates `single-writer` from `replicated`
/// (ADR-0010), and had no reader.
///
/// # What it is not
///
/// No statement about whether the test checks the fixture *correctly* — only
/// that it has a reader. The reverse direction (a named name without a file) is
/// caught by the run itself: `fixture()` then panics.
#[test]
fn every_fixture_is_named_by_a_test() {
    let source = include_str!("loader.rs");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let mut checked = 0_usize;
    let mut orphans = Vec::new();
    for group in ["valid", "invalid"] {
        for entry in std::fs::read_dir(root.join(group)).expect("fixture directory readable") {
            let name = entry.expect("directory entry").file_name();
            let name = name.to_string_lossy().to_string();
            if !std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"))
            {
                continue;
            }
            checked += 1;
            if !source.contains(&format!("\"{name}\"")) {
                orphans.push(format!("{group}/{name}"));
            }
        }
    }

    // An empty set contains no violation — the finding from the fuzz run in 9c,
    // one layer down.
    assert!(
        checked >= 20,
        "only {checked} fixtures found — does the guard read the right directory?"
    );
    assert!(
        orphans.is_empty(),
        "fixtures without a reader (they check nothing): {orphans:?}"
    );
}

/// **No content may follow the root element** (ADR-0008).
///
/// # The finding
///
/// Measured, **everything** after `</workloads>` was silently discarded:
/// garbage, a foreign element, text — and a **second complete document**.
/// Whoever concatenated two definitions (`cat a.xml b.xml > all.xml`) got the
/// first one's workloads and not a word about the second's:
///
/// ```text
/// second root: ACCEPTED, 1 workloads, canonical 214 bytes (input 416)
/// ```
///
/// On the cluster path that means: `tgctl cluster apply` sends one command per
/// read workload (ADR-0004), reports "accepted" — and half is missing. That is
/// not the class of a facet error: it is not refused, it is **half executed**.
///
/// # Why that is no new decision
///
/// ADR-0008 fixes XML, and a document with two roots is none
/// (`document ::= prolog element Misc*`). What the loader accepted was non-XML;
/// the check redeems an existing assurance. The same reasoning with which
/// ADR-0072 decided the session's strictness: "I got something I did not
/// understand and passed over it" is in a REMIT/DORA environment no state one
/// can check afterwards.
#[test]
fn nothing_may_follow_the_root_element() {
    let base = std::fs::read_to_string("tests/fixtures/valid/minimal.xml").expect("fixture");

    // Per case the layer that catches it — that is the actual statement. Half a
    // tag is caught by the **parser** (`tag not closed`), and that is the more
    // precise message; everything well-formed is caught by the trailing check.
    for (what, suffix, expected) in [
        ("a second document", base.clone(), "after the root element"),
        (
            "a foreign element",
            "<evil/>".to_owned(),
            "after the root element",
        ),
        ("text", "hello".to_owned(), "after the root element"),
        ("half a tag", "<broken".to_owned(), "XML not readable"),
    ] {
        let document = format!("{base}{suffix}");
        let error = tg_defs::from_str(&document)
            .err()
            .unwrap_or_else(|| panic!("{what} after the root must be refused"));
        assert!(
            error.to_string().contains(expected),
            "{what}: the message must name '{expected}': {error}"
        );
    }
}

/// **And what XML permits after the root stays permitted.**
///
/// The other half of the assurance: `Misc*` is a comment, a processing
/// instruction or whitespace. A check that also rejected those would turn every
/// document with a trailing blank line into an error — and that is legitimate
/// XML that every editor produces.
#[test]
fn xml_misc_after_the_root_stays_valid() {
    let base = std::fs::read_to_string("tests/fixtures/valid/minimal.xml").expect("fixture");

    for (what, suffix) in [
        ("whitespace", "\n\n  \t\n"),
        ("a comment", "<!-- done -->"),
        ("a processing instruction", "<?tg nothing?>"),
        ("both", "\n<!-- a -->\n<?b c?>\n"),
    ] {
        let document = format!("{base}{suffix}");
        tg_defs::from_str(&document)
            .unwrap_or_else(|err| panic!("{what} after the root is permitted: {err}"));
    }
}

/// **Every simple type of the schema has a rejection that names it.**
///
/// A facet without an invalid fixture is a rule nobody checks — and this
/// project has paid dearly for exactly that once: the generated parser lay in
/// the tree for two commits with a **weakened** path-traversal facet, and it
/// stood out only because `volume-path-traversal.xml` existed. A facet without
/// a fixture would have passed silently.
///
/// Measured, `PullPolicy` had **no** rejection, and `Replicas` only its lower
/// bound; `VolumeBytes` none at all. All three are refused correctly — only
/// nobody had proved it.
///
/// Checked via the **name of the type in the fixture's comment**. That is at
/// the same time the information to the next reader about what it proves; a
/// hand-maintained table type → file would be the construction this tree has
/// measured several times as a source of error.
///
/// What the guard **cannot** do: check that the fixture really violates *this*
/// facet. That is said by its comment, and that it is refused at all is said by
/// `invalid_fixtures_are_rejected`.
#[test]
fn every_simple_type_has_a_rejection() {
    const SCHEMA: &str = include_str!("../../../schema/workload.xsd");

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("invalid");
    let mut hay = String::new();
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).expect("fixture directory readable") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|ext| ext == "xml") {
            hay.push_str(&std::fs::read_to_string(&path).expect("fixture readable"));
            files += 1;
        }
    }
    assert!(
        files >= 20,
        "only {files} invalid fixtures found — the guard reads the wrong thing"
    );

    let mut types = Vec::new();
    let mut findings = Vec::new();
    for chunk in SCHEMA.split("<xs:simpleType name=\"").skip(1) {
        let name = chunk
            .split('"')
            .next()
            .expect("the name ends at the quotation mark");
        types.push(name);
        if !hay.contains(name) {
            findings.push(name);
        }
    }
    assert!(
        types.len() >= 15,
        "only {} simple types found — the guard reads the wrong thing",
        types.len()
    );
    assert!(
        findings.is_empty(),
        "these types have no invalid fixture that names them: {findings:?}"
    );
}
