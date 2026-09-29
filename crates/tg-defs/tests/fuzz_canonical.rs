//! Fuzz run against the definition path's trust boundary.
//!
//! `tg-consensus/tests/fuzz_wire.rs` throws randomness at `from_str` — the way
//! **in**. Here stands the way back out: `workload_to_xml`. It is just as much
//! part of the boundary although it reads no foreign bytes, for it processes
//! what foreign bytes yielded — and what it emits is read again elsewhere
//! (`tg-consensus` into the state machine, `tg-runtime` into the cache).
//!
//! The asserted invariant is the **round trip**: what has been read once
//! survives emitting and re-reading unchanged, and that for every value the
//! schema permits. If it breaks, the desired state drifts silently — the
//! definition still parses, it merely means something else.
//!
//! Conventions as in `fuzz_wire.rs`: fresh seed per run, iteration count from
//! `TG_FUZZ_ITERATIONS`, default is the release threshold.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use tg_defs::{
    ImageExt as _, MeshExt, PlacementExt as _, ResourcesExt, VolumeExt as _, WorkloadExt as _,
    from_str, generated::WorkloadType, workload_to_xml,
};

/// Iterations, if `TG_FUZZ_ITERATIONS` says nothing else.
const DEFAULT_ITERATIONS: u32 = 20_000;

/// Reads the iteration count from `TG_FUZZ_ITERATIONS`, falling back to
/// [`DEFAULT_ITERATIONS`] if the variable is unset or unparsable.
///
/// # Returns
///
/// The number of fuzz iterations to run.
fn iterations() -> u32 {
    std::env::var("TG_FUZZ_ITERATIONS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS)
}

/// Draws a fresh, non-deterministic seed for a fuzz run.
///
/// # Returns
///
/// A 64-bit seed, guaranteed odd so it is usable directly by [`Rng::new`].
fn fresh_seed() -> u64 {
    RandomState::new().build_hasher().finish() | 1
}

/// xorshift64* — reproduces a run completely from its seed.
struct Rng(u64);

impl Rng {
    /// Creates a generator seeded with `seed`, forced odd for the xorshift
    /// multiplier.
    ///
    /// # Returns
    ///
    /// A new [`Rng`] instance.
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    /// Advances the generator's state and returns the next pseudo-random
    /// value.
    ///
    /// # Returns
    ///
    /// The next 64-bit pseudo-random value in the sequence.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Draws a pseudo-random index below `bound`.
    ///
    /// # Returns
    ///
    /// A value in `0..bound`.
    ///
    /// # Panics
    ///
    /// Panics if the reduced value does not fit in a `usize` (unreachable in
    /// practice given the small bounds used by this module).
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("fits")
    }

    /// Picks a pseudo-random element from a non-empty slice.
    ///
    /// # Returns
    ///
    /// A reference to the chosen element.
    fn pick<'a, T>(&mut self, from: &'a [T]) -> &'a T {
        &from[self.below(from.len())]
    }

    /// Decides pseudo-randomly with probability `1 / in_n`.
    ///
    /// # Returns
    ///
    /// `true` roughly once every `in_n` calls.
    fn chance(&mut self, in_n: u64) -> bool {
        self.next().is_multiple_of(in_n)
    }
}

/// A name that observes the facet `[a-z][a-z0-9-]{0,62}`.
///
/// Deliberately inside the schema: what violates it belongs in the fuzz run over
/// `from_str` (the rejection is checked there). Here it is about the values that
/// **get through** — they must survive the round trip.
fn name(rng: &mut Rng) -> String {
    const HEAD: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const TAIL: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

    let len = rng.below(63);
    let mut out = String::from(char::from(*rng.pick(HEAD)));
    for _ in 0..len {
        out.push(char::from(*rng.pick(TAIL)));
    }
    // A trailing hyphen is permitted, but a good candidate for a sloppy
    // canonicalization — that is why it stays.
    out
}

/// An image reference that observes the facet length and may contain XML
/// special characters. That is precisely where an assembled output breaks.
fn reference(rng: &mut Rng) -> String {
    const PARTS: &[&str] = &[
        "example.com/a",
        "registry.example.com/team/app",
        "a&b",
        "x<y",
        "q\"z",
        "p'r",
        "ü-mläut",
        "tag:1.2.3",
        "sha256:abcdef",
        " ",
        "\t",
    ];

    // At least one part without whitespace: after the parser's trimming the
    // schema demands one character (minLength 1). A purely whitespace value
    // would be a case for the rejection path, and here it is about the values
    // that **get through**.
    //
    // The rejection path lies in three places: `loader.rs`
    // (`invalid_fixtures_are_rejected`, one known violation each),
    // `tg-consensus/tests/hostile_input.rs` (the same boundary one layer up,
    // via `apply`) and `fuzz_hostile.rs` beside it (randomized).
    //
    // A reference to `hostile_input.rs` without a crate once stood here — and I
    // thereupon declared the file **non-existent**, because I looked for it in
    // `tg-defs`. It lies in `tg-consensus`. A reference without a crate is none
    // in a workspace with fourteen crates.
    let mut out = String::from(*rng.pick(&PARTS[..PARTS.len() - 2]));
    for _ in 0..rng.below(4) {
        out.push_str(rng.pick(PARTS));
    }
    out.truncate(200);
    out
}

/// The levels of the failure domains (ADR-0034).
const LEVELS: &[&str] = &["site", "hall", "rack", "node"];

/// A label that observes the facet `[a-z0-9][a-z0-9-]{0,62}`.
///
/// Unlike [`name`] it may begin with a digit — that is the difference between a
/// workload name and a topology label, and a canonicalization that confuses
/// them stands out exactly here.
fn label(rng: &mut Rng) -> String {
    const HEAD: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const TAIL: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

    let len = rng.below(63);
    let mut out = String::from(char::from(*rng.pick(HEAD)));
    for _ in 0..len {
        out.push(char::from(*rng.pick(TAIL)));
    }
    out
}

/// A mount path that observes the facet.
///
/// The pattern is `(/[a-zA-Z0-9._-]*[a-zA-Z0-9_-][a-zA-Z0-9._-]*)+` — every
/// component needs at least one character that is **not a dot**. That is the
/// bolt against a path component of only dots (such as `..`), and the run
/// observes it: what violates it belongs in the rejection path.
fn mount_path(rng: &mut Rng) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
    const SOLID: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";

    let mut out = String::new();
    for _ in 0..=rng.below(3) {
        out.push('/');
        for _ in 0..rng.below(6) {
            out.push(char::from(*rng.pick(CHARS)));
        }
        // At least one that is not a dot.
        out.push(char::from(*rng.pick(SOLID)));
        for _ in 0..rng.below(6) {
            out.push(char::from(*rng.pick(CHARS)));
        }
    }
    out
}

/// A document with exactly one workload whose optional parts are randomized.
fn document(rng: &mut Rng) -> String {
    use std::fmt::Write as _;

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<workloads xmlns=\"urn:tardigrade:workload:v1\">\n",
    );

    let class = if rng.chance(2) {
        format!(" class=\"{}\"", rng.pick(&["replicated", "single-writer"]))
    } else {
        String::new()
    };
    let _ = writeln!(
        xml,
        "  <workload name=\"{}\" kind=\"{}\"{class}>",
        name(rng),
        rng.pick(&["service", "job"])
    );

    let policy = if rng.chance(2) {
        format!(
            " pullPolicy=\"{}\"",
            rng.pick(&["always", "if-not-present", "never"])
        )
    } else {
        String::new()
    };
    let _ = writeln!(
        xml,
        "    <image reference=\"{}\"{policy}/>",
        escape(&reference(rng))
    );

    if rng.chance(2) {
        xml.push_str("    <command>\n");
        for _ in 0..=rng.below(4) {
            let _ = writeln!(xml, "      <arg>{}</arg>", escape(&reference(rng)));
        }
        xml.push_str("    </command>\n");
    }

    if rng.chance(2) {
        xml.push_str("    <resources>\n");
        if rng.chance(2) {
            let _ = writeln!(xml, "      <cpu millicores=\"{}\"/>", 1 + rng.below(64_000));
        }
        if rng.chance(2) {
            let _ = writeln!(
                xml,
                "      <memory bytes=\"{}\"/>",
                1_048_576 + rng.next() % 1_000_000_000
            );
        }
        xml.push_str("    </resources>\n");
    }

    // The order in the document follows the xs:sequence: mesh stands between
    // resources and placement. An element in the wrong place would be a
    // rejection case and does not belong here.
    if rng.chance(2) {
        let _ = writeln!(xml, "    <mesh port=\"{}\"/>", 1 + rng.below(65_535));
    }

    // **readiness**. The order follows the `xs:sequence`: between `mesh`
    // and `volumes`.
    if rng.chance(2) {
        let _ = writeln!(xml, "    <readiness port=\"{}\"/>", 1 + rng.below(65_535));
    }

    volumes(rng, &mut xml);
    placement(rng, &mut xml);

    if rng.chance(2) {
        xml.push_str("    <dependencies>\n");
        for _ in 0..=rng.below(6) {
            let _ = writeln!(
                xml,
                "      <{element} ref=\"{}\"/>",
                name(rng),
                element = rng.pick(&[
                    "after",
                    "before",
                    "requires",
                    "wants",
                    "bindsTo",
                    "conflicts"
                ])
            );
        }
        xml.push_str("    </dependencies>\n");
    }

    xml.push_str("  </workload>\n</workloads>\n");
    xml
}

/// Generates a workload's volume declarations and appends them to `xml`.
///
/// A function of its own, because `document` would otherwise lie above the line
/// limit — and because both forms belong together: `source` with `readOnly`,
/// `size` with `readWrite`.
fn volumes(rng: &mut Rng, xml: &mut String) {
    use std::fmt::Write as _;

    // **volumes**. `source` belongs to `readOnly` and is required there,
    // `size` to `readWrite` — the condition stands in `tg_model::storage`
    // and not in the schema (XSD 1.0 knows no conditional attributes), so
    // the run produces both forms schema-conformantly.
    if rng.chance(2) {
        xml.push_str("    <volumes>\n");
        for _ in 0..=rng.below(3) {
            let readonly = rng.chance(2);
            let _ = writeln!(
                xml,
                "      <volume name=\"{}\" path=\"{}\" mode=\"{}\"{}/>",
                name(rng),
                mount_path(rng),
                if readonly { "readOnly" } else { "readWrite" },
                if readonly {
                    format!(" source=\"{}\"", reference(rng))
                } else {
                    format!(" size=\"{}\"", 8_388_608 + rng.next() % 1_000_000_000)
                }
            );
        }
        xml.push_str("    </volumes>\n");
    }
}

/// Generates a workload's placement declaration and appends it to `xml`.
///
/// `replicas` carries the instances and `spread` the anti-affinity level; a lost
/// `replicas` would mean one instance instead of three.
fn placement(rng: &mut Rng, xml: &mut String) {
    use std::fmt::Write as _;

    // **placement**. `replicas` carries the instances and `spread` the
    // anti-affinity level; a lost `replicas` would mean one instance instead
    // of three.
    if rng.chance(2) {
        let mut attributes = String::new();
        if rng.chance(2) {
            let _ = write!(attributes, " replicas=\"{}\"", 1 + rng.below(64));
        }
        if rng.chance(2) {
            let _ = write!(attributes, " spread=\"{}\"", rng.pick(LEVELS));
        }
        let _ = writeln!(xml, "    <placement{attributes}>");
        for _ in 0..rng.below(3) {
            let _ = writeln!(
                xml,
                "      <domain level=\"{}\" value=\"{}\"/>",
                rng.pick(LEVELS),
                label(rng)
            );
        }
        if rng.chance(2) {
            let _ = writeln!(xml, "      <pin node=\"{}\"/>", label(rng));
        }
        xml.push_str("    </placement>\n");
    }
}

fn escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Everything that must survive the round trip, in comparable form.
fn fingerprint(workload: &WorkloadType) -> String {
    let dependencies: Vec<String> = workload
        .dependencies()
        .iter()
        .map(|dependency| format!("{:?}:{}", dependency.kind(), dependency.target()))
        .collect();

    // **Volumes in full**, not only their number: a lost `path` would give a
    // container a different volume than declared, and the canonicalization goes
    // into the log (ADR-0008).
    let volumes: Vec<String> = workload
        .volumes()
        .iter()
        .map(|volume| {
            format!(
                "{}@{}:{:?}:{:?}:{:?}",
                volume.name(),
                volume.path(),
                volume.mode(),
                volume.source(),
                volume.size()
            )
        })
        .collect();

    // **Placement with `replicas`** (ADR-0034): a lost `replicas` would mean one
    // instance instead of three, and the warm standby from ADR-0010 would be
    // gone.
    let placement = workload.placement().map(|placement| {
        let domains: Vec<String> = placement
            .domains()
            .iter()
            .map(|domain| format!("{:?}={}", domain.level, domain.value))
            .collect();
        format!(
            "{}:{:?}:{}:{:?}",
            placement.replicas(),
            placement.spread(),
            domains.join(","),
            placement.pin()
        )
    });

    format!(
        "{}|{:?}|{:?}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{:?}|{}",
        workload.name(),
        workload.kind(),
        workload.class(),
        workload.image().reference(),
        workload.image().pull_policy(),
        workload.command(),
        workload.resources().and_then(ResourcesExt::millicores),
        workload.resources().and_then(ResourcesExt::memory_bytes),
        workload.mesh().map(MeshExt::port),
        workload.readiness(),
        volumes.join(","),
        placement,
        dependencies.join(",")
    )
}

/// Every schema-conformant definition survives the canonicalization unchanged —
/// and the second round changes nothing any more.
///
/// Three invariants are asserted: no crash, no field loss, and idempotence. The
/// third is the one that counts in the cluster: were the output not stable, two
/// nodes with different numbers of upserts would have different bytes for the
/// same definition (ADR-0004).
#[test]
fn any_valid_definition_survives_canonicalization() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);

    let mut accepted = 0_u32;
    // What the generator **reached**. Without this count the run would confirm
    // itself: an element it never produces it also does not check — the finding
    // from 9c, where 200 000 buffers reached the answer path not once and every
    // invariant was green.
    let mut with_readiness = 0_u32;
    let mut with_volumes = 0_u32;
    let mut with_placement = 0_u32;
    for round in 0..iterations() {
        let source = document(&mut rng);

        let Ok(set) = from_str(&source) else {
            // The schema refused — a valid outcome, only not the subject of
            // this run.
            continue;
        };
        accepted += 1;
        assert_eq!(set.workloads().len(), 1, "seed {seed}, round {round}");
        let original = &set.workloads()[0];

        if original.readiness().is_some() {
            with_readiness += 1;
        }
        if !original.volumes().is_empty() {
            with_volumes += 1;
        }
        if original.placement().is_some() {
            with_placement += 1;
        }

        let once = workload_to_xml(original)
            .unwrap_or_else(|err| panic!("seed {seed}, round {round}: not serializable: {err}"));

        let restored = from_str(&once).unwrap_or_else(|err| {
            panic!("seed {seed}, round {round}: own output not readable: {err}\n{once}")
        });
        assert_eq!(restored.workloads().len(), 1, "seed {seed}, round {round}");

        assert_eq!(
            fingerprint(&restored.workloads()[0]),
            fingerprint(original),
            "seed {seed}, round {round}: field loss\nsource:\n{source}\noutput:\n{once}"
        );

        let twice = workload_to_xml(&restored.workloads()[0]).expect("serializable");
        assert_eq!(
            twice, once,
            "seed {seed}, round {round}: canonicalization is not idempotent"
        );
    }

    // The run must really have reached the round trip. A generator whose
    // documents the schema refuses wholesale would run green here without ever
    // having called the canonicalization — a test that checks nothing and looks
    // like one.
    assert!(
        accepted * 2 > iterations(),
        "seed {seed}: only {accepted} of {} documents got through the schema",
        iterations()
    );

    // **And the optional parts must have occurred.** Each is randomized with
    // `chance(2)`, so a tenth of the accepted documents is a bound with plenty
    // of room — it separates "rarely" from "never", and only the second is the
    // error.
    let floor = accepted / 10;
    for (what, seen) in [
        ("readiness", with_readiness),
        ("volumes", with_volumes),
        ("placement", with_placement),
    ] {
        assert!(
            seen > floor,
            "seed {seed}: <{what}> occurred only {seen} times (of {accepted} \
             accepted) — then the run does not check it"
        );
    }
}
