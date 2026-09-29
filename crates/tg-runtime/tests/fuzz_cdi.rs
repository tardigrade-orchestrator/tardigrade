//! **A fuzz run on the CDI spec** (ADR-0143).
//!
//! A real trust boundary lies here: the file determines **which device nodes a
//! container gets**, it is read as root, and at provisioning time it comes
//! from vendor tooling (ADR-0028) -- so not from this tree. The test rules
//! make a fuzz run at such a boundary mandatory.
//!
//! # The finding from 9c is worked in
//!
//! There the first fuzz run was **empty**: pure randomness never produced a
//! parsable DNS packet, and every invariant confirmed itself. This run
//! therefore builds **valid** specs and damages them, and an assurance at the
//! end records that a minimum share was accepted at all.
//!
//! # The invariants
//!
//! 1. **No crash** -- the parser sees arbitrary text.
//! 2. **No device node outside `/dev/`**, and none with a `..`. That is the
//!    security statement: a node elsewhere would cover a file of the rootfs,
//!    and what a program then opens would be decided by the spec file.
//! 3. **No accepted device carries one of the four refused sections** --
//!    `hooks`, `netDevices`, `intelRdt`, `additionalGids`. Checked at the
//!    **text** of the input, that is, with an independent oracle instead of a
//!    second version of the same logic.
//! 4. **No file mode above `0o777`** -- what is computed from `permissions`
//!    stays a file mode.

use std::collections::hash_map::RandomState;
use std::fmt::Write as _;
use std::hash::{BuildHasher as _, Hasher as _};

use tg_runtime::cdi::Catalogue;

/// Iterations, if `TG_FUZZ_ITERATIONS` says nothing else.
const DEFAULT_ITERATIONS: u32 = 20_000;

fn iterations() -> u32 {
    std::env::var("TG_FUZZ_ITERATIONS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS)
}

fn fresh_seed() -> u64 {
    RandomState::new().build_hasher().finish() | 1
}

/// xorshift64* -- one seed reproduces the run completely.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("fits")
    }

    fn pick<'a, T>(&mut self, from: &'a [T]) -> &'a T {
        &from[self.below(from.len())]
    }
}

/// The building blocks a spec arises from.
///
/// **The first entry of every list is the valid one**, and `rng.mostly`
/// chooses it in four of five cases. Without this bias the run accepts almost
/// nothing and no longer checks the acceptance path -- measured 7 of 20 000,
/// the finding from 9c in a new shape. The assurance at the end caught it.
const PATHS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/../etc/passwd",
    "/etc/shadow",
    "dev/null",
    "/dev/",
    "/dev/not-there",
    "",
];
const TYPES: &[&str] = &["c", "b", "u", "p", "s", "", "char"];
const PERMS: &[&str] = &["rw", "r", "w", "rwm", "rr", "x", "", "rwmx"];
const KINDS: &[&str] = &[
    "example.com/probe",
    "nvidia.com/gpu",
    "gpu",
    "a/b",
    "example.com/",
    "/probe",
    "example.com/a/b",
];
const NAMES: &[&str] = &["0", "gpu-1", "a.b", "-x", "x-", "", "\u{fc}", "0_1"];
const VERSIONS: &[&str] = &["0.6.0", "0.8.0", "1.0.0", "0.6", "x.y.z", ""];
const EXTRAS: &[&str] = &[
    "",
    r#""env": [ "A=1" ],"#,
    r#""hooks": [ { "hookName": "createContainer", "path": "/bin/sh" } ],"#,
    r#""netDevices": [ { "name": "eth1" } ],"#,
    r#""intelRdt": { "closID": "g" },"#,
    r#""additionalGids": [ 5 ],"#,
    r#""somethingNew": 1,"#,
];

impl Rng {
    /// Takes the **first** entry in four of five cases.
    fn mostly<'a, T>(&mut self, from: &'a [T]) -> &'a T {
        if self.below(5) == 0 {
            self.pick(from)
        } else {
            &from[0]
        }
    }
}

/// Builds a spec that is mostly valid and sometimes malicious.
fn spec(rng: &mut Rng) -> String {
    let mut devices = String::new();
    let count = 1 + rng.below(2);
    for index in 0..count {
        if index > 0 {
            devices.push(',');
        }
        let file_mode = if rng.below(8) == 0 {
            format!(r#""fileMode": {},"#, [438, 292, 146, -1][rng.below(4)])
        } else {
            String::new()
        };
        let permissions = if rng.below(2) == 0 {
            format!(r#""permissions": "{}","#, rng.mostly(PERMS))
        } else {
            String::new()
        };
        let _ = write!(
            devices,
            r#"{{ "name": "{name}", "containerEdits": {{ {extra}
                 "deviceNodes": [ {{ "path": "{path}", "type": "{kind}",
                   {file_mode}{permissions}
                   "major": {major}, "minor": {minor} }} ] }} }}"#,
            name = rng.mostly(NAMES),
            extra = rng.mostly(EXTRAS),
            path = rng.mostly(PATHS),
            kind = rng.mostly(TYPES),
            major = *rng.mostly(&[1i64, 195, -1, 0]),
            minor = *rng.mostly(&[3i64, 5, -7, 0]),
        );
    }

    let mut text = format!(
        r#"{{ "cdiVersion": "{}", "kind": "{}", "devices": [ {devices} ] }}"#,
        rng.mostly(VERSIONS),
        rng.mostly(KINDS),
    );

    // **And then damage it** -- in one of eight cases.
    if rng.below(8) == 0 {
        let noise = ['{', '}', '"', ',', ':', '\\', '\u{0}', '\u{e4}', '['];
        let at = rng.below(text.len().max(1));
        let at = text
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|i| *i <= at)
            .last()
            .unwrap_or(0);
        text.insert(at, noise[rng.below(noise.len())]);
    }
    text
}

#[test]
fn no_spec_makes_the_reader_lie() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let rounds = iterations();
    let mut accepted = 0u32;

    let dir = tempfile::tempdir().expect("the directory");
    let file = dir.path().join("fuzz.json");

    for round in 0..rounds {
        let text = spec(&mut rng);
        std::fs::write(&file, &text).expect("write");

        let (catalogue, _findings) = Catalogue::read(&[dir.path().to_path_buf()]);
        if catalogue.is_empty() {
            continue;
        }
        accepted += 1;

        let context = || format!("seed {seed}, round {round}, input:\n{text}");

        for name in ["hooks", "netDevices", "intelRdt", "additionalGids"] {
            assert!(
                !text.contains(name),
                "a spec with `{name}` was accepted -- {}",
                context()
            );
        }
        assert!(
            !text.contains("somethingNew"),
            "an unknown field was accepted -- {}",
            context()
        );

        for kind in ["example.com/probe", "nvidia.com/gpu"] {
            for device_name in catalogue.names_of(kind) {
                let device = catalogue
                    .get(&format!("{kind}={device_name}"))
                    .expect("just named");

                for node in &device.edits.nodes {
                    assert!(
                        node.path.starts_with("/dev/"),
                        "a device node outside /dev: {} -- {}",
                        node.path.display(),
                        context()
                    );
                    assert!(
                        !node
                            .path
                            .components()
                            .any(|c| matches!(c, std::path::Component::ParentDir)),
                        "a device node with a `..`: {} -- {}",
                        node.path.display(),
                        context()
                    );
                    assert!(
                        node.file_mode <= 0o777,
                        "{:#o} is no file mode -- {}",
                        node.file_mode,
                        context()
                    );
                    assert!(
                        node.major >= 0 && node.minor >= 0,
                        "a negative device number {}:{} -- {}",
                        node.major,
                        node.minor,
                        context()
                    );
                }
            }
        }
    }

    // **The finding from 9c:** a run that never accepts anything confirms
    // every invariant and checks nothing.
    assert!(
        accepted * 20 > rounds,
        "only {accepted} of {rounds} specs were accepted -- the run no longer \
         checks the acceptance path (seed {seed})"
    );
}
