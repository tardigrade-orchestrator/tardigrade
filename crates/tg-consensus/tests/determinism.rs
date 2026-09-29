//! Determinism under seeded randomness — the storage-layer half of the
//! simulation evidence.
//!
//! The DST runs must reproduce completely from a single seed, so they can
//! serve as exportable evidence for resilience-testing obligations. The
//! actual test rig — an in-process bus with injectable partition, delay,
//! reordering and loss — is a separate deliverable and lies in `tests/dst/`.
//!
//! What can already be checked here, without a network and without controlled
//! time, is the property everything further sits on: **the same log, the same
//! state.** Without it no statement about freedom from split-brain is possible —
//! two nodes that derive different states from the same log are already apart
//! without a single message having been lost.
//!
//! The randomness is an xorshift64* in twenty lines and no dependency: what is
//! needed is reproducibility, not statistical quality. The seed stands in every
//! error message.

use openraft::storage::{RaftLogStorageExt as _, RaftStateMachine as _};
use openraft::testing::log_id;
use openraft::{Entry, EntryPayload, RaftLogReader as _};
use tg_consensus::{ClusterState, Command, Outcome, Storage, Topology, UtcMillis, wire};

/// The seeds the test run goes through. A fixed list instead of a timestamp: a
/// green run must be green again tomorrow, and a red one reproducibly red.
const SEEDS: [u64; 8] = [1, 2, 3, 42, 1_337, 99_991, 0xDEAD_BEEF, 0x5EED_5EED];

/// How many commands are generated per run.
const STEPS: usize = 200;

/// xorshift64* — deterministic, small, without a dependency.
struct Rng(u64);

impl Rng {
    /// Builds a generator from a seed.
    ///
    /// # Parameters
    /// - `seed`: the seed to derive the sequence from.
    ///
    /// # Returns
    /// The generator, ready to produce values.
    fn new(seed: u64) -> Self {
        // A seed of 0 would nail the sequence down at its fixed point.
        Self(seed | 1)
    }

    /// Advances the generator and produces the next value.
    ///
    /// # Returns
    /// The next pseudo-random `u64` in the sequence.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Produces the next value, reduced to a bounded range.
    ///
    /// # Parameters
    /// - `bound`: the exclusive upper bound of the returned value.
    ///
    /// # Returns
    /// A pseudo-random value in `0..bound`.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

const WORKLOADS: [(&str, Option<&str>); 3] = [
    ("api", None),
    ("ledger", Some("single-writer")),
    ("audit", Some("single-writer")),
];
const NODES: [&str; 2] = ["node-1", "node-2"];

/// Builds an XML workload document, optionally with a workload `class`
/// attribute.
///
/// # Parameters
/// - `name`: the workload name.
/// - `class`: the workload's class attribute, if any.
///
/// # Returns
/// The XML document as a string.
fn document(name: &str, class: Option<&str>) -> String {
    let class = class.map_or(String::new(), |c| format!(" class=\"{c}\""));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n\
         <workload name=\"{name}\" kind=\"service\"{class}>\n\
         <image reference=\"example.com/{name}:1\"/>\n\
         </workload>\n\
         </workloads>\n"
    )
}

/// Generates a command sequence from a seed.
///
/// The clock runs along: `now` rises monotonically, `expires_at` lies one lease
/// length (15 s) before or after it. Thereby both valid renewals and
/// takeovers after expiry arise, without the cases having to be enumerated by
/// hand.
fn script(seed: u64) -> Vec<Command> {
    let mut rng = Rng::new(seed);
    let mut now = 0_u64;
    let mut commands = Vec::with_capacity(STEPS);

    for _ in 0..STEPS {
        now += rng.below(9_000);

        let workload = WORKLOADS[usize::try_from(rng.below(3)).expect("fits")];
        let other = WORKLOADS[usize::try_from(rng.below(3)).expect("fits")].0;
        let node = NODES[usize::try_from(rng.below(2)).expect("fits")];

        commands.push(match rng.below(11) {
            0 => Command::UpsertWorkload {
                document: document(workload.0, workload.1),
            },
            1 => Command::RemoveWorkload {
                name: workload.0.to_owned(),
            },
            2 => Command::AllowTraffic {
                from: workload.0.to_owned(),
                to: other.to_owned(),
            },
            3 => Command::RevokeTraffic {
                from: workload.0.to_owned(),
                to: other.to_owned(),
            },
            4 => Command::UpsertNode {
                name: node.to_owned(),
                topology: Topology {
                    site: "fra".to_owned(),
                    hall: format!("h{}", rng.below(2)),
                    rack: format!("r{}", rng.below(3)),
                },
                capacity: tg_consensus::Resources::default(),
                reserved: tg_consensus::Resources::default(),
                source: tg_consensus::Origin::Operator,
            },
            5 => Command::AssignPlacement {
                workload: workload.0.to_owned(),
                node: node.to_owned(),
                instance: 0,
            },
            6 => Command::ClearPlacement {
                workload: workload.0.to_owned(),
            },
            7 => Command::GrantLease {
                workload: workload.0.to_owned(),
                node: node.to_owned(),
                now: UtcMillis::new(now),
                expires_at: UtcMillis::new(now + 15_000),
            },
            8 => Command::RenewLease {
                workload: workload.0.to_owned(),
                node: node.to_owned(),
                now: UtcMillis::new(now),
                expires_at: UtcMillis::new(now + 15_000),
            },
            9 => Command::SetActiveInstance {
                workload: workload.0.to_owned(),
                instance: u32::try_from(rng.below(3)).expect("fits"),
            },
            _ => Command::RegisterTrust {
                node: node.to_owned(),
                bundle: format!("bundle-{}", rng.below(4)),
            },
        });
    }

    commands
}

/// Applies a command sequence to a fresh cluster state.
///
/// # Parameters
/// - `commands`: the commands to apply, in order.
///
/// # Returns
/// The resulting state and the outcome of each applied command, in order.
fn run(commands: &[Command]) -> (ClusterState, Vec<Outcome>) {
    let mut state = ClusterState::default();
    let outcomes = commands.iter().map(|c| state.apply(c)).collect();

    (state, outcomes)
}

/// Two nodes, the same log, the same byte — for every seed.
#[test]
fn the_same_log_yields_the_same_state_on_every_node() {
    for seed in SEEDS {
        let commands = script(seed);
        let (left, left_outcomes) = run(&commands);
        let (right, right_outcomes) = run(&commands);

        assert_eq!(
            left_outcomes, right_outcomes,
            "seed {seed}: the outcomes deviate"
        );
        assert_eq!(
            wire::encode_state(&left).expect("encodable"),
            wire::encode_state(&right).expect("encodable"),
            "seed {seed}: the states deviate byte for byte"
        );
    }
}

/// The run is interruptible at any place: encode the state, decode it, carry on
/// — the result is the same as without the interruption. That is the snapshot
/// property without which a catching-up node cannot catch up.
#[test]
fn a_snapshot_in_the_middle_changes_nothing() {
    for seed in SEEDS {
        let commands = script(seed);
        let (reference, _) = run(&commands);

        // The cut point comes from the same seed -- reproducible.
        let cut =
            usize::try_from(Rng::new(seed.wrapping_add(7)).below(STEPS as u64)).expect("fits");

        let mut state = ClusterState::default();
        for command in &commands[..cut] {
            state.apply(command);
        }

        let bytes = wire::encode_state(&state).expect("encodable");
        let mut resumed = wire::decode_state(&bytes).expect("decodable");
        for command in &commands[cut..] {
            resumed.apply(command);
        }

        assert_eq!(
            resumed, reference,
            "seed {seed}: the snapshot at step {cut} changed the run"
        );
    }
}

/// And the same over the disk: in the middle of the run the process dies, the
/// rest comes from the log at the start. No entry twice, none skipped.
#[tokio::test]
async fn a_crash_in_the_middle_changes_nothing() {
    for seed in SEEDS {
        let commands = script(seed);
        let (reference, _) = run(&commands);

        let entries: Vec<Entry<_>> = commands
            .iter()
            .enumerate()
            .map(|(index, command)| Entry {
                log_id: log_id(1, 1, u64::try_from(index).expect("fits") + 1),
                payload: EntryPayload::Normal(command.clone().into()),
            })
            .collect();

        let cut =
            usize::try_from(Rng::new(seed.wrapping_add(13)).below(STEPS as u64)).expect("fits");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("raft.redb");

        {
            let mut storage = Storage::open(&path).expect("open");
            storage
                .log
                .blocking_append(entries.clone())
                .await
                .expect("append");
            storage
                .machine
                .apply(entries[..cut].to_vec())
                .await
                .expect("apply");
        }

        let mut storage = Storage::open(&path).expect("reopen");
        let (applied, _) = storage
            .machine
            .applied_state()
            .await
            .expect("applied_state");
        let resume = applied.map_or(0, |id| id.index + 1);
        let rest = storage
            .log
            .try_get_log_entries(resume..)
            .await
            .expect("read the rest");
        storage.machine.apply(rest).await.expect("apply the rest");

        assert_eq!(
            storage.machine.state(),
            reference,
            "seed {seed}: the crash after step {cut} changed the state"
        );
    }
}

/// **No hash-ordered collection in the deterministic crates.**
///
/// `tg-consensus` is the state machine, `tg-model` the pure functions from which
/// the leader computes commands, and `tg-store` the projection including the
/// slice sent to each node. All three must deliver the same result on every
/// replica.
///
/// Measured, they uphold that everywhere today — it just stands **nowhere**, and
/// the check above would not find it: it builds the same log twice and compares
/// the states, and two `HashMap`s compare order-independently. What would get
/// through is everything that arises from an **order**: the order of the commands
/// a planner issues, the bytes of a serialized slice, the content of a snapshot.
///
/// Hence a tripwire and no assurance: whoever adds a hash-ordered collection gets
/// a red test here instead of a divergence an auditor sees only in the audit
/// trail. `BTreeMap` and `BTreeSet` do the same everywhere and order in the
/// process.
#[test]
fn the_deterministic_crates_use_no_hash_ordered_collections() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/");

    let mut seen = 0_usize;
    let mut offenders = Vec::new();

    for crate_name in DETERMINISTIC {
        for file in rust_files(&root.join(crate_name).join("src")) {
            let text = std::fs::read_to_string(&file).expect("readable");
            seen += 1;
            let code = code_of(&text);
            for forbidden in [
                "HashMap",
                "HashSet",
                // **The hashers too** -- `DefaultHasher` is expressly rejected,
                // because its result is not stable between Rust versions, and
                // `tg_model::keys` therefore writes FNV-1a out. Nothing nailed
                // that down: whoever used `DefaultHasher` made the whole cluster
                // rotate in one day after a compiler upgrade.
                "DefaultHasher",
                "RandomState",
            ] {
                if code.contains(forbidden) {
                    offenders.push(format!("{}: {forbidden}", file.display()));
                }
            }
        }
    }

    // Without this assurance the test would check nothing as soon as the layout
    // changes: an empty file set contains no violations.
    assert!(seen >= 15, "the source text was not read: {seen} files");
    assert!(
        offenders.is_empty(),
        "hash-ordered collections or an unstable hasher in a deterministic \
         crate -- two replicas drift apart with it without a message being \
         lost: {offenders:?}"
    );
}

/// **No wall clock in the deterministic crates.**
///
/// The same rule as above, a different source. A state machine that reads the
/// clock derives two different states from the same log — depending on *when* a
/// replica applies it. That is why **the command carries its time** (`at`,
/// `now`), and why the audit export inserts nothing where nothing stands: the
/// Raft log orders, but it does not date.
///
/// Measured, the clock is **not present at all** in all three crates. That stands
/// nowhere, and the check above would not find it: it builds the same log twice
/// **in the same moment**.
///
/// Randomness deliberately gets **no** rule here: `generate_token` uses `OsRng`,
/// and that is right — it runs in the client before the command arises, and the
/// log carries only its hash.
#[test]
fn the_deterministic_crates_do_not_read_the_wall_clock() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/");

    let mut seen = 0_usize;
    let mut offenders = Vec::new();

    for crate_name in DETERMINISTIC {
        for file in rust_files(&root.join(crate_name).join("src")) {
            let text = std::fs::read_to_string(&file).expect("readable");
            seen += 1;

            // **The wall clock is forbidden everywhere.** It is the one that
            // drives two replicas apart: the same log would yield a different
            // state depending on the moment of application.
            if text.contains("SystemTime::now") {
                offenders.push(file.display().to_string());
                continue;
            }

            // **The monotonic clock only in the transport.** The two clock
            // sources are kept expressly separate, and `Instant` is no wall
            // clock: it cannot get into any state, because it is nowhere
            // compared or stored -- it measures a duration.
            //
            // The transport is by definition I/O and no part of the determinism
            // argument; there a duration **is** measured (`heartbeat_interval`
            // is at the same time the time bound of replication, and without a
            // measurement a slow path never replicates, and quietly at that).
            //
            // The exception is **exactly one directory**, and the wall clock
            // stays forbidden there too: a timestamp on a message would again be
            // a statement that can get into the state.
            let transport = file.components().any(|part| part.as_os_str() == "net");
            if !transport && text.contains("Instant::now") {
                offenders.push(file.display().to_string());
            }
        }
    }

    assert!(seen >= 15, "the source text was not read: {seen} files");
    assert!(
        offenders.is_empty(),
        "a wall clock in a deterministic crate -- the same log would then yield \
         a different state depending on the moment of application. The time \
         belongs in the command: {offenders:?}"
    );
}

/// The crates that must yield the same thing from the same log.
///
/// **`tgd` is deliberately not among them**, and the reason belongs here so that
/// nobody adds it as an omission: there the leader reads the wall clock — it
/// **must**, to fill `at`/`now` in the five commands that carry them — and
/// `tgd::identity` keeps a `HashMap` as a nonce table. That is queried by name and never
/// traversed in an order. What `tgd` computes in commands and slices it computes
/// with the pure functions from `tg-model` and the projection from `tg-store` —
/// both are in here.
const DETERMINISTIC: [&str; 3] = ["tg-consensus", "tg-model", "tg-store"];

/// The source text without the lines that are only prose.
///
/// **Otherwise the tripwire would check its own rationale.** `tg_model::keys`
/// explains in a doc comment why FNV-1a is written out there and **not**
/// `DefaultHasher` — by name. A text comparison over the whole file would find
/// exactly this explanation and report it as a violation.
///
/// The limit belongs to it: a **trailing** comment at the end of a code line
/// stays and can still strike wrongly. That is the cheaper error — it is
/// recognizable at once on reading the message, and the remedy is not to name the
/// name there.
fn code_of(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// All `.rs` files under a directory, recursively.
fn rust_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }

    out
}
