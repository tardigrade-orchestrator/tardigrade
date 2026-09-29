//! Fuzz runs against the trust boundaries: the wire format and the definition
//! document.
//!
//! Two things distinguish this file from `hostile_input.rs`:
//!
//! - **The seed is fresh.** Every run sees different inputs; otherwise this
//!   would be a static test case with a coat of randomness. On a failure the seed
//!   stands in the message; out of it comes a fixed regression test in
//!   `hostile_input.rs`, not a second fuzz run.
//! - **What is asserted are invariants, not values.** No crash, only the expected
//!   error class, a round trip for valid inputs, a bounded output size.
//!
//! The iteration count comes from `TG_FUZZ_ITERATIONS`. The default is the
//! release threshold; for fast local rounds it may be lowered, for the release
//! not.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use tg_consensus::{ClusterState, Command, Outcome, Rejection, Topology, UtcMillis, wire};

/// Iterations, when `TG_FUZZ_ITERATIONS` says nothing else.
const DEFAULT_ITERATIONS: u32 = 20_000;

fn iterations() -> u32 {
    std::env::var("TG_FUZZ_ITERATIONS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_ITERATIONS)
}

/// A fresh seed per run, from the operating system's entropy.
///
/// `RandomState` is the way there that gets by without a dependency.
fn fresh_seed() -> u64 {
    RandomState::new().build_hasher().finish() | 1
}

/// xorshift64* — reproduces a run completely from its seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("fits")
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next() & 0xFF).expect("fits")
    }
}

/// The characters the fuzz inputs are mixed from.
///
/// Not purely random bytes: JSON and XML have a structure, and a random stream
/// almost never hits it. The mixture of structural and wild characters comes
/// considerably closer to the inputs that actually hurt.
const ALPHABET: &[u8] = b"{}[]\",:0123456789abcdefghijklmnopqrstuvwxyz_-<>/=?!&;\\\n \t\0\xff";

fn noise(rng: &mut Rng, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| ALPHABET[rng.below(ALPHABET.len())])
        .collect()
}

/// A valid command per variant, for the round trip.
fn command(rng: &mut Rng) -> Command {
    let name = format!("w{}", rng.below(4));
    let node = format!("node-{}", rng.below(3));
    let now = rng.next() >> 20;

    match rng.below(13) {
        0 => Command::UpsertWorkload {
            document: String::from_utf8_lossy(&noise(rng, 32)).into_owned(),
        },
        1 => Command::RemoveWorkload { name },
        2 => Command::AllowTraffic {
            from: name,
            to: node,
        },
        3 => Command::RevokeTraffic {
            from: name,
            to: node,
        },
        4 => Command::UpsertNode {
            name: node,
            topology: Topology {
                site: String::from_utf8_lossy(&noise(rng, 8)).into_owned(),
                hall: format!("h{}", rng.below(3)),
                rack: format!("r{}", rng.below(3)),
            },
            capacity: tg_consensus::Resources::default(),
            reserved: tg_consensus::Resources::default(),
            source: tg_consensus::Origin::Operator,
        },
        5 => Command::RemoveNode { name: node },
        6 => Command::AssignPlacement {
            workload: name,
            node,
            instance: 0,
        },
        7 => Command::ClearPlacement { workload: name },
        8 => Command::GrantLease {
            workload: name,
            node,
            now: UtcMillis::new(now),
            expires_at: UtcMillis::new(now.wrapping_add(15_000)),
        },
        9 => Command::RenewLease {
            workload: name,
            node,
            now: UtcMillis::new(now),
            expires_at: UtcMillis::new(now.wrapping_add(15_000)),
        },
        10 => Command::SetActiveInstance {
            workload: name,
            instance: u32::try_from(rng.next() % 70).unwrap_or(0),
        },
        11 => Command::RegisterTrust {
            node,
            bundle: String::from_utf8_lossy(&noise(rng, 24)).into_owned(),
        },
        _ => Command::RevokeTrust { node },
    }
}

/// Every command survives the round trip through the wire format — with special
/// characters, quotation marks and backslashes in the fields too. Exactly there a
/// hand-written encoding breaks.
#[test]
fn any_command_survives_the_round_trip() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);

    for step in 0..iterations() {
        let original = command(&mut rng);
        let encoded = wire::encode_command(&original)
            .unwrap_or_else(|err| panic!("seed {seed}, step {step}: not encodable: {err}"));
        let decoded = wire::decode_command(&encoded)
            .unwrap_or_else(|err| panic!("seed {seed}, step {step}: not readable: {err}"));

        assert_eq!(
            decoded, original,
            "seed {seed}, step {step}: the round trip changed the command"
        );
    }
}

/// Random bytes at the three decoders.
///
/// Two things are asserted. First: the call comes back. A panic here would be no
/// trifle — the decoder reads what another node sent or the disk gave back; a
/// crash at this place is a denial of service a single byte triggers.
///
/// Second: if a random stream **does** hit something readable, the round trip
/// over it is stable. An `Err` is the intended signal and no failure; unstable
/// would be a value that changes on re-encoding — then a log entry would be a
/// different one after being read and written once.
#[test]
fn random_input_is_either_rejected_or_stable() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);

    for step in 0..iterations() {
        let len = 1 + rng.below(96);
        let bytes = noise(&mut rng, len);
        let text = String::from_utf8_lossy(&bytes).into_owned();

        let command = wire::decode_command(&text)
            .and_then(|value| wire::encode_command(&value).map(|json| (value, json)))
            .and_then(|(value, json)| wire::decode_command(&json).map(|again| (value, again)));
        assert!(
            command
                .as_ref()
                .map_or(true, |(value, again)| value == again),
            "seed {seed}, step {step}: the command is not round-trip stable"
        );

        let entry = wire::decode_entry(&bytes)
            .and_then(|value| wire::encode_entry(&value).map(|raw| (value, raw)))
            .and_then(|(value, raw)| wire::decode_entry(&raw).map(|again| (value, again)));
        assert!(
            entry.as_ref().map_or(true, |(value, again)| value == again),
            "seed {seed}, step {step}: the log entry is not round-trip stable"
        );

        let state = wire::decode_state(&bytes)
            .and_then(|value| wire::encode_state(&value).map(|raw| (value, raw)))
            .and_then(|(value, raw)| wire::decode_state(&raw).map(|again| (value, again)));
        assert!(
            state.as_ref().map_or(true, |(value, again)| value == again),
            "seed {seed}, step {step}: the state is not round-trip stable"
        );
    }
}

/// A valid document, altered at one character position.
///
/// The invariants: no crash, a rejection leaves the state untouched, an
/// acceptance leaves exactly one workload — and the rationale stays bounded,
/// whatever came in.
#[test]
fn no_mutated_document_breaks_the_state_machine() {
    const TEMPLATE: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\
         <workload name=\"api\" kind=\"service\" class=\"single-writer\">\
         <image reference=\"example.com/api:1\"/>\
         <dependencies><after ref=\"db\"/></dependencies>\
         </workload></workloads>";

    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let template: Vec<char> = TEMPLATE.chars().collect();

    for step in 0..iterations() {
        let mut mutated = template.clone();
        for _ in 0..=rng.below(3) {
            let at = rng.below(mutated.len());
            match rng.below(3) {
                0 => mutated[at] = char::from(rng.byte() | 0x20),
                1 => {
                    mutated.remove(at);
                }
                _ => mutated.insert(at, char::from(ALPHABET[rng.below(ALPHABET.len())])),
            }
        }
        let document: String = mutated.into_iter().collect();

        let mut state = ClusterState::default();
        let outcome = state.apply(&Command::UpsertWorkload {
            document: document.clone(),
        });

        match outcome {
            Outcome::Applied => assert_eq!(
                state.workloads().len(),
                1,
                "seed {seed}, step {step}: accepted, but not exactly one workload"
            ),
            Outcome::Rejected(Rejection::MalformedDocument { detail }) => {
                assert_eq!(
                    state,
                    ClusterState::default(),
                    "seed {seed}, step {step}: refused, but the state changed"
                );
                assert!(
                    detail.chars().count() <= 600,
                    "seed {seed}, step {step}: the rationale is {} characters long",
                    detail.chars().count()
                );
            }
            other => {
                panic!("seed {seed}, step {step}: unexpected outcome {other:?} for {document:?}")
            }
        }
    }
}
