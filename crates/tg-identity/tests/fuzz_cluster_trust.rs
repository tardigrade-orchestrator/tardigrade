//! A fuzz run against the cluster verifier (ADR-0043).
//!
//! The bytes [`tg_identity::cluster::check`] sees come from the counterpart of a TLS
//! handshake -- that is, from the network. That is a trust boundary, and there a fuzz
//! run is mandatory.
//!
//! # The lesson from phase 9c is applied here
//!
//! The DNS fuzzer's first attempt was **empty**: pure randomness never produces a
//! parsable packet, 200 000 buffers reached the answer path not a single time, and
//! every invariant confirmed itself. For DER it holds doubly.
//!
//! That is why the run produces **valid leaves and damages them**, and an assurance at
//! the end records that a minimum share got as far as the key check at all.
//!
//! Conventions as in `fuzz_nonce`: a fresh seed per run, the iteration count from
//! `TG_FUZZ_ITERATIONS`, the default is the release threshold. A failure reports its
//! seed and belongs nailed down as a seeded regression test -- it is a finding, no
//! flakiness.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use rustls_pki_types::CertificateDer;
use tg_identity::cluster::{ClusterVerifyError, NodeTrust, check, node_leaf};
use tg_identity::{SpiffeId, TrustDomain};

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

/// A seeded stream -- the same construction as in the other fuzz runs.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        // xorshift64*: small, seeded, reproducible.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            usize::try_from(self.next_u64() % bound as u64).unwrap_or(0)
        }
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next_u64() & 0xFF).unwrap_or(0)
    }
}

fn spki(key: &rcgen::KeyPair) -> Vec<u8> {
    use rcgen::PublicKeyData as _;

    key.subject_public_key_info()
}

/// **The verifier does not crash, and it lets no stranger through.**
///
/// Two invariants, both absolute:
///
/// 1. Every buffer leads to `Ok` or to one of the named reasons -- never to a panic.
/// 2. If a buffer is accepted, then it carries the identity of an **admitted** node
///    and the key **registered** there. A damaged leaf must never get through under a
///    foreign name.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "a fuzz run is build-up, loop and assurance in one piece; taking it \
              apart would distribute the invariant over three functions"
)]
fn no_mutated_leaf_is_ever_accepted_as_a_foreign_node() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let domain = TrustDomain::new("cluster.local").expect("Trust Domain");

    // Three admitted nodes, one beside them that is not admitted.
    let names = ["node-1", "node-2", "node-3"];
    let mut trust = NodeTrust::new();
    let mut leaves: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new();

    for name in names {
        let id = SpiffeId::for_node(&domain, name).expect("ID");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
        let leaf = node_leaf(&key, &id).expect("leaf");
        trust.insert(name, spki(&key));
        leaves.push((name.to_owned(), leaf, spki(&key)));
    }
    {
        let id = SpiffeId::for_node(&domain, "node-foreign").expect("ID");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
        let leaf = node_leaf(&key, &id).expect("leaf");
        leaves.push(("node-foreign".to_owned(), leaf, spki(&key)));
    }

    let total = iterations();
    let mut parsed = 0_u32;
    let mut accepted = 0_u32;

    for round in 0..total {
        let (origin, base, _) = &leaves[rng.below(leaves.len())];
        let mut bytes = base.clone();

        // Damage: swap bytes, truncate, append, turn blocks.
        match rng.below(5) {
            0 => {
                let flips = 1 + rng.below(4);
                for _ in 0..flips {
                    let at = rng.below(bytes.len());
                    bytes[at] = rng.byte();
                }
            }
            1 => {
                let keep = rng.below(bytes.len());
                bytes.truncate(keep);
            }
            2 => {
                let extra = 1 + rng.below(32);
                for _ in 0..extra {
                    bytes.push(rng.byte());
                }
            }
            3 if bytes.len() > 8 => {
                let a = rng.below(bytes.len());
                let b = rng.below(bytes.len());
                bytes.swap(a, b);
            }
            // Undamaged: the run must hit the normal case too, otherwise we measure
            // only the parser.
            _ => {}
        }

        let expected = if rng.below(4) == 0 {
            Some(names[rng.below(names.len())])
        } else {
            None
        };

        let verdict = check(
            &CertificateDer::from(bytes.clone()),
            tg_identity::Role::Node,
            &domain,
            &trust,
            expected,
        );

        match verdict {
            Ok(id) => {
                accepted += 1;
                parsed += 1;

                let name = id.node().unwrap_or_default();
                let registered = trust.get(name);
                assert!(
                    registered.is_some(),
                    "round {round}, seed {seed}: '{name}' is not admitted and was \
                     accepted all the same (initial leaf {origin})"
                );

                let (_, presented) =
                    x509_parser::parse_x509_certificate(&bytes).expect("accepted, so readable");
                assert_eq!(
                    presented.public_key().raw,
                    registered.unwrap_or_default(),
                    "round {round}, seed {seed}: accepted with a foreign key"
                );
                if let Some(want) = expected {
                    assert_eq!(
                        name, want,
                        "round {round}, seed {seed}: a different peer than dialled"
                    );
                }
            }
            Err(err) => {
                if !matches!(err, ClusterVerifyError::Unreadable { .. }) {
                    parsed += 1;
                }
                // Every reason must be a named one -- the enumeration is exhaustive,
                // so the compiler checks that. What counts here is that the message is
                // not empty: it lands in the log of an operator who wants to know why
                // a node does not talk.
                assert!(
                    !err.to_string().is_empty(),
                    "round {round}, seed {seed}: a reason without a message"
                );
            }
        }
    }

    // The assurance from the module head: the run really reached the deep path.
    // Without it the invariant would confirm itself.
    let deep = f64::from(parsed) / f64::from(total);
    assert!(
        deep > 0.15,
        "seed {seed}: only {parsed} of {total} buffers got past the parser \
         ({deep:.3}) -- the run does not check the verifier"
    );
    assert!(
        accepted > 0,
        "seed {seed}: not a single buffer was accepted -- the run does not hit \
         the normal case"
    );
}
