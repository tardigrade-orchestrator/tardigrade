//! Fuzz run against the address plan (ADR-0012, ADR-0039, ADR-0069).
//!
//! The inputs come from a **log command** an operator issues and from an
//! ordinal consensus hands out. Neither is hostile — but the input space is
//! large, the computation is arithmetic on prefix lengths, and its result
//! carries every route, every nftables rule and every `WireGuard` `AllowedIP`
//! in the cluster.
//!
//! Conventions as everywhere: a fresh seed per run, the iteration count from
//! `TG_FUZZ_ITERATIONS`, the default is the release gate, a find is nailed down
//! as a deterministic test of its own.
//!
//! Four invariants are asserted, and the third is the one at issue:
//!
//! 1. No crash and no overflow, whatever the prefixes.
//! 2. An accepted plan carries exactly `capacity()` ordinals — the last one
//!    yields a subnet, the first one above it does not.
//! 3. **Two different ordinals never yield the same subnet.** A node that
//!    silently got another's subnet would be the worst possible outcome: two
//!    nodes with the same addresses, and nobody sees an error.
//! 4. Every subnet handed out lies **within** the cluster CIDR and carries the
//!    demanded prefix length.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use tg_model::network::{Plan, PlanError};

/// Iterations, if `TG_FUZZ_ITERATIONS` does not say otherwise.
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

    #[expect(
        clippy::cast_possible_truncation,
        reason = "wanted: one byte per field"
    )]
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }

    #[expect(clippy::cast_possible_truncation, reason = "wanted: a 32-bit address")]
    fn addr(&mut self) -> u32 {
        self.next() as u32
    }
}

/// The run.
///
/// The prefixes are **not** rolled uniformly but over the whole range `0..=32`
/// — otherwise the run would reach the bounds at issue (`/0`, `/30`, `/31`,
/// `/32`) only with vanishing probability.
#[test]
fn no_two_ordinals_ever_share_a_subnet() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);
    let mut accepted = 0_u32;

    for round in 0..iterations() {
        let cluster_prefix = rng.byte() % 33;
        let node_prefix = rng.byte() % 33;
        let net = Ipv4Net::new(Ipv4Addr::from(rng.addr()), cluster_prefix)
            .expect("a prefix <= 32 is valid");

        let plan = match Plan::new(net, node_prefix) {
            Ok(plan) => plan,
            // A rejection is a valid result; it only must not crash.
            Err(
                PlanError::NodePrefixTooWide { .. }
                | PlanError::NodeSubnetTooSmall { .. }
                | PlanError::ClusterFull { .. },
            ) => continue,
        };
        accepted += 1;

        let capacity = plan.capacity();

        // Invariant 2: the boundary sits exactly at `capacity`.
        assert!(
            plan.subnet_of(capacity - 1).is_ok(),
            "seed {seed}, round {round}: {net}/{node_prefix} carries {capacity} \
             subnets, but the last ordinal yields none"
        );
        assert!(
            matches!(plan.subnet_of(capacity), Err(PlanError::ClusterFull { .. })),
            "seed {seed}, round {round}: {net}/{node_prefix} handed out a subnet \
             for ordinal {capacity}"
        );

        // Invariants 3 and 4, on a sample: walking the whole capacity would be
        // a billion steps per round at /0.
        let mut taken: HashMap<Ipv4Net, u32> = HashMap::new();
        for ordinal in sample(capacity, &mut rng) {
            let subnet = plan.subnet_of(ordinal).unwrap_or_else(|err| {
                panic!("seed {seed}, round {round}: ordinal {ordinal} of {capacity}: {err}")
            });

            assert_eq!(
                subnet.prefix_len(),
                node_prefix,
                "seed {seed}, round {round}: wrong prefix length"
            );
            assert!(
                plan.net().contains(&subnet),
                "seed {seed}, round {round}: {subnet} does not lie in {}",
                plan.net()
            );
            if let Some(other) = taken.insert(subnet, ordinal) {
                assert_eq!(
                    other, ordinal,
                    "seed {seed}, round {round}: the ordinals {other} and \
                     {ordinal} share {subnet}"
                );
            }
        }
    }

    // **Without this assurance the run confirms itself.** Were `Plan::new` to
    // refuse everything, every invariant above would be vacuously true — the
    // same finding as at the first DNS fuzz run in 9c, which never produced a
    // parsable packet. Measured, the share lies at about a third; the threshold
    // has ample room so that it does not become a source of flakiness itself.
    assert!(
        accepted >= iterations() / 20,
        "seed {seed}: only {accepted} of {} plans were accepted — the run has \
         barely reached the computation path",
        iterations()
    );
}

/// Ordinals that are checked: the edges and a few random ones.
///
/// The edges by hand, because a random grab into a range of a billion never
/// hits them — and precisely there the errors sit.
fn sample(capacity: u32, rng: &mut Rng) -> Vec<u32> {
    let mut out = vec![0, capacity - 1];
    if capacity > 2 {
        out.push(capacity / 2);
        for _ in 0..4 {
            out.push(rng.addr() % capacity);
        }
    }
    out
}
