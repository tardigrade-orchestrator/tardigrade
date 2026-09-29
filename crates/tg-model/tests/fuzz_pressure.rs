//! Fuzz run over a node's pressure (ADR-0109).
//!
//! `Resources::pressure` is a pure computation over two maps with `u64` values,
//! and ADR-0109 determination 1 **claims** that the overflow is excluded:
//! `u64::MAX * 10^6` fits into `u128`. A run substantiates that instead of
//! claiming it — and at the same time it substantiates the property for which
//! there can be no guard: that a resource **name** shifts nothing.
//!
//! A trust boundary it is **not** — the numbers come from consensus
//! (`UpsertNode`, `AssignPlacement`) and not from outside. The run stands
//! because the input space is not trivial; the testing rules demand that for
//! every such unit.
//!
//! Conventions as everywhere: a fresh seed per run, iterations over
//! `TG_FUZZ_ITERATIONS`, the default is the release gate, a find is nailed down
//! as a seeded regression test.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use tg_model::placement::Resources;

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

    /// An amount that takes the **edges** along: zero, one, `u64::MAX` and the
    /// neighbours of the scaling bound. Pure randomness over 64 bits never hits
    /// them, and the errors sit there.
    fn amount(&mut self) -> u64 {
        match self.next() % 8 {
            0 => 0,
            1 => 1,
            2 => u64::MAX,
            3 => u64::MAX / 1_000_000,
            4 => u64::MAX / 1_000_000 + 1,
            5 => 1_000_000,
            _ => self.next(),
        }
    }

    /// A resource map over up to four names.
    fn resources(&mut self, names: &[&str]) -> Resources {
        let mut out = Resources::default();
        for name in names {
            if !self.next().is_multiple_of(3) {
                out = out.with(name, self.amount());
            }
        }
        out
    }
}

/// **The pressure computes over the whole `u64` range, without overflow.**
///
/// Four assurances, and the third is the one for which there is otherwise no
/// guard:
///
/// 1. no crash — not at `u64::MAX`, not at capacity zero;
/// 2. **monotonic in the occupancy**: more occupied never means less pressure;
/// 3. **independent of names**: the same values under different names yield the
///    same pressure (ADR-0109, positive consequence — the old lexicographic
///    rule would have shifted the selection here);
/// 4. a capacity of zero produces no pressure (determination 2).
#[test]
fn pressure_holds_over_the_whole_range() {
    let seed = fresh_seed();
    let mut rng = Rng::new(seed);

    let names = ["cpu-millicores", "memory-bytes", "device-gpu", "aaa-early"];
    let mut with_pressure = 0_u32;
    let mut carried = 0_u32;
    let mut with_zero = 0_u32;

    for round in 0..iterations() {
        let used = rng.resources(&names);
        // The capacity arises over `minus` in every third round -- that is, the
        // way the planner gets it (`schedulable_capacity`). That way is the
        // only one that produces an entry with the value **zero**: `minus`
        // writes directly into the map and saturates (ADR-0047), and `with`
        // filters the zero away. Without it the run does not enter the `filter`
        // branch in `pressure` at all.
        let capacity = if round.is_multiple_of(3) {
            rng.resources(&names).minus(&rng.resources(&names))
        } else {
            rng.resources(&names)
        };

        // 1: no crash, and the result is a number.
        let pressure = used.pressure(&capacity);
        if pressure > 0 {
            with_pressure += 1;
        }
        if !capacity.is_empty() {
            carried += 1;
        }
        if capacity.entries().iter().any(|(_, have)| *have == 0) {
            with_zero += 1;
        }

        // 2: more occupied never means less pressure.
        let more = used.clone().with(names[0], u64::MAX);
        assert!(
            more.pressure(&capacity) >= pressure,
            "seed {seed}, round {round}: more occupied gave less pressure \
             ({} < {pressure})",
            more.pressure(&capacity)
        );

        // 3: the same state under permuted names.
        let swapped = ["memory-bytes", "cpu-millicores", "aaa-early", "device-gpu"];
        let mut used_again = Resources::default();
        let mut cap_again = Resources::default();
        for (from, to) in names.iter().zip(swapped.iter()) {
            let (u, c) = (used.get(from), capacity.get(from));
            if u > 0 {
                used_again = used_again.with(to, u);
            }
            if c > 0 {
                cap_again = cap_again.with(to, c);
            }
        }
        // Only comparable if the zeros have lost no entries: `with` leaves a
        // zero out, so for the pressure only what has a capacity above zero
        // counts anyway.
        assert_eq!(
            used_again.pressure(&cap_again),
            used.pressure(&capacity),
            "seed {seed}, round {round}: a resource name shifted the pressure"
        );

        // 4: a capacity of zero produces no pressure.
        assert_eq!(
            used.pressure(&Resources::default()),
            0,
            "seed {seed}, round {round}: an empty capacity produced pressure"
        );
    }

    // Without these assurances the run would confirm itself: a `pressure` that
    // always gives zero satisfies every invariant above.
    //
    // The thresholds are **measured**, not computed -- over three seeds 71 %
    // with pressure, 97 % with a capacity and 19 % with an entry of zero. What
    // is demanded is a twentieth, so fourteen-, nineteen- and fourfold room: a
    // threshold at the expected value would be the trap this tree has already
    // paid for once at the peer run.
    let total = iterations();
    assert!(
        with_pressure * 20 > total,
        "seed {seed}: only {with_pressure} of {total} rounds had any pressure \
         at all -- the acceptance path is not entered"
    );
    assert!(
        carried * 20 > total,
        "seed {seed}: only {carried} of {total} rounds had a capacity"
    );
    assert!(
        with_zero * 20 > total,
        "seed {seed}: only {with_zero} of {total} rounds had a capacity with an \
         entry of zero -- the `filter` branch is not entered"
    );
}
