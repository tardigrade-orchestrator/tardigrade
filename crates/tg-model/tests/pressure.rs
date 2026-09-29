//! What "least occupied" means with several resources (ADR-0109).
//!
//! The planner's selection rule stood in ADR-0034 as **one sentence** and was
//! no statement with a resource **map**; the gap was filled by a derived `Ord`
//! that compares lexicographically — that is, by the alphabetically first
//! resource name. These witnesses record that the **occupancy** decides now.

use tg_model::placement::Resources;

/// The pressure is the utilization of the **scarcest** resource (ADR-0109).
///
/// The two cases are the measured ones from the ADR, and lexicographically they
/// come out **differently** — without this counter-direction the witness would
/// be satisfied by the old rule too.
#[test]
fn the_fullest_resource_decides_not_the_first_name() {
    let cpu = Resources::CPU_MILLICORES;
    let mem = Resources::MEMORY_BYTES;
    let capacity = Resources::default()
        .with(cpu, 4000)
        .with(mem, 16_000_000_000);

    // Case 1: A holds 9 GB, B only 200 millicores.
    let a = Resources::default().with(cpu, 100).with(mem, 9_000_000_000);
    let b = Resources::default().with(cpu, 200);
    assert!(
        a.pressure(&capacity) > b.pressure(&capacity),
        "a node with 9 GB occupied is not the emptier one: A={} B={}",
        a.pressure(&capacity),
        b.pressure(&capacity)
    );

    // Case 2: A holds five bytes, B a million millicores.
    let a = Resources::default().with(mem, 5);
    let b = Resources::default().with(cpu, 999_999);
    assert!(
        a.pressure(&capacity) < b.pressure(&capacity),
        "a million occupied millicores is not less than five bytes: A={} B={}",
        a.pressure(&capacity),
        b.pressure(&capacity)
    );
}

/// **A resource without capacity produces no pressure** (determination 2).
///
/// Counting happens over the capacity and not over the occupancy: there is
/// thereby no division by zero, and a node without declared capacity has
/// pressure zero — it takes only workloads without a resource request, for
/// `fits` admits nothing else there.
///
/// # Which layer carries that
///
/// The second assurance (`with(cpu, 0)`) is green because `Resources::with`
/// does **not enter** the zero at all — not because of the filter in
/// `pressure`. Only the way over `minus` reaches that one, and
/// `a_capacity_eaten_by_its_reserve_divides_by_nothing` checks it beside
/// this.
#[test]
fn a_resource_without_capacity_carries_no_pressure() {
    let cpu = Resources::CPU_MILLICORES;
    let used = Resources::default().with(cpu, 1);

    assert_eq!(used.pressure(&Resources::default()), 0);
    assert_eq!(used.pressure(&Resources::default().with(cpu, 0)), 0);

    // The counter-check to the assurance on which determination 2 rests: a
    // request does not get onto a node without capacity.
    assert!(
        !Resources::default()
            .with(cpu, 1)
            .fits(&Resources::default(), &Resources::default()),
        "a resource request must not fit onto a node without capacity"
    );
}

/// **The resolution is finite, and that is the cost side.**
///
/// At 16 GB capacity one byte and two bytes are the same pressure; then the
/// name decides (ADR-0034, unchanged). The lexicographic ordering was finer
/// there — but a planner that prefers a node because of one byte does nothing
/// useful.
#[test]
fn a_difference_below_the_resolution_is_a_tie() {
    let mem = Resources::MEMORY_BYTES;
    let capacity = Resources::default().with(mem, 16_000_000_000);

    let one = Resources::default().with(mem, 1);
    let two = Resources::default().with(mem, 2);
    assert_eq!(one.pressure(&capacity), two.pressure(&capacity));

    // And the counter-direction: what lies above the resolution is not.
    let much = Resources::default().with(mem, 1_000_000_000);
    assert!(one.pressure(&capacity) < much.pressure(&capacity));
}

/// **A resource name shifts nothing** (ADR-0109, positive).
///
/// The same state under an alphabetically earlier name yields the same
/// pressure. Under the old rule the name would have decided the selection
/// (`"aaa" < "zzz"`, and the key comparison comes before the value).
///
/// # What it does not guard
///
/// Measured, it falls at **no** mutation to [`Resources::pressure`]: the
/// independence from names follows structurally from a name being only the key
/// for `get` there. It stands as a **statement about the decision** (ADR-0109,
/// positive consequence) and not as a guard — only somebody who rebuilt the
/// lexicographic rule could break it.
#[test]
fn renaming_a_resource_changes_no_pressure() {
    let capacity = Resources::default().with("aaa", 1000).with("zzz", 1000);
    let early = Resources::default().with("aaa", 500);
    let late = Resources::default().with("zzz", 500);

    assert_eq!(early.pressure(&capacity), late.pressure(&capacity));
}

/// **A zero never becomes an entry** — on this way.
///
/// `Resources::with` filters it silently, and the producers from the command
/// line go through this function (`tgctl node upsert --resource name=0` lands
/// here). `minus` and `plus` do **not** — see the witness below.
#[test]
fn a_zero_never_becomes_an_entry() {
    let cpu = Resources::CPU_MILLICORES;

    assert!(Resources::default().with(cpu, 0).is_empty());
    assert_eq!(Resources::default().with(cpu, 0).entries(), Vec::new());

    // And the counter-direction: what lies above zero is entered -- otherwise
    // a `with` that enters nothing at all would be just as green.
    assert_eq!(
        Resources::default().with(cpu, 1).entries(),
        vec![(cpu, 1_u64)]
    );

    // An overwrite with zero does not clear the entry away either: that is
    // measured and belongs recorded, because it would be the other reading.
    let before = Resources::default().with(cpu, 5);
    assert_eq!(before.clone().with(cpu, 0).get(cpu), 5);
}

/// **A capacity eaten by its reserve does not divide by zero.**
///
/// That is the way that reaches the `filter` in [`Resources::pressure`] — and
/// it does **not** go over `with`: `minus` writes directly into the map and
/// saturates (ADR-0047, "a reserve larger than the capacity yields zero"). The
/// map is **not** empty afterwards, it carries an entry with the value zero.
///
/// Reachable with an ordinary action: `tgctl node upsert n1 --resource
/// cpu-millicores=1000 --reserve cpu-millicores=1000`. Without the filter the
/// consequence would be a panic in the scheduler task (ADR-0082) — and with it
/// the end of every lease renewal (ADR-0064).
#[test]
fn a_capacity_eaten_by_its_reserve_divides_by_nothing() {
    let cpu = Resources::CPU_MILLICORES;
    let free = Resources::default()
        .with(cpu, 1000)
        .minus(&Resources::default().with(cpu, 1000));

    // The half of the assurance: the map really still carries the entry.
    // Without it the test would be satisfied by a `minus` that clears it away
    // too -- and then it does not check the filter.
    assert!(!free.is_empty(), "minus cleared the entry away");
    assert_eq!(free.entries(), vec![(cpu, 0_u64)]);

    // And the planner computes on that.
    assert_eq!(Resources::default().with(cpu, 5).pressure(&free), 0);
    assert_eq!(Resources::default().pressure(&free), 0);
}
