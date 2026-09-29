//! A fuzz run against the **data plane's** trust boundary (ADR-0007/0025).
//!
//! The bytes [`PeerVerifier::check`] sees are the counterpart's certificate of
//! an mTLS handshake. Whoever reaches the sidecar port presents them -- after
//! the mesh redirect (ADR-0060), that is, every container of the node. That is
//! a trust boundary, and there a fuzz run is mandatory.
//!
//! # Why it exists only now
//!
//! The cluster verifier has had its own since ADR-0043 (`fuzz_cluster_trust`).
//! The data plane had none -- the same asymmetry as with the guard for
//! `client_auth_mandatory`, and again the more exposed side was the
//! unprotected one.
//!
//! # The lesson from phase 9c is applied
//!
//! Pure randomness never produces a parsable certificate; the first DNS fuzzer
//! was therefore **empty** and confirmed every invariant itself. The run
//! therefore produces **valid leaves and damages them**, and an assurance at
//! the end holds fast that a minimum share was accepted at all.
//!
//! Conventions as in the other runs: a fresh seed per run,
//! `TG_FUZZ_ITERATIONS` with the release threshold as the default. A failure
//! reports its seed and belongs nailed down as a seeded regression test -- it
//! is a finding, no flakiness.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use rustls_pki_types::{CertificateDer, UnixTime};
use tg_identity::{Authority, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};
use tg_proxy::policy::{PolicyCache, RevocationWindow, Snapshot};
use tg_proxy::verify::{Bundle, Enforcement, PeerVerifier, SharedBundle, SharedPolicy};

const DEFAULT_ITERATIONS: u32 = 20_000;
const YEAR: i64 = 365 * 24 * 60 * 60;
const NOW: u64 = 1_800_000_000;

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

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("the trust domain")
}

/// **No damaged leaf ever gets through as a foreign workload.**
///
/// Three invariants, all absolute:
///
/// 1. Every buffer leads to `Ok` or to a named reason -- never to a panic.
/// 2. If one is accepted, it carries a SPIFFE ID of **our** trust domain.
/// 3. And for that identity there is a `may_talk` edge. That is
///    deny-by-default (ADR-0025), and it is the assurance that counts: a
///    damaged leaf must never get another's role.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "a fuzz run is setup, loop and assurance in one piece; taking \
              it apart would spread the invariant over three functions"
)]
fn no_mutated_leaf_is_ever_accepted_as_a_foreign_workload() {
    let seed = fresh_seed();
    let mut rng = Rng(seed);
    let domain = domain();

    // Our CA -- and a foreign one beside it, whose leaves must never get
    // through, however plausible they look.
    let signer = LocalSigner::generate().expect("the key");
    let ca = self_signed_ca(&domain, &signer, 0, 10 * YEAR).expect("the CA");
    let anchor = ca.certificate_der().to_vec();
    let ours = Authority::new(ca, signer, Lifetime::default()).expect("the issuer");

    let foreign_signer = LocalSigner::generate().expect("the key");
    let foreign_ca = self_signed_ca(&domain, &foreign_signer, 0, 10 * YEAR).expect("the CA");
    let foreign =
        Authority::new(foreign_ca, foreign_signer, Lifetime::default()).expect("the issuer");

    // `api` may talk with `ledger`, `foreign` with nobody.
    let mut cache = PolicyCache::new(RevocationWindow::adr_0014());
    cache
        .apply(
            &Snapshot::from_edges(1, vec![("api".to_owned(), "ledger".to_owned())]),
            0,
        )
        .expect("the edges");
    let policy = SharedPolicy::new(cache);

    let local = SpiffeId::for_workload(&domain, "ledger").expect("the ID");
    let verifier = PeerVerifier::new(
        local,
        SharedBundle::new(Bundle::from_der(vec![anchor])),
        policy,
        Enforcement::Inbound,
    );

    // Four base leaves: permitted, not permitted, and both from the foreign
    // CA. Without the last two the run would check only the parser.
    let mut leaves: Vec<(&str, bool, Vec<u8>)> = Vec::new();
    for (name, authority, ours_ca) in [
        ("api", &ours, true),
        ("foreign", &ours, true),
        ("api", &foreign, false),
        ("foreign", &foreign, false),
    ] {
        let id = SpiffeId::for_workload(&domain, name).expect("the ID");
        let svid = authority
            .issue(&id, i64::try_from(NOW).unwrap_or(0))
            .expect("the SVID");
        leaves.push((name, ours_ca, svid.certificate_der().to_vec()));
    }

    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(NOW));
    let total = iterations();
    let mut accepted = 0_u32;

    for round in 0..total {
        let (origin, from_ours, base) = &leaves[rng.below(leaves.len())];
        let mut bytes = base.clone();

        // Damaging: swap bytes, truncate, append, turn blocks.
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
            // Undamaged: the run must hit the normal case too, otherwise we
            // measure only the parser.
            _ => {}
        }

        let verdict = verifier.check(&CertificateDer::from(bytes.clone()), &[], now);

        match verdict {
            Ok(id) => {
                accepted += 1;

                // **The load-bearing assertion.** A mutation cannot make a
                // leaf signed by our CA out of one signed by a foreign one --
                // that would be a signature forgery. If one is accepted whose
                // origin is the foreign CA, the chain check did not bite.
                // Without this line the run would stay green if `verify_chain`
                // fell out: a foreign leaf for `api` passes all the other
                // assertions.
                assert!(
                    *from_ours,
                    "round {round}, seed {seed}: a leaf of the foreign CA was \
                     accepted (base leaf {origin})"
                );
                assert_eq!(
                    id.trust_domain(),
                    &domain,
                    "round {round}, seed {seed}: a foreign trust domain was \
                     accepted (base leaf {origin})"
                );
                assert_eq!(
                    id.workload(),
                    Some("api"),
                    "round {round}, seed {seed}: accepted without an edge \
                     (base leaf {origin})"
                );
            }
            // Every named reason is all right; the assertion is that there
            // **is** one and no panic.
            Err(reason) => {
                assert!(
                    !reason.to_string().is_empty(),
                    "round {round}, seed {seed}: a refusal without a reason"
                );
            }
        }
    }

    // **Without this assurance the run would confirm itself.** A run in
    // which a leaf is never accepted upholds every invariant above without
    // touching the path it is about -- the finding from phase 9c.
    //
    // **One per cent, and the number is computed, not guessed.** The expected
    // value lies at **five** per cent, and by construction at that: one of
    // five mutation cases leaves the leaf unchanged, and one of four base
    // leaves is acceptable. Measured over eight seeds: 942 to 1055 of 20 000.
    //
    // The first version demanded exactly those five per cent -- that is, the
    // **expected value itself**, whereby about every second run would have
    // fallen. A fuzz run that is red half the time gets switched off instead
    // of read. A fifth of it leaves the spread room and nevertheless catches
    // what it is about: a run that does **not** touch the acceptance path.
    assert!(
        accepted * 100 >= total,
        "seed {seed}: only {accepted} of {total} leaves accepted -- the run \
         hardly touched the acceptance path"
    );
}
