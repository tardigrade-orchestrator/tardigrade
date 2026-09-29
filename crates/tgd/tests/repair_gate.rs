//! The gate of the RTS repair (ADR-0108, determination 3).
//!
//! The **one** new authorization rule of this ADR: a sigma for seat `N` goes only
//! to a caller that **is** seat `N`. It needs no new auth system, only a
//! comparison -- and that rests on the service knowing the caller's seat
//! (`Seats::seat_of` over the node name from the credential, ADR-0097).
//!
//! Why it is necessary at all is measured and stands in ADR-0108: `t`
//! passed-through sigmas **are** the input of step 3 and yield the share. A
//! coordinator that saw them would be the trusted dealer.
//!
//! Separated from `SignerService` so that the rule is checkable without a port: an
//! access rule one can only see at the running service is one whose rejection path
//! nobody has seen -- the same argument as at `admin::may_administer` and
//! `admin::class_of`.

use tgd::signer::may_receive_sigma;

/// **Only the seat itself.**
#[test]
fn a_sigma_goes_only_to_the_seat_it_concerns() {
    assert!(may_receive_sigma(Some(4), 4));
    assert!(!may_receive_sigma(Some(3), 4), "a helper must not see it");
    assert!(!may_receive_sigma(Some(5), 4));
}

/// **Without a credential nothing** -- and that is the difference from the admin
/// socket.
///
/// There `None` means "the Unix socket", and whoever reaches it may do anything
/// (ADR-0044, determination 4). Here `None` is a connection **without** a
/// certificate on a port that demands one (ADR-0097) -- or a leaf whose node name
/// represents no seat in the admission list. Neither is a reason to hand out a
/// sigma.
#[test]
fn without_a_seat_in_the_certificate_nothing() {
    assert!(!may_receive_sigma(None, 4));
    assert!(!may_receive_sigma(None, 1));
}

// --- Every route is dispatched ---------------------------------------------

/// **Every route of the signer port has an arm** in `SignerService::call`.
///
/// The guard the compiler cannot be: `&str` constants are not enumerable, and the
/// `_ =>` arm catches every one nobody dispatches.
///
/// Why that counts is **measured**: a route without an arm answers
/// `unimplemented("unknown method")` -- and both gRPC services of this process say
/// exactly the same. From the message it could not be read which port a call had
/// hit; half an hour went into the search for that. The guard catches the case
/// before it needs a diagnosis.
///
/// What it **cannot** do stands with it: say whether the arm calls the right
/// service. That is said by the witnesses at the real port (`tgd/tests/signing.rs`).
#[test]
fn every_signer_route_is_dispatched() {
    let routes = include_str!("../../tg-identity/src/threshold/wire.rs");
    let dispatch = include_str!("../src/signer.rs");
    let mut seen = 0;
    let mut orphans = Vec::new();

    for line in routes.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": &str = ") else {
            continue;
        };
        if !value.contains("/tardigrade.signer.v1.Signer/") {
            continue;
        }
        seen += 1;
        // The arm names the **constant**, not the path -- that is why the search
        // is for its name and not for the string.
        if !dispatch.contains(&format!("{name} => Box::pin")) {
            orphans.push(name.to_owned());
        }
    }

    assert!(
        seen > 8,
        "only {seen} routes were found -- the guard no longer reads the source \
         correctly"
    );
    assert!(
        orphans.is_empty(),
        "these routes of the signer port are not dispatched and answer \
         `Unimplemented`: {orphans:?}"
    );
}
