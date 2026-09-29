//! The server name from a **real** QUIC Initial (ADR-0092).
//!
//! The datagrams are recorded, not built: `curl --http3-only` over **ngtcp2
//! 1.22.1 with OpenSSL 3.5.7** -- foreign code that read RFC 9000 and RFC 9001
//! independently. The same yardstick as `dig` in phase 9c, `rust-spiffe` in 7c
//! and `curl` in 10d. The provenance and the recording stand in
//! `data/PROVENANCE.md`.
//!
//! A self-built datagram would be no substantiation: it would arise with the
//! same crypto with which it is read, and would show only
//! self-consistency.

use tg_proxy::quic::{Handshake, Peek, QuicError};

const NAMED: [&[u8]; 2] = [
    include_bytes!("data/named_0.bin"),
    include_bytes!("data/named_1.bin"),
];
const ANONYMOUS: [&[u8]; 2] = [
    include_bytes!("data/anon_0.bin"),
    include_bytes!("data/anon_1.bin"),
];

/// **The name comes out -- and only after the second datagram.**
///
/// The second half is the actual statement. OpenSSL 3.5's `ClientHello`
/// carries post-quantum key shares and does **not** fit into one Initial; a
/// reader that looks only at the first packet finds nothing here. Precisely
/// the finding for whose sake ADR-0092 determination 4 makes the CRYPTO
/// reassembly mandatory -- without the assertion on `Incomplete` it would not
/// be visible that it is needed at all.
#[test]
fn a_real_client_hello_needs_both_datagrams_and_then_names_itself() {
    let mut handshake = Handshake::new();

    assert_eq!(
        handshake.absorb(NAMED[0]),
        Ok(Peek::Incomplete),
        "one Initial alone does not carry the ClientHello -- whoever reads a \
         name here already did not get it from these bytes"
    );
    assert_eq!(
        handshake.absorb(NAMED[1]),
        Ok(Peek::Named("s3.example.com".to_owned())),
        "the name from the assembled ClientHello is missing"
    );
}

/// **A `ClientHello` without an SNI is unassignable.**
///
/// The same stack against an **IP**: OpenSSL then sends no server name. In the
/// egress that means deny -- the sidecar decides by the name the connection
/// itself names (ADR-0041), and here it names none.
#[test]
fn a_client_hello_without_a_name_is_anonymous() {
    let mut handshake = Handshake::new();

    assert_eq!(handshake.absorb(ANONYMOUS[0]), Ok(Peek::Incomplete));
    assert_eq!(
        handshake.absorb(ANONYMOUS[1]),
        Ok(Peek::Anonymous),
        "without an SNI no name may arise"
    );
}

/// **What is no Initial is refused** -- not guessed.
#[test]
fn a_datagram_that_is_not_a_quic_initial_is_refused() {
    for (what, bytes) in [
        ("empty", &b""[..]),
        ("a short header", &[0x40, 0x00, 0x00][..]),
        ("TLS over TCP", &[0x16, 0x03, 0x01, 0x00, 0x05][..]),
        (
            "a Handshake instead of an Initial",
            &[0xe0, 0x00, 0x00, 0x00, 0x01][..],
        ),
    ] {
        let mut handshake = Handshake::new();
        assert_eq!(
            handshake.absorb(bytes),
            Err(QuicError::NotInitial),
            "{what} was read as an Initial"
        );
    }
}

/// **A foreign version is named, not guessed.**
///
/// QUIC v2 (RFC 9369) carries a different salt. A packet whose key derivation
/// we do not know is one whose name we do not know -- and that is something
/// other than "no QUIC".
#[test]
fn an_unknown_version_is_refused_with_its_number() {
    let mut datagram = NAMED[0].to_vec();
    datagram[1..5].copy_from_slice(&0x6b33_43cfu32.to_be_bytes());

    let mut handshake = Handshake::new();
    assert_eq!(
        handshake.absorb(&datagram),
        Err(QuicError::UnsupportedVersion(0x6b33_43cf)),
        "QUIC v2 was read with v1's keys"
    );
}

/// **A truncated Initial is a finding, no half name.**
#[test]
fn a_truncated_initial_is_refused() {
    for cut in [20, 100, 600, 1199] {
        let mut handshake = Handshake::new();
        assert!(
            handshake.absorb(&NAMED[0][..cut]).is_err(),
            "an Initial that is missing {} bytes was read",
            NAMED[0].len() - cut
        );
    }
}

/// **A foreign connection ID does not decrypt.**
///
/// The Initial's keys hang on the destination connection ID (RFC 9001 §5.2).
/// One byte in it different, and the AEAD check falls -- that is the
/// counter-check to the fact that above there was really decryption and no
/// guessing.
#[test]
fn a_changed_connection_id_does_not_decrypt() {
    let mut datagram = NAMED[0].to_vec();
    datagram[6] ^= 0xff;

    let mut handshake = Handshake::new();
    assert_eq!(
        handshake.absorb(&datagram),
        Err(QuicError::Undecryptable),
        "an Initial with a foreign connection ID was decrypted"
    );
}

/// **The datagrams' order does not count.**
///
/// CRYPTO frames carry their offset; UDP gives no order. A reader that built
/// on it would see nothing at every reordered flight.
#[test]
fn the_datagrams_may_arrive_in_any_order() {
    let mut handshake = Handshake::new();

    assert_eq!(handshake.absorb(NAMED[1]), Ok(Peek::Incomplete));
    assert_eq!(
        handshake.absorb(NAMED[0]),
        Ok(Peek::Named("s3.example.com".to_owned())),
        "reordered, the name did not come out"
    );
}

/// **The same datagram twice shifts nothing.**
///
/// A client repeats its Initial when no answer comes -- measured, `curl` sends
/// four of them. Whoever concatenates the fragments instead of ordering them
/// by offset would get a twice as long `ClientHello` out of it.
#[test]
fn a_repeated_datagram_changes_nothing() {
    let mut handshake = Handshake::new();

    assert_eq!(handshake.absorb(NAMED[0]), Ok(Peek::Incomplete));
    assert_eq!(handshake.absorb(NAMED[0]), Ok(Peek::Incomplete));
    assert_eq!(
        handshake.absorb(NAMED[1]),
        Ok(Peek::Named("s3.example.com".to_owned())),
        "the repeat shifted the assembly"
    );
}

/// **Repeats run into a bound -- and it sits far enough above** (ADR-0092,
/// determination 4).
///
/// The bytes come from a container, so a client must not tie up memory with
/// fragments. The bound is `MAX_CRYPTO` and private; what is checked is
/// therefore the **effect**: at some point `absorb` refuses, with a reason.
///
/// **And the second half carries the first.** A `Handshake` that refuses every
/// datagram would be "bounded" too -- and would take every container's way
/// out. What is demanded is therefore that the bound lies **above** what a
/// real client sends: the neighbouring test measured that `curl` repeats its
/// Initial **four** times. A factor of five is the ordering condition between
/// the two numbers -- until here they stood in two files and had no
/// relationship.
///
/// Measured at today's recordings it bursts in round **62**: 64 KiB divided by
/// around 1080 CRYPTO bytes per datagram. The number belongs to the fixtures,
/// the relationship is the assurance.
#[test]
fn repeats_run_into_a_ceiling_that_sits_far_above_a_real_client() {
    /// What `curl` measurably sends (see `a_repeated_datagram_changes_nothing`).
    const REAL_RETRANSMISSIONS: usize = 4;

    let mut handshake = Handshake::new();
    let mut accepted = 0_usize;

    // An upper bound so that a `Handshake` without a bound does not run
    // forever: a test that hangs is worse than one that fails.
    let refusal = (1..=10_000).find_map(|_| match handshake.absorb(NAMED[0]) {
        Ok(_) => {
            accepted += 1;
            None
        }
        Err(err) => Some(err),
    });

    let Some(err) = refusal else {
        panic!(
            "after {accepted} repeats the assembler still does not refuse -- a \
             container could thereby tie up memory"
        );
    };

    assert_eq!(
        err,
        QuicError::TooMuch,
        "the refusal is to name the bound and not something else"
    );
    assert!(
        accepted > REAL_RETRANSMISSIONS * 5,
        "the bound bites after {accepted} repeats -- a real client sends \
         {REAL_RETRANSMISSIONS}, and a factor of five is the minimum so that a \
         duplicating network costs no handshake"
    );
}

/// **Two Initials in one datagram** -- coalesced, as a real client sends
/// them.
///
/// The loop in `absorb` reads several packets in a row; until now only the
/// case "one datagram, one packet" was checked, because the recordings lie
/// separately. Concatenated they are exactly the form RFC 9000 §12.2 permits
/// -- and the name comes out of **one** call.
#[test]
fn two_initials_in_one_datagram_yield_the_name() {
    let mut datagram = NAMED[0].to_vec();
    datagram.extend_from_slice(NAMED[1]);

    let mut handshake = Handshake::new();
    assert_eq!(
        handshake.absorb(&datagram),
        Ok(Peek::Named("s3.example.com".to_owned())),
        "two coalesced Initials must carry in one call"
    );
}

/// **Four packets per datagram, the fifth is no longer read**
/// (`MAX_PACKETS`).
///
/// The bound against a datagram that occupies the reader with coalesced
/// packets -- the bytes come from a container (ADR-0092).
///
/// # The setup is discriminating, and without a single self-built byte
///
/// The name arises only from **both** recordings (OpenSSL 3.5's `ClientHello`
/// does not fit into one Initial). If the second stands in **fifth** place,
/// the bound cuts it off; in fourth it carries. That is the same comparison
/// with **one** thing different -- the number of fillers before it.
///
/// An assertion on `Incomplete` alone would say nothing: five copies of the
/// same packet yield no complete `ClientHello` even without a bound.
#[test]
fn a_fifth_coalesced_packet_is_not_read() {
    let mut over = Vec::new();
    for _ in 0..4 {
        over.extend_from_slice(NAMED[0]);
    }
    over.extend_from_slice(NAMED[1]);

    let mut handshake = Handshake::new();
    assert_eq!(
        handshake.absorb(&over),
        Ok(Peek::Incomplete),
        "the fifth packet must no longer be read"
    );

    // One filler fewer: four packets, and the name comes.
    let mut within = Vec::new();
    for _ in 0..3 {
        within.extend_from_slice(NAMED[0]);
    }
    within.extend_from_slice(NAMED[1]);

    let mut handshake = Handshake::new();
    assert_eq!(
        handshake.absorb(&within),
        Ok(Peek::Named("s3.example.com".to_owned())),
        "in fourth place the same packet must carry -- otherwise the \
         comparison above does not check the bound"
    );
}

/// **A connection ID over twenty bytes is refused** (`MAX_CID`,
/// RFC 9000 §17.2).
///
/// The **first** place at which the reader reads a **length** named by the
/// sender -- and the bytes come from a container. Without the bound it would
/// be a length byte that determines how much is read.
///
/// # Why a built header is legitimate here
///
/// The check sits **before** the crypto: `Reader::cid` bites while parsing the
/// long header, long before there is any decryption. What is checked is
/// thereby **our counting** and not the format -- unlike with the recordings
/// above, where a self-built packet would show only self-consistency.
///
/// # The bound lies exactly, and that is half the assurance
///
/// At **twenty** bytes `Undecryptable` comes: the header was read completely,
/// and it fails only at the crypto (this built packet's Initial keys do not
/// fit). At **twenty-one** `Malformed` comes -- that is, the bound. Without
/// the first half a check that refuses every CID would be green too.
#[test]
fn a_connection_id_over_twenty_bytes_is_refused() {
    // A long header per RFC 9000 §17.2: the type byte, the version, the DCID
    // length, the DCID, the SCID length, the SCID, the token length, the
    // length, the payload.
    fn header(dcid: u8, scid: u8) -> Vec<u8> {
        let mut bytes = vec![0xC3, 0x00, 0x00, 0x00, 0x01, dcid];
        bytes.extend(std::iter::repeat_n(0xAB, usize::from(dcid)));
        bytes.push(scid);
        bytes.extend(std::iter::repeat_n(0xCD, usize::from(scid)));
        bytes.push(0x00); // the token length, varint 0
        bytes.extend([0x40, 0x20]); // the length, varint 32
        bytes.extend(std::iter::repeat_n(0x00, 32));
        bytes
    }

    assert_eq!(
        Handshake::new().absorb(&header(20, 0)),
        Err(QuicError::Undecryptable),
        "twenty bytes are permitted -- the header must be read"
    );
    assert_eq!(
        Handshake::new().absorb(&header(21, 0)),
        Err(QuicError::Malformed),
        "twenty-one is not"
    );

    // The same bound applies to the second identifier: `cid` is called twice.
    assert_eq!(
        Handshake::new().absorb(&header(8, 21)),
        Err(QuicError::Malformed),
        "the source identifier is bounded too"
    );
}
