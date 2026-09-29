//! The sidecar renews its SVID (ADR-0014, ADR-0035).
//!
//! Written **before** the implementation.
//!
//! # The finding
//!
//! `fetch_identity` was called **once** -- on the bootstrap runtime, which is
//! discarded afterwards -- and `Config::identity` was a value. No caller ever
//! fetched a new SVID.
//!
//! ADR-0014 gives an SVID **15 minutes**. After that time the sidecar's leaf
//! has expired, and `an_expired_svid_is_refused` (phase 8a) holds fast what a
//! verifier does with it: it refuses it. **A quarter of an hour after the
//! start every mTLS handshake of this sidecar thereby fails** -- the whole
//! data plane from ADR-0007. The tests never saw it, because they run seconds.
//!
//! The way for it has been built since 7c and was not used: "rotation comes as
//! a **push** over the open stream, not as an answer to a poll" (ADR-0035).
//! The server pushes; the sidecar did not listen.
//!
//! # Why the chain is checked at the handshake and not at the field
//!
//! A test that only reads `SharedIdentity::current()` shows that a field is
//! different. What counts is what `rustls` **puts on the wire** -- and that is
//! decided by the certificate resolver, not by the field.

use std::sync::Arc;
use std::time::Duration;

use tg_identity::{Authority, Lifetime, LocalSigner, SpiffeId, TrustDomain, self_signed_ca};
use tg_proxy::identity::{Identity, SharedIdentity};
use tg_proxy::policy::{PolicyCache, RevocationWindow, Snapshot};
use tg_proxy::verify::{Bundle, Enforcement, PeerVerifier, SharedPolicy};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const YEAR: i64 = 365 * 24 * 60 * 60;

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("valid")
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs(),
    )
    .expect("fits")
}

struct Pki {
    anchor: Vec<u8>,
    authority: Authority<LocalSigner>,
}

impl Pki {
    fn new() -> Self {
        let signer = LocalSigner::generate().expect("the key");
        let ca = self_signed_ca(&domain(), &signer, 0, 10 * YEAR).expect("the CA");
        let anchor = ca.certificate_der().to_vec();
        let authority = Authority::new(ca, signer, Lifetime::default()).expect("the issuer");

        Self { anchor, authority }
    }

    fn identity(&self, workload: &str) -> Identity {
        let id = SpiffeId::for_workload(&domain(), workload).expect("the ID");
        let svid = self.authority.issue(&id, now()).expect("the SVID");

        Identity::new(
            &id.to_string(),
            vec![svid.certificate_der().to_vec()],
            svid.private_key_der().to_vec(),
        )
        .expect("the identity")
    }
}

fn policy() -> SharedPolicy {
    let mut cache = PolicyCache::new(RevocationWindow::adr_0014());
    cache
        .apply(
            &Snapshot::from_edges(1, vec![("api".to_owned(), "api".to_owned())]),
            now(),
        )
        .expect("the snapshot");

    SharedPolicy::new(cache)
}

/// Accepts an mTLS connection and gives back the **leaf** the client
/// presented.
///
/// The DER bytes are compared: two SVIDs of the same workload differ in serial
/// number, key and validity -- a foreign parser for that would be a dependency
/// for nothing.
async fn leaf_presented_by_client(
    listener: TcpListener,
    identity: &SharedIdentity,
    anchor: &[u8],
) -> Vec<u8> {
    let verifier = PeerVerifier::new(
        SpiffeId::for_workload(&domain(), "api").expect("the ID"),
        SharedBundle::new(Bundle::from_der(vec![anchor.to_vec()])),
        policy(),
        Enforcement::Inbound,
    );
    let config =
        tg_proxy::tls::server_config(identity, verifier).expect("the server configuration");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let (stream, _) = listener.accept().await.expect("the connection");
    let tls = acceptor.accept(stream).await.expect("the handshake");
    let (_, connection) = tls.get_ref();
    connection
        .peer_certificates()
        .expect("the client chain")
        .first()
        .expect("the leaf")
        .to_vec()
}

/// **An exchanged SVID lies on the wire** -- over **the same** `rustls`
/// configuration.
///
/// That is the actual statement, and this test's first attempt missed it: it
/// built a new configuration per round, and `Rotating::new` reads the current
/// state anyway in the process. The counter-check -- the resolver never looks
/// again -- stayed **green**, and the test checked past its object.
///
/// In operation the configuration arises **once per shard at startup** and
/// lives as long as the sidecar. Exactly that way it stands here: built once,
/// two handshakes, an exchange in between.
#[tokio::test(flavor = "multi_thread")]
async fn a_rotated_svid_reaches_the_wire() {
    let pki = Pki::new();
    let identity = SharedIdentity::new(pki.identity("api"));
    let first = identity.current().chain()[0].to_vec();

    // **Built once**, as in operation.
    let verifier = PeerVerifier::new(
        SpiffeId::for_workload(&domain(), "api").expect("the ID"),
        SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()])),
        policy(),
        Enforcement::Outbound,
    );
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        tg_proxy::tls::client_config(&identity, verifier).expect("the client configuration"),
    ));

    let mut leaves = Vec::new();
    for round in 0..2 {
        if round == 1 {
            // What the open stream pushes (ADR-0035).
            identity.replace(pki.identity("api"));
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("the socket");
        let addr = listener.local_addr().expect("the address");
        let server = {
            let identity = identity.clone();
            let anchor = pki.anchor.clone();
            tokio::spawn(
                async move { leaf_presented_by_client(listener, &identity, &anchor).await },
            )
        };

        let stream = TcpStream::connect(addr).await.expect("connected");
        let name = rustls::pki_types::ServerName::try_from("api.cluster.local")
            .expect("the name")
            .to_owned();
        let mut tls = connector
            .connect(name, stream)
            .await
            .expect("the handshake");
        let _ = tls.write_all(b"x").await;
        let _ = tls.shutdown().await;
        let mut sink = Vec::new();
        let _ = tls.read_to_end(&mut sink).await;

        leaves.push(
            tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("in time")
                .expect("the task"),
        );
    }

    assert_ne!(
        identity.current().chain()[0].to_vec(),
        first,
        "the fixture must really have exchanged"
    );
    assert_ne!(
        leaves[0], leaves[1],
        "the second handshake put the same leaf on the wire -- the exchange \
         does not reach `rustls`"
    );
}

/// **The identifier stays the same.**
///
/// A rotated SVID belongs to the same workload (ADR-0006). If the SPIFFE ID
/// changed with every rotation, every `may_talk` edge would be void after
/// fifteen minutes (ADR-0025).
#[test]
fn rotation_keeps_the_spiffe_id() {
    let pki = Pki::new();
    let identity = SharedIdentity::new(pki.identity("api"));
    let before = identity.current().id().clone();

    identity.replace(pki.identity("api"));

    assert_eq!(identity.current().id(), &before);
}

// ------------------------------------- the trust anchor (ADR-0014) -----

use tg_proxy::verify::SharedBundle;

/// **A delivered anchor takes effect** -- over **the same** verifier.
///
/// `PeerVerifier::set_bundle` existed since 8a and had **no caller** -- and
/// could have none: it took `&mut self`, and the verifier lives behind an
/// `Arc` in the `rustls` configuration. The form did not fit the place at
/// which it was needed.
///
/// The anchor weighs less than the SVID -- the root from ADR-0014 is
/// long-lived, while an SVID expires every fifteen minutes. It counts at the
/// **switch**: whoever introduces a second root would otherwise have to
/// restart every sidecar, and precisely that is the moment at which one does
/// not want to.
#[test]
fn a_delivered_anchor_takes_effect() {
    let known = Pki::new();
    let stranger = Pki::new();

    // At the beginning the verifier knows only the one root.
    let bundle = SharedBundle::new(Bundle::from_der(vec![known.anchor.clone()]));
    let verifier = PeerVerifier::new(
        SpiffeId::for_workload(&domain(), "api").expect("the ID"),
        bundle.clone(),
        policy(),
        Enforcement::Inbound,
    );

    let foreign = stranger.identity("api");
    let leaf = foreign.chain()[0].clone();
    let at = rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        u64::try_from(now()).expect("after 1970"),
    ));

    assert!(
        verifier.check(&leaf, &[], at).is_err(),
        "a foreign root must not carry at the beginning"
    );

    // What the stream delivers afterwards (ADR-0035).
    assert!(
        bundle.replace(Bundle::from_der(vec![
            known.anchor.clone(),
            stranger.anchor.clone(),
        ])),
        "the setup must bite"
    );

    assert!(
        verifier.check(&leaf, &[], at).is_ok(),
        "the delivered anchor does not reach the verifier"
    );
}

/// **An empty bundle is not taken over.**
///
/// It verifies nothing -- every handshake would fall. The stream can deliver
/// it (an agent that is just coming up), and fail-static here means: keep the
/// last usable state (ADR-0019).
#[test]
fn an_empty_bundle_is_refused() {
    let pki = Pki::new();
    let bundle = SharedBundle::new(Bundle::from_der(vec![pki.anchor.clone()]));

    let taken = bundle.replace(Bundle::from_der(Vec::new()));

    assert!(!taken, "an empty bundle must not be taken over");
    assert!(
        !bundle.current().is_empty(),
        "the previous anchor must apply on"
    );
}

/// **And the operator sees how long the SVID still carries.**
///
/// Without this metric a sidecar whose stream has torn down is not
/// distinguishable from a healthy one: it holds its old SVID and carries on
/// enforcing (ADR-0019) -- until the first handshake fails. The deadline is
/// thereby the number an alarm rule belongs on.
///
/// A **point in time** and no age, as with `tg_node_last_report`
/// (ADR-0057).
#[test]
fn the_svid_expiry_is_reported() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let pki = Pki::new();
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let expected = metrics::with_local_recorder(&recorder, || {
        let identity = pki.identity("api");
        let until = tg_identity::expires_at(&identity.chain()[0]).expect("the deadline");
        SharedIdentity::new(pki.identity("api")).replace(identity);
        until
    });

    let reported = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .find_map(|(key, _, _, value)| {
            (key.key().name() == tg_telemetry::names::PROXY_SVID_EXPIRES_AT).then_some(value)
        })
        .expect("the deadline must be reported");

    // On the **value**, not on the presence: a metric that carries just any
    // number says nothing to an operator.
    #[allow(clippy::cast_precision_loss)]
    let expected = expected as f64;
    assert!(
        matches!(reported, DebugValue::Gauge(seen) if (seen.into_inner() - expected).abs() < 1.0),
        "{reported:?} instead of {expected}"
    );
}

/// The rotation's cadence lies below the gauges' expiry deadline.
///
/// **An ordering condition across two crates** (ADR-0088): gauges expire after
/// 15 minutes, and `tg_proxy_svid_expires_at_timestamp_seconds` is set **only**
/// when a new SVID comes over the stream. If the rotation lead time lies above
/// the deadline, the time series disappears between two rotations -- and with
/// it `TardigradeSidecarSvidExpiring`, that is, precisely the alarm for a leaf
/// that is expiring.
///
/// ADR-0088 justified that with "the sidecar refreshes its points in time at a
/// one-minute cadence". For the edges and the egress that is true; for the
/// **SVID** it is not -- there the cadence is the lead time from ADR-0014,
/// measured seven minutes. That carries with more than double the room, but it
/// carries for a different reason than claimed there, and both numbers belong
/// to different crates.
///
/// Whoever changes either of the two makes this test red -- and thereby has
/// the conversation instead of losing a time series silently.
#[test]
fn the_rotation_outruns_the_gauge_decay() {
    let lead = tg_identity::Lifetime::default().rotate_after;
    let decay = Duration::from_secs(tg_telemetry::init::GAUGE_IDLE_SECONDS);

    assert!(
        lead * 2 <= decay,
        "the rotation lead time ({lead:?}) must lie below the expiry deadline \
         ({decay:?}) with room -- otherwise `{}` disappears between two \
         rotations",
        tg_telemetry::names::PROXY_SVID_EXPIRES_AT
    );

    // The counter direction, so that the assertion is not fulfilled by a
    // rotation that does not exist at all: a lead time of zero would mean that
    // rotation happens at **every** check, and then the comparison would say
    // nothing.
    assert!(
        !lead.is_zero(),
        "without a lead time there would be no cadence to compare against"
    );
}
