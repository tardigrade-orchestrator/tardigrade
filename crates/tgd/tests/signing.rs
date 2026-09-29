//! The signing group over five processes (ADR-0097).
//!
//! The actual proof: **no process holds the CA key**, and nevertheless an SVID
//! arises whose chain carries against the group key. Three shares travel for that
//! over mTLS paths that each demand a leaf in a list.
//!
//! # Why one leader and four seats
//!
//! ADR-0014 decouples the signing group **from the Raft membership**, and exactly
//! that is what this setup checks: one node leads and issues, the remaining four
//! run only their signer port. Were there five cluster members, the decoupling
//! would not be visible -- it would look like an agreement that happens to hold.

mod support;

use std::path::Path;
use std::process::Command as OsCommand;

use rustls_pki_types::{CertificateDer, UnixTime};
use tg_identity::control::{Credentials, IdentityClient, JoinRequest};
use tg_identity::threshold::{GroupShape, Material, OsEntropy, PlainCustody, Seat, dkg};

use tg_identity::{SpiffeId, TrustDomain};
use tgd::admin::AdminClient;

/// Reads material **the way `tgd` reads it** (ADR-0140).
///
/// Not with `PlainCustody`: a seat that runs on a machine with a TPM files its
/// share as an **envelope**, and a witness that expects it in the clear checks a
/// disk that does not exist there. The custody comes from the same function as in
/// the process -- two ways would be two opportunities to differ.
fn material_at(dir: &std::path::Path) -> Result<Material, tg_identity::threshold::ThresholdError> {
    let custody = tg_identity::threshold::custody_for(&tg_identity::layout::signing(dir))?;

    Material::load(dir, custody.as_ref())
}

/// The token for the invitation.
const TOKEN: &str = "s3kr3t-token-for-the-group-0001";

/// A node of the line-up: its directory, its ports, its seat.
struct Node {
    seat: u16,
    dir: tempfile::TempDir,
    signer_port: u16,
    identity_port: u16,
    /// The telemetry endpoint.
    ///
    /// **Remembered and not merely set**: the share's generation is a metric
    /// (ADR-0107), and without the port it would not be queryable in the test
    /// rig.
    telemetry_port: u16,
    leaf_pem: String,
}

/// Runs the ceremony and creates a data directory for every seat.
///
/// **The same ceremony function as `cargo xtask threshold`** -- one source, not a
/// copy in the test rig (ADR-0097, determination 5).
fn prepare(shape: GroupShape, forge: &[u16]) -> (Vec<Node>, Vec<u8>) {
    let mut entropy = OsEntropy;
    let done = dkg::ceremony(shape, &mut entropy).expect("the ceremony must carry");

    // The CA certificate over the group key: here the test rig signs with all
    // five shares -- the only moment in which anybody can. Afterwards the key lies
    // nowhere in full.
    let (anchor_pem, anchor_der) = certify(shape, &done);

    let mut nodes = Vec::new();
    for (seat, share, group) in &done {
        let dir = tempfile::tempdir().expect("tempdir");
        Material::save(
            dir.path(),
            share,
            group,
            tg_identity::threshold::Epoch::GENESIS,
            &PlainCustody,
        )
        .expect("material");

        let signing = tg_identity::layout::signing(dir.path());
        std::fs::write(signing.join(tg_identity::layout::CA), &anchor_pem).expect("CA");
        std::fs::write(signing.join(tg_identity::layout::BUNDLE), &anchor_pem).expect("bundle");

        // Every seat gets a node key of its **own**: its leaf is the credential
        // it presents on the signer port, and with a shared key the list would be
        // no distinction.
        let identity = tg_identity::layout::dir(dir.path());
        std::fs::create_dir_all(&identity).expect("directory");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
        std::fs::write(
            identity.join(tg_identity::layout::NODE_KEY),
            key.serialize_pem(),
        )
        .expect("key");
        let id = SpiffeId::for_node(&domain(), &format!("tgd-{}", seat.number())).expect("ID");
        let leaf_pem = tg_identity::cluster::node_leaf_pem(&key, &id).expect("leaf");

        nodes.push(Node {
            seat: seat.number(),
            dir,
            signer_port: support::free_port(),
            identity_port: support::free_port(),
            telemetry_port: support::free_port(),
            leaf_pem,
        });
    }

    // Leaves that belong to no seat of this line-up -- for `forge`.
    //
    // **A name of its own per seat**, and that is enforced by a bolt: a single
    // `tgd-foreign` for three seats is a **name collision**, and `Seats::load`
    // refuses both bearers (ADR-0097). The leader would afterwards have two
    // admissions, would not load the signing CA and would not run the identity
    // port at all -- the rejection would come from `Unimplemented` instead of from
    // the handshake, and the witness would say nothing about determination 2.
    //
    // Nobody noticed it before: the old `load` made **one** entry out of the three
    // foreign leaves and nevertheless reported five admissions.
    let strangers: std::collections::BTreeMap<u16, String> = forge
        .iter()
        .map(|seat| {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
            let id = SpiffeId::for_node(&domain(), &format!("tgd-foreign-{seat}")).expect("ID");
            let pem = tg_identity::cluster::node_leaf_pem(&key, &id).expect("leaf");
            (*seat, pem)
        })
        .collect();

    // The leaves crosswise: every node needs the **others'**, otherwise their
    // call does not get through (ADR-0097, determination 2). In operation an
    // operator distributes them; here the test rig stands in for them.
    for node in &nodes {
        let signers = tg_identity::layout::signers(node.dir.path());
        std::fs::create_dir_all(&signers).expect("directory");
        for other in &nodes {
            // `forge` names the seats for which the **first** node gets a foreign
            // leaf -- the case from determination 2 in its pure form: the file is
            // there, the port listens, and the leaf does not belong to this seat.
            //
            // A **missing** leaf does not do for that: the same list carries the
            // port's admission *and* the call's binding (`Seats::dial`), so a seat
            // without a leaf runs no signer port at all. The rejection would then
            // come from "Connection refused" and would say nothing about mTLS.
            let pem = match strangers.get(&other.seat) {
                Some(stranger) if node.seat == 1 => stranger,
                _ => &other.leaf_pem,
            };
            std::fs::write(signers.join(format!("{}.pem", other.seat)), pem).expect("leaf");
        }
    }

    (nodes, anchor_der)
}

/// Issues the CA certificate over the group key.
fn certify(
    shape: GroupShape,
    done: &[(
        tg_identity::threshold::Seat,
        tg_identity::threshold::KeyPackage,
        tg_identity::threshold::PublicKeyPackage,
    )],
) -> (String, Vec<u8>) {
    use std::sync::Arc;
    use tg_identity::threshold::{
        LocalLink, Participant, PlainCustody, SignerLink, ThresholdSigner,
    };

    let mut links: Vec<Arc<dyn SignerLink>> = Vec::new();
    for (seat, share, group) in done {
        let participant = Participant::new(
            *seat,
            share,
            group,
            tg_identity::threshold::Epoch::GENESIS,
            Arc::new(PlainCustody),
        )
        .expect("seal");
        links.push(Arc::new(LocalLink::new(participant, Box::new(OsEntropy))));
    }
    let group = done.first().expect("a seat").2.clone();
    let signer = ThresholdSigner::new(group, shape, links).expect("group");

    let ca = tg_identity::self_signed_ca(&domain(), &signer, 0, 4_000_000_000).expect("CA");

    (ca.certificate_pem().clone(), ca.certificate_der().to_vec())
}

fn domain() -> TrustDomain {
    TrustDomain::new("cluster.local".to_owned()).expect("domain")
}

/// Which TPM a child is to see (ADR-0140).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tpm {
    /// The machine's -- for the one witness that substantiates the sealing.
    Real,
    /// None. The default, and for a measured reason: a TPM is **one serial device
    /// for the whole machine**, `cargo test` runs the test binaries concurrently,
    /// and forty-five `tgd` processes at it made eight of nine witnesses fall over
    /// (run serially, the same nine green).
    None,
}

/// Starts a node. Only the first leads (`--init`).
fn start(node: &Node, nodes: &[Node], leader: bool) -> support::Running {
    start_on(node, nodes, leader, Tpm::None)
}

/// As [`start`], with an express choice of the device.
fn start_on(node: &Node, nodes: &[Node], leader: bool, tpm: Tpm) -> support::Running {
    let mut args = vec![
        "--telemetry-addr".to_owned(),
        format!("127.0.0.1:{}", node.telemetry_port),
        "--id".to_owned(),
        node.seat.to_string(),
        "--node".to_owned(),
        format!("tgd-{}", node.seat),
        "--listen".to_owned(),
        format!("127.0.0.1:{}", node.identity_port),
        "--cluster-listen".to_owned(),
        format!("127.0.0.1:{}", support::free_port()),
        "--node-listen".to_owned(),
        format!("127.0.0.1:{}", support::free_port()),
        "--data-dir".to_owned(),
        node.dir.path().to_str().expect("path").to_owned(),
        "--peer".to_owned(),
        format!("{}=http://127.0.0.1:{}", node.seat, node.identity_port),
        "--signer-listen".to_owned(),
        format!("127.0.0.1:{}", node.signer_port),
    ];
    if leader {
        args.push("--init".to_owned());
    }
    // The **other** seats; our own is run locally and expressly does not go into
    // the list (ADR-0097, determination 1).
    for other in nodes {
        if other.seat != node.seat {
            args.push("--signer".to_owned());
            args.push(format!(
                "{}=http://127.0.0.1:{}",
                other.seat, other.signer_port
            ));
        }
    }

    support::Running(
        OsCommand::new(env!("CARGO_BIN_EXE_tgd"))
            .args(&args)
            // The device this child is to see (ADR-0140, see [`Tpm`]). A path
            // that points into the void is the same situation as a machine
            // without a TPM -- **no** switch that turns the sealing off.
            .env(
                "TG_TPM_DEVICE",
                match tpm {
                    Tpm::Real => "/dev/tpmrm0",
                    Tpm::None => "/nonexistent/tpm",
                },
            )
            .stdout(support::log(&format!("tgd-signer-{}", node.seat)))
            .stderr(support::log(&format!("tgd-signer-{}-err", node.seat)))
            .spawn()
            .expect("tgd startable"),
    )
}

/// Verifies the issued chain against the group key.
fn verify(leaf_pem: &str, anchor: &[u8]) {
    let anchor_der = CertificateDer::from(anchor.to_vec());
    let trust = webpki::anchor_from_trusted_cert(&anchor_der).expect("anchor");
    let leaf_der = CertificateDer::from(pem::parse(leaf_pem).expect("PEM").into_contents());
    let cert = webpki::EndEntityCert::try_from(&leaf_der).expect("readable");
    cert.verify_for_usage(
        &[webpki::ring::ED25519],
        &[trust],
        &[],
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            u64::try_from(now() + 30).expect("after 1970"),
        )),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .expect("the chain signed by the group must carry");
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

/// Waits until **every** signer port accepts.
///
/// The reason is measured, not precautionary: the refresh witness fell twice with
/// `seat 2 did not answer`, and in all five logs their signer port stands
/// as the **last** listener -- measured 0.6 ms after the Raft port.
/// `await_leadership` waits for the **Raft** ports; the leadership can therefore
/// stand while a seat is still binding its signer port, and the coordinator's
/// advance check (ADR-0107) then hits it too early.
///
/// What is waited for is an **`accept`** and not a log line: that is the property
/// at which the coordinator fails. Not repeated until green -- the witness checks
/// the same thing afterwards as before, only no longer against a half-started
/// cluster.
fn await_signer_ports(nodes: &[Node]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    for node in nodes {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], node.signer_port));
        loop {
            if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200))
                .is_ok()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the signer port of seat {} does not accept",
                node.seat
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// Waits until this node leads.
async fn await_leadership(admin: &AdminClient) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if admin.status().await.is_ok_and(|status| status.is_leader) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("no leader in 30 s");
}

/// What a node reported.
fn log_of(seat: u16) -> String {
    std::fs::read_to_string(support::log_path(&format!("tgd-signer-{seat}-err")))
        .or_else(|_| std::fs::read_to_string(support::log_path(&format!("tgd-signer-{seat}"))))
        .unwrap_or_default()
}

/// **The proof:** five processes, no CA key, one carrying SVID.
///
/// The statement sits in what is **not** there: under `<data-dir>/signing/` there
/// is no `ca.key.pem` -- in none of the five directories. Nevertheless the leader
/// issues an agent intermediate, and `webpki` accepts the chain against the group
/// key.
///
/// Without the signer path that would not be constructible: the leader holds one
/// share of five, and the threshold is three (ADR-0014). Two others must have
/// answered over mTLS.
#[tokio::test(flavor = "multi_thread")]
async fn five_processes_without_a_ca_key_issue_a_usable_svid() {
    support::sweep_old_logs();
    let shape = GroupShape::adr_0014();
    let (nodes, anchor) = prepare(shape, &[]);

    // The property for whose sake the whole path exists -- checked **before** the
    // start, so that the test is not accidentally right.
    for node in &nodes {
        let key = tg_identity::layout::signing(node.dir.path()).join("ca.key.pem");
        assert!(
            !key.exists(),
            "no node may hold the CA key: {}",
            key.display()
        );
    }

    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| start(node, &nodes, at == 0))
        .collect();

    let leader = &nodes[0];
    let admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_leadership(&admin).await;

    admin
        .write(tg_consensus::Command::InviteNode {
            node: "node-7".to_owned(),
            digest: tg_consensus::token_digest(TOKEN),
            expires_at: now() + 900,
        })
        .await
        .expect("invitation");

    let applicant = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let client = IdentityClient::with_channel(support::open_channel(
        &format!("http://127.0.0.1:{}", leader.identity_port),
        &leader.leaf_pem,
    ));

    let credentials = client
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: tg_identity::control::spki_base64(&applicant),
            underlay: None,
        })
        .await
        .expect("call");

    let Credentials::Issued {
        node_svid_pem,
        bundle_pem,
        intermediate_pem,
        ..
    } = credentials
    else {
        panic!(
            "the join was not accepted: {credentials:?}\n--- leader ---\n{}",
            log_of(leader.seat)
        );
    };

    // The **join** gives no intermediate (ADR-0037): the node SVID hangs directly
    // on the CA, and that is here the group. The anchor travels along -- and it
    // must be the same one the ceremony produced.
    assert!(intermediate_pem.is_none(), "the join gives no intermediate");
    assert_eq!(
        pem::parse(&bundle_pem).expect("PEM").into_contents(),
        anchor,
        "the anchor that travelled along must be the group key"
    );

    // **The proof.** The chain carries against the group key, and no process
    // holds it: three shares came together over mTLS.
    verify(&node_svid_pem, &anchor);

    // And the counter-check for the diagnosis: the leader chose the group and not
    // the fallback. Without it the test would not prove **with what** the signing
    // happened -- a `ca.key.pem` somebody files would yield the same chain.
    let log = log_of(leader.seat);
    assert!(
        log.contains("the signing CA: the group"),
        "the leader must run the group, not the fallback:\n{log}"
    );
}

/// Waits until the leader's admin socket accepts calls.
///
/// A call to [`support::await_admin`] and no loop of its own any more: the process
/// check in it arose **here** (the finding from `cluster.rs`, found again at a
/// third place) -- it stood afterwards in this version and not in
/// `audit_rotation`'s, and a waiting discipline in two versions is one that goes
/// apart.
fn wait_for_admin(running: &mut [support::Running], data_dir: &Path, id: u16) -> AdminClient {
    let path = tgd::admin::socket_path(data_dir, u64::from(id));
    let mut children: Vec<&mut std::process::Child> =
        running.iter_mut().map(|node| &mut node.0).collect();
    support::await_admin(&path, &mut children)
}

/// **Determination 2, at real handshakes:** a leaf that does not belong to this
/// seat gives no share.
///
/// The setup is the same as above, with **one** thing different: in the leader's
/// admission list a **foreign** leaf stands for seats 3, 4 and 5. All five
/// processes run, all five ports listen, each holds its share -- and the leader
/// does not reach three of them, because the one answering is not the one dialled.
///
/// That leaves seat 1 (itself) and seat 2: two of three, and the threshold is
/// three (ADR-0014).
///
/// # What this setup does **not** separate
///
/// The call has two layers: the admission list (is this SPIFFE ID entered at
/// all?) and the name binding (`expecting` -- is the one answering the one
/// dialled?). Measured, the **first** already refuses here: under `3.pem` stands
/// `tgd-foreign-3`, so `tgd-3` is not in the list at all. Taking `expecting` away
/// leaves the test green -- the second layer is not visible in this setup.
/// Separating it would need a list that contains all the real leaves, and for that
/// there is no seam.
///
/// # Why a *missing* leaf does not do for that
///
/// The same list carries two things -- the port's admission and the call's
/// binding. A seat without a leaf therefore runs no signer port at all
/// (`load_group` finds no channel), and the rejection would come from "Connection
/// refused". Measured: my first attempt did exactly that and stayed green when the
/// port no longer demanded the client certificate -- it did not check what it
/// claims.
#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_leaf_gives_no_share() {
    support::sweep_old_logs();
    let shape = GroupShape::adr_0014();
    let (nodes, _anchor) = prepare(shape, &[3, 4, 5]);

    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| start(node, &nodes, at == 0))
        .collect();

    let leader = &nodes[0];
    let admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_leadership(&admin).await;

    admin
        .write(tg_consensus::Command::InviteNode {
            node: "node-7".to_owned(),
            digest: tg_consensus::token_digest(TOKEN),
            expires_at: now() + 900,
        })
        .await
        .expect("invitation");

    let applicant = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let client = IdentityClient::with_channel(support::open_channel(
        &format!("http://127.0.0.1:{}", leader.identity_port),
        &leader.leaf_pem,
    ));

    let credentials = client
        .join(JoinRequest {
            node: "node-7".to_owned(),
            token: TOKEN.to_owned(),
            spki: tg_identity::control::spki_base64(&applicant),
            underlay: None,
        })
        .await
        // **The port stands in the message**, and that is the answer to a wobble
        // whose cause I have **not** proved: the call once came back with
        // `Unimplemented` and an empty body -- the answer of a gRPC service that
        // does not know the route. Both services of this process say the same
        // (`unimplemented("unknown method")`), so it could not be read from that
        // **which** port the test had dialled. With the number the next case
        // carries its answer.
        .unwrap_or_else(|err| {
            panic!(
                "call to the leader's identity port {} (seat {}): {err}",
                leader.identity_port, leader.seat
            )
        });

    // **The statement:** the group runs, the processes run, and no SVID arises --
    // because three seats do not admit the caller.
    assert!(
        matches!(credentials, Credentials::Refused { .. }),
        "without admission no SVID may arise: {credentials:?}\n--- leader ---\n{}",
        log_of(leader.seat)
    );

    // And the other half of the assurance beside it: the leader **runs** the
    // group. Without it the rejection would be obtainable from a node without
    // signing material too, and the test would say nothing about the admission
    // list.
    let log = log_of(leader.seat);
    assert!(
        log.contains("the signing CA: the group"),
        "the leader must run the group:\n{log}"
    );
}

/// **A refresh over five real processes** (ADR-0107).
///
/// The witness this path needs and that no other can give: the three rounds go
/// over the signer port between five `tgd`, round 2 from seat to seat -- and
/// afterwards the new generation and **only** it lies on **every** data directory.
/// The `tgctl` test rig cannot see that: it provides the admin service and files
/// the answer.
///
/// And the statement sits in what does **not** happen: the group key stays the
/// same, so the CA certificate over it still holds -- that is why the node keeps
/// minting SVIDs afterwards that verify against the same anchor.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_over_five_processes_replaces_the_version_everywhere() {
    support::sweep_old_logs();
    let shape = GroupShape::adr_0014();
    let (nodes, _anchor) = prepare(shape, &[]);

    // Before: everyone holds **one** generation. Without this half the assertion
    // afterwards would say nothing about the refresh.
    let before_key = material_at(nodes[0].dir.path())
        .expect("starting generation")
        .group()
        .verifying_key()
        .serialize()
        .expect("key");
    for node in &nodes {
        assert_eq!(
            tg_identity::threshold::epochs(node.dir.path()).expect("generations"),
            vec![tg_identity::threshold::Epoch::GENESIS],
            "seat {} does not hold exactly one generation before the refresh",
            node.seat
        );
    }

    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| start(node, &nodes, at == 0))
        .collect();

    let leader = &nodes[0];
    let admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_leadership(&admin).await;
    await_signer_ports(&nodes);

    let answer = admin.refresh_group().await.expect("the refresh must carry");
    assert_eq!(answer.epoch, 1, "the generation did not move on");

    // **On every directory, not only at the coordinator.** A refresh that reaches
    // only the trigger would be a group that no longer signs.
    //
    // And **the old one is gone** (determination 6): only with that does the
    // refresh have its effect -- as long as it lies there, t seats can keep signing
    // in it, and a betrayed share still holds. It is discarded because all five
    // reported that the new one lies on their disk.
    for node in &nodes {
        assert_eq!(
            tg_identity::threshold::epochs(node.dir.path()).expect("generations"),
            vec![tg_identity::threshold::Epoch::new(1)],
            "seat {} does not hold exactly the new generation after the refresh",
            node.seat
        );
    }

    // And the group key survives: the new generation names the same one the
    // ceremony produced -- that is why the CA certificate over it still holds, and
    // that is why the node keeps minting usable SVIDs afterwards.
    let after = material_at(nodes[0].dir.path()).expect("new generation");
    assert_eq!(
        after.group().verifying_key().serialize().expect("key"),
        before_key,
        "the group key has changed -- the CA certificate does not hold for it"
    );
}

/// **Which generation a seat holds stands at the endpoint** (ADR-0107).
///
/// The number an operator needs after a refresh: did it arrive everywhere? And
/// does somebody still hold the old one -- then the refresh has no effect, because
/// t seats can keep signing in it.
///
/// What is checked is the **value**, not the presence of the line: a metric with
/// any old number tells an operator nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_epoch_of_a_seat_is_at_the_endpoint() {
    support::sweep_old_logs();
    let shape = GroupShape::adr_0014();
    let (nodes, _anchor) = prepare(shape, &[]);

    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| start(node, &nodes, at == 0))
        .collect();

    let leader = &nodes[0];
    let admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_leadership(&admin).await;
    await_signer_ports(&nodes);

    // Before: **one** generation, and it is the zeroth. Without this half it
    // would not be visible that the number moves.
    let before = support::scrape(leader.telemetry_port);
    assert!(
        holds(&before, tg_telemetry::names::SIGNER_EPOCH, "0"),
        "the generation does not stand as 0 at the endpoint:\n{before}"
    );
    assert!(
        holds(&before, tg_telemetry::names::SIGNER_EPOCHS, "1"),
        "before the refresh the seat does not hold exactly one generation:\n{before}"
    );

    admin.refresh_group().await.expect("the refresh must carry");

    // Afterwards: the new one, and **still exactly one** -- the old one is
    // discarded (determination 6). Two would be the case the alarm rule waits
    // for.
    let after = support::scrape(leader.telemetry_port);
    assert!(
        holds(&after, tg_telemetry::names::SIGNER_EPOCH, "1"),
        "the new generation does not stand at the endpoint:\n{after}"
    );
    // **And the group key is the same** (ADR-0107). That is the assurance of the
    // whole procedure -- new shares, the same group --, and it stands here at the
    // place an operator looks it up. It is a fingerprint and not a key: eight hex
    // characters.
    let before_print = group_fingerprint(&before).expect("fingerprint before");
    let after_print = group_fingerprint(&after).expect("fingerprint after");
    assert_eq!(
        before_print, after_print,
        "the group key changed at the refresh -- then the CA certificate over it \
         no longer holds"
    );
    assert_eq!(before_print.len(), 8, "no fingerprint: {before_print}");

    // **And all five report the same one.** A seat with foreign material stands
    // out nowhere else: it starts, and only the aggregation fails.
    for node in &nodes {
        let print = group_fingerprint(&support::scrape(node.telemetry_port))
            .unwrap_or_else(|| panic!("seat {} reports no fingerprint", node.seat));
        assert_eq!(
            print, after_print,
            "seat {} runs a different group",
            node.seat
        );
    }

    assert!(
        holds(&after, tg_telemetry::names::SIGNER_EPOCHS, "1"),
        "after the refresh the seat does not hold exactly one generation:\n{after}"
    );
}

/// The fingerprint from `tg_identity_signer_group_info`.
///
/// What is read is the **label**, not the value -- that is always `1`, and the
/// statement sits in the label (the same shape as `tg_identity_data_key_info`,
/// ADR-0100).
fn group_fingerprint(scraped: &str) -> Option<String> {
    let name = tg_telemetry::names::SIGNER_GROUP;
    scraped
        .lines()
        .filter(|line| !line.starts_with('#') && line.starts_with(name))
        .find_map(|line| {
            let at = line.find("fingerprint=\"")? + "fingerprint=\"".len();
            let rest = &line[at..];
            let end = rest.find('"')?;

            Some(rest[..end].to_owned())
        })
}

/// Whether a metric carries the named value **line by line**.
///
/// That a name occurs somewhere in the document says nothing about its labels and
/// nothing about its value. What is compared is the text and not a parsed `f64`:
/// the same form as in `telemetry.rs` beside it, and it needs no error bound for a
/// number that is a generation number.
fn holds(scraped: &str, name: &str, value: &str) -> bool {
    scraped.lines().any(|line| {
        !line.starts_with('#')
            && line.starts_with(name)
            && line[name.len()..].starts_with('{')
            && line.trim_end().ends_with(&format!(" {value}"))
    })
}

/// **And the read path names the same group as the endpoint.**
///
/// The witness stands here and not in `tgctl`: its test rig **provides** the admin
/// service and files the answer -- it cannot see the seam (`SignerSvc` reads the
/// real group) at all. It is checked at five real processes with real shares.
///
/// The carrying assertion is the last one: metric and read path are **two sources
/// for one fact**, and that they name the same fingerprint holds them together. If
/// they went apart, one of the two would say something about a group this node
/// does not run.
#[tokio::test(flavor = "multi_thread")]
async fn the_signing_group_reaches_the_read_path() {
    support::sweep_old_logs();
    let shape = GroupShape::adr_0014();
    let (nodes, _anchor) = prepare(shape, &[]);

    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| start(node, &nodes, at == 0))
        .collect();

    let leader = &nodes[0];
    let admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_leadership(&admin).await;
    await_signer_ports(&nodes);

    let answer = admin.signer().await.expect("the read path must answer");

    assert_eq!(answer.kind, "group", "{answer:?}");
    assert_eq!(answer.seat, Some(leader.seat), "{answer:?}");
    assert_eq!(answer.shape, Some((5, 3)), "{answer:?}");
    // Exactly **one** generation: the ceremony creates GENESIS, and no refresh ran
    // here (ADR-0107, determination 6).
    assert_eq!(answer.epochs, vec![0], "{answer:?}");
    // **Five links, our own included** -- my expectation was four, and the
    // measurement turned it round: our own share is one of the `t` contributions,
    // so the coordinator holds a `LocalLink` on itself beside the four `GrpcLink`.
    // The `--signer` setting, by contrast, names only the four others; the
    // assertion on our own seat records the difference so that nobody reads it as
    // an arithmetic error.
    assert_eq!(answer.linked, vec![1, 2, 3, 4, 5], "{answer:?}");
    assert!(
        answer.linked.contains(&leader.seat),
        "our own seat is missing from the links: {answer:?}"
    );
    assert_eq!(answer.admitted, 5, "{answer:?}");

    let print = answer.fingerprint.expect("ein Fingerabdruck");
    assert_eq!(
        Some(print.as_str()),
        group_fingerprint(&support::scrape(leader.telemetry_port)).as_deref(),
        "metric and read path name different groups"
    );
}

// --- RTS over the wire (ADR-0108) -------------------------------------------

/// A channel to a seat's signer port, **identified as** `as_seat`.
///
/// mTLS in both directions: the port checks the credential against its admission
/// list (ADR-0097), and the client checks the one answering against its leaf. The
/// key lies on the disk of the seat we represent -- the same one `prepare` filed
/// there.
fn signer_channel(nodes: &[Node], as_seat: u16, to: u16) -> tonic::transport::Channel {
    let mine = nodes.iter().find(|n| n.seat == as_seat).expect("seat");
    let peer = nodes.iter().find(|n| n.seat == to).expect("seat");

    let pem = std::fs::read_to_string(
        tg_identity::layout::dir(mine.dir.path()).join(tg_identity::layout::NODE_KEY),
    )
    .expect("node key");
    let key = rcgen::KeyPair::from_pem(&pem).expect("key");
    let id = SpiffeId::for_node(&domain(), &format!("tgd-{as_seat}")).expect("ID");
    let identity = tg_identity::NodeIdentity::new(&key, id).expect("identity");

    let trust = tg_identity::cluster::anchors_from_pem(&peer.leaf_pem, &domain()).expect("anchor");
    let verifier = tg_identity::NodeVerifier::new(domain(), tg_identity::cluster::shared(trust))
        .expecting(&format!("tgd-{to}"));
    let config = tg_identity::cluster::client_config(&identity, verifier).expect("configuration");
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));

    tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{}", peer.signer_port))
        .expect("endpoint")
        .connect_timeout(std::time::Duration::from_secs(10))
        .connect_with_connector_lazy(tower::service_fn(move |uri: http::Uri| {
            let connector = connector.clone();
            async move {
                let host = uri.host().unwrap_or("127.0.0.1").to_owned();
                let port = uri.port_u16().unwrap_or(443);
                let stream = tokio::net::TcpStream::connect((host, port)).await?;
                let name = rustls::pki_types::ServerName::try_from("cluster.invalid")
                    .map_err(std::io::Error::other)?;
                let tls = connector.connect(name, stream).await?;

                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }
        }))
}

/// **The proof of cut 2:** a repair over real processes, real mTLS, and a sigma
/// only the lost seat gets.
///
/// The sequence is the one from ADR-0108: the **lost** seat coordinates (it can,
/// because the credential on the signer port is the node key and not the share,
/// ADR-0097), the deltas go from seat to seat -- no call of this test carries one
/// --, and it fetches the sigmas individually.
///
/// The carrying assertion is the last one: `repair::restore` checks the restored
/// share against the **group key** (the finding from 7b: `repair_share_part3` does
/// not count the sigmas). That there is an `Ok` therefore means that three
/// contributions really came together -- and the comparison against the real share
/// beside it says that it is the **same** one.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_share_is_repaired_over_the_wire() {
    support::sweep_old_logs();
    let shape = GroupShape::adr_0014();
    let (nodes, _anchor) = prepare(shape, &[]);

    let lost_seat = 5u16;
    let real = material_at(nodes[4].dir.path()).expect("material");
    let lost = Seat::new(lost_seat).expect("seat");

    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| start(node, &nodes, at == 0))
        .collect();

    let leader = &nodes[0];
    let _admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_signer_ports(&nodes);

    let helpers: Vec<Seat> = [1, 2, 3].map(|n| Seat::new(n).expect("seat")).into();
    let handle = tokio::runtime::Handle::current();

    // Steps 1 and 2: the lost seat prompts every helper. **It sees no delta in
    // the process** -- the answer is empty, and the helper has delivered to the
    // others before it comes.
    for helper in &helpers {
        let link = tg_identity::threshold::GrpcLink::new(
            *helper,
            signer_channel(&nodes, lost_seat, helper.number()),
            handle.clone(),
        );
        tokio::task::spawn_blocking(move || {
            tg_identity::threshold::SignerLink::repair_deal(&link, lost, &helpers_of())
        })
        .await
        .expect("task")
        .unwrap_or_else(|err| panic!("step 1 at seat {}: {err}", helper.number()));
    }

    // Step 3: the sigmas -- as the seat they concern.
    let mut sigmas = Vec::new();
    for helper in &helpers {
        let link = tg_identity::threshold::GrpcLink::new(
            *helper,
            signer_channel(&nodes, lost_seat, helper.number()),
            handle.clone(),
        );
        let sigma = tokio::task::spawn_blocking(move || {
            tg_identity::threshold::SignerLink::repair_sigma(&link, lost)
        })
        .await
        .expect("task")
        .unwrap_or_else(|err| panic!("sigma from seat {}: {err}", helper.number()));
        sigmas.push(sigma);
    }

    let restored =
        tg_identity::threshold::repair::restore(&sigmas, lost, real.group()).expect("step 3");
    assert_eq!(
        restored.signing_share(),
        real.share().signing_share(),
        "RTS restores -- the share must be byte for byte the same"
    );
}

/// The helpers as a function of their own, so that the loop can move them.
fn helpers_of() -> Vec<Seat> {
    [1, 2, 3].map(|n| Seat::new(n).expect("seat")).into()
}

/// **A sigma goes only to the seat it concerns** (ADR-0108, D3).
///
/// The counter-direction to the witness above, and the one new authorization rule
/// of this ADR. The setup is the same, with **one** thing different: the question
/// is asked as seat 4 for the sigma for seat 5.
///
/// Why that counts is measured and stands in the ADR: `t` passed-through sigmas
/// **are** the input of step 3 and yield the share. A helper that were allowed to
/// collect them would be the trusted dealer.
#[tokio::test(flavor = "multi_thread")]
async fn a_sigma_goes_only_to_the_seat_it_concerns_over_the_wire() {
    support::sweep_old_logs();
    let shape = GroupShape::adr_0014();
    let (nodes, _anchor) = prepare(shape, &[]);

    let lost = Seat::new(5).expect("seat");
    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| start(node, &nodes, at == 0))
        .collect();

    let leader = &nodes[0];
    let _admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_signer_ports(&nodes);

    let handle = tokio::runtime::Handle::current();
    let helper = Seat::new(1).expect("seat");

    // Begin the repair first -- otherwise the rejection would be obtainable from a
    // helper that has nothing at all, and the test would say nothing about the
    // gate.
    let link =
        tg_identity::threshold::GrpcLink::new(helper, signer_channel(&nodes, 5, 1), handle.clone());
    tokio::task::spawn_blocking(move || {
        tg_identity::threshold::SignerLink::repair_deal(&link, lost, &helpers_of())
    })
    .await
    .expect("task")
    .expect("step 1");

    // And now ask as seat 4.
    let intruder =
        tg_identity::threshold::GrpcLink::new(helper, signer_channel(&nodes, 4, 1), handle.clone());
    let refused = tokio::task::spawn_blocking(move || {
        tg_identity::threshold::SignerLink::repair_sigma(&intruder, lost)
    })
    .await
    .expect("task");

    let err = match refused {
        Ok(_) => panic!("seat 4 must not get the sigma for seat 5"),
        Err(err) => err.to_string(),
    };
    assert!(
        // **Measured `seat 1 did not answer`.** Previously
        // `|| contains("unreachable")` stood here, and the arm was **dead**
        // -- it told a reader this outcome was possible, while the rejection
        // always comes from the seat asked. Exactly that is this test's
        // assurance, and an "unreachable" would be its opposite.
        err.contains("seat 1"),
        "the rejection comes from the seat we asked: {err}"
    );

    // The other half of the assurance: the **same** helper hands it out to seat 5.
    // Without it the rejection would be obtainable from a port that accepts
    // nobody.
    let owner =
        tg_identity::threshold::GrpcLink::new(helper, signer_channel(&nodes, 5, 1), handle.clone());
    tokio::task::spawn_blocking(move || {
        tg_identity::threshold::SignerLink::repair_sigma(&owner, lost)
    })
    .await
    .expect("task")
    .expect("seat 5 must get its sigma");
}

/// **The proof of cut 3:** the client fetches a lost share back and **files it**
/// (ADR-0108, determinations 6 and 7).
///
/// The difference from the witness above is the statement: there the test runs the
/// three steps itself, here `tgd::signer::Repair` runs them -- the production path
/// `tgctl signer repair` uses. It reads the group key **without the share beside
/// it** (the half generation `epochs` does not count -- exactly the repair case),
/// runs the rounds over real signer ports and writes only afterwards.
///
/// **Seat 5 does not run in the process**, and that is no test cosmetics but the
/// assurance: `tgd` does not start without a share (determination 7), so no
/// process can repair itself. The sequence is therefore the one of operation --
/// start (so that `identity/node.leaf.pem` arises, from which the client reads its
/// name), stop, lose the share, repair.
///
/// The carrying assertion is the last one: the share that lies on the disk
/// afterwards is **byte for byte the same**. `restore` checks it against the group
/// key anyway, but that says nothing about whether the result was also written --
/// and without the write `tgd` still does not start.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_restores_a_lost_share_and_leaves_it_on_disk() {
    support::sweep_old_logs();
    let shape = GroupShape::adr_0014();
    let (nodes, _anchor) = prepare(shape, &[]);

    let lost_seat = 5u16;
    let real = material_at(nodes[4].dir.path()).expect("material");

    // **All five start**, so that each files its `node.leaf.pem` -- the affected
    // one too: the client reads its name from it, and a node that never ran would
    // have none (then it would be a fresh admission and no repair).
    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| start(node, &nodes, at == 0))
        .collect();

    let leader = &nodes[0];
    let _admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_signer_ports(&nodes);

    let own_leaf =
        tg_identity::layout::dir(nodes[4].dir.path()).join(tg_identity::layout::NODE_LEAF);
    assert!(own_leaf.exists(), "tgd files its cluster leaf (ADR-0043)");

    // The affected seat stops running and loses its share. The **group key
    // stays** -- that is the repair case.
    running.remove(4);
    let at = tg_identity::threshold::share_path(nodes[4].dir.path());
    std::fs::remove_file(&at).expect("delete the share");
    assert!(
        material_at(nodes[4].dir.path()).is_err(),
        "the witness must hit the repair case: without a share"
    );
    assert_eq!(
        tg_identity::threshold::groups(nodes[4].dir.path()).expect("groups"),
        vec![tg_identity::threshold::Epoch::GENESIS],
        "the group key is still there"
    );

    let helpers: Vec<(u16, String)> = [1, 2, 3]
        .map(|n| {
            let peer = nodes.iter().find(|node| node.seat == n).expect("seat");
            (n, format!("http://127.0.0.1:{}", peer.signer_port))
        })
        .into();

    let handle = tokio::runtime::Handle::current();
    let dir = nodes[4].dir.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        let repair = tgd::signer::Repair::prepare(&dir, &domain(), lost_seat, &helpers)
            .unwrap_or_else(|err| panic!("preparation: {err}"));
        assert_eq!(repair.epoch(), tg_identity::threshold::Epoch::GENESIS);
        repair
            .run(&handle)
            .unwrap_or_else(|err| panic!("repair: {err}"));
    })
    .await
    .expect("task");

    let back = material_at(nodes[4].dir.path()).expect("the share must lie there again");
    assert_eq!(
        back.share().signing_share(),
        real.share().signing_share(),
        "RTS restores -- the share must be byte for byte the same"
    );
    assert_eq!(back.epoch(), real.epoch(), "and in the same generation");
}

/// **A failed run leaves no state behind** (ADR-0108, D4).
///
/// "All `t` or none, and **no state beyond the run**" -- the refresh implements
/// both halves (`refresh_abandon` in the error path), the repair implemented only
/// the second: a new start replaces the old one. Measured,
/// `SignerLink::repair_abandon` thereby had **no** caller outside the wire answer
/// -- the route was there, the client did not call it, and the helpers' inboxes
/// held their deltas until a new run came at some point.
///
/// The failure is produced over a fourth helper whose port belongs to nobody:
/// `prepare` succeeds (the channel is lazy), step 1 succeeds at the first three,
/// and the fourth aborts. The assertion is the effect, not the call: afterwards
/// each of the three says "has begun no repair".
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_repair_leaves_no_state_behind() {
    support::sweep_old_logs();
    let shape = GroupShape::adr_0014();
    let (nodes, _anchor) = prepare(shape, &[]);

    let lost_seat = 5u16;
    let lost = Seat::new(lost_seat).expect("seat");

    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| start(node, &nodes, at == 0))
        .collect();

    let leader = &nodes[0];
    let _admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_signer_ports(&nodes);
    running.remove(4);

    let at = tg_identity::threshold::share_path(nodes[4].dir.path());
    std::fs::remove_file(&at).expect("delete the share");

    // Three reachable helpers and a fourth whose port belongs to nobody. **The
    // port is free**, not merely guessed: `free_port` binds and checks.
    let dead = support::free_port();
    let mut helpers: Vec<(u16, String)> = [1, 2, 3]
        .map(|n| {
            let peer = nodes.iter().find(|node| node.seat == n).expect("seat");
            (n, format!("http://127.0.0.1:{}", peer.signer_port))
        })
        .into();
    helpers.push((4, format!("http://127.0.0.1:{dead}")));

    let handle = tokio::runtime::Handle::current();
    let dir = nodes[4].dir.path().to_path_buf();
    let err = tokio::task::spawn_blocking(move || {
        tgd::signer::Repair::prepare(&dir, &domain(), lost_seat, &helpers)
            .expect("the preparation succeeds: the channel is lazy")
            .run(&handle)
            .expect_err("the fourth helper does not answer")
    })
    .await
    .expect("task");
    assert!(err.contains('4'), "the message names the helper: {err}");

    // **The effect, not the call**: the three that took part no longer have an
    // inbox. The question is asked as the affected seat -- only it may
    // (determination 3).
    let handle = tokio::runtime::Handle::current();
    for helper in [1u16, 2, 3] {
        let link = tg_identity::threshold::GrpcLink::new(
            Seat::new(helper).expect("seat"),
            signer_channel(&nodes, lost_seat, helper),
            handle.clone(),
        );
        let answer = tokio::task::spawn_blocking(move || {
            tg_identity::threshold::SignerLink::repair_sigma(&link, lost)
        })
        .await
        .expect("task");
        // **What is checked is the effect, not the text.** Over the wire every
        // rejection is an `Unreachable` category -- the reason goes into the log
        // (`wire::unreachable`, the same separation as at `tg_proxy::tls::alert`).
        // That the port is **alive** is said by the same setup one line earlier:
        // it served step 1.
        assert!(
            answer.is_err(),
            "seat {helper} still holds its inbox (ADR-0108, D4)"
        );
    }
}

/// The share lies sealed -- and where there is no TPM, it does not (ADR-0140,
/// determination 8).
///
/// **Both values in one run**, and that is the point: a metric that shows only its
/// good case does not substantiate that it can report the bad one at all -- and the
/// bad one is the one the alarm rule waits for. Seat 1 gets the machine's device,
/// the remaining four do not; the same situation as a cluster in which a node has
/// lost its TPM.
///
/// Only **one** child at the real device, and that too is measured: a TPM is
/// serial for the whole machine, and five processes at it fell over beside the
/// eight other witnesses.
#[tokio::test(flavor = "multi_thread")]
async fn a_seat_reports_whether_its_share_is_sealed() {
    support::sweep_old_logs();
    if !tg_identity::threshold::TpmCustody::present() {
        eprintln!("no TPM on this machine -- skipped");
        return;
    }

    let shape = GroupShape::adr_0014();
    let (nodes, _anchor) = prepare(shape, &[]);

    let mut running: Vec<support::Running> = nodes
        .iter()
        .enumerate()
        .map(|(at, node)| {
            let tpm = if at == 0 { Tpm::Real } else { Tpm::None };
            start_on(node, &nodes, at == 0, tpm)
        })
        .collect();

    let leader = &nodes[0];
    let admin = wait_for_admin(&mut running, leader.dir.path(), leader.seat);
    await_leadership(&admin).await;
    await_signer_ports(&nodes);

    // The seat with a device: the ceremony filed plaintext, `adopt` took it over
    // at startup (determination 9).
    let sealed = support::scrape(leader.telemetry_port);
    assert!(
        holds(&sealed, tg_telemetry::names::SIGNER_SEALED, "1"),
        "the first seat's share is not reported as sealed:\n{sealed}"
    );

    // And on the disk there really stands an envelope -- not just a number that
    // claims it.
    let on_disk = std::fs::read(tg_identity::threshold::share_path(leader.dir.path()))
        .expect("the share must lie there");
    assert!(
        tg_identity::threshold::is_envelope(&on_disk),
        "the metric says sealed, the disk carries a naked share"
    );

    // The seat without a device: the same metric, the other value.
    let plain = support::scrape(nodes[1].telemetry_port);
    assert!(
        holds(&plain, tg_telemetry::names::SIGNER_SEALED, "0"),
        "a seat without a TPM does not report that its share lies open:\n{plain}"
    );
}
