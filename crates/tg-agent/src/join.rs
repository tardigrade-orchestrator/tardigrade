//! The agent fetches its intermediate (ADR-0006, ADR-0037).
//!
//! Until here the agent intermediate lay on the disk because an operator had put
//! it there. Now the agent fetches it — and the files that arise in the process
//! are **the same**. The minting path notices no difference, and that is
//! intentional: it was laid out since 7a for the intermediate coming from
//! outside.
//!
//! ```text
//! <data-dir>/identity/node.key.pem          the node key -- stays here
//! <data-dir>/identity/join-token            the invitation; is consumed
//! <data-dir>/identity/intermediate.pem      fetched
//! <data-dir>/identity/intermediate.key.pem  fresh per renewal
//! <data-dir>/identity/bundle.pem            fetched
//! ```
//!
//! # The node key arises here and stays here
//!
//! That is ADR-0037's load-bearing statement: the token is not the identity but
//! the permission to enter it **once**. The key is generated locally, never goes
//! over the network, and from the join on it is what identifies the node. That is
//! why the node SVID may be short, and why a node comes back without an operator
//! after an arbitrarily long absence.
//!
//! # The token is consumed, here too
//!
//! After a successful join the agent deletes the token file. The server has
//! devalued it anyway; leaving it lying afterwards would be a secret without a
//! purpose on a disk.
//!
//! # What happens on a failure: nothing bad
//!
//! If the control plane is not reachable, the agent keeps what it has and tries
//! again later. The intermediate carries twelve hours (ADR-0014), the renewal
//! runs every three — three further opportunities remain before something is
//! missing. The distance is chosen exactly for that (ADR-0019).

use std::path::{Path, PathBuf};
use std::time::Duration;

use rcgen::SigningKey as _;
use tg_identity::control::{
    Credentials, IdentityClient, JoinRequest, RenewRequest, Underlay, base64, renew_message,
    spki_base64,
};

pub(crate) const RENEW_EVERY: Duration = Duration::from_hours(3);

const _: () = assert!(
    RENEW_EVERY.as_secs() <= tg_identity::IntermediateProfile::RENEW_AFTER.as_secs(),
    "the agent asks less often than the rotation lead time from ADR-0014 \
     demands -- the intermediate then runs into its lead time (see RENEW_EVERY)"
);

const _: () = assert!(
    tg_identity::IntermediateProfile::RENEW_AFTER.as_secs()
        < tg_identity::IntermediateProfile::TTL.as_secs(),
    "the rotation lead time does not lie before the intermediate's expiry"
);

const RETRY_AFTER: Duration = Duration::from_mins(1);

const RETRY_FLOOR: Duration = Duration::from_secs(1);

#[must_use]
pub(crate) fn backoff(failures: u32) -> Duration {
    let doubled = RETRY_FLOOR
        .checked_mul(2_u32.saturating_pow(failures.min(16)))
        .unwrap_or(RETRY_AFTER);
    doubled.min(RETRY_AFTER)
}

const ANNOUNCE_FLOOR: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(crate) enum JoinError {
    Unreachable {
        detail: String,
    },
    Refused {
        reason: String,
    },
    Local {
        detail: String,
    },
    NotLeading {
        leader: Option<u64>,
    },
}

impl JoinError {
    pub(crate) fn forwarded(&self) -> crate::endpoints::Next {
        match self {
            Self::NotLeading { leader } => crate::endpoints::next_after_referral(*leader),
            // An endpoint that does not answer is possibly the crashed old
            // leader: it moves on, but after the waiting time
            // (determination 3).
            _ => crate::endpoints::Next::AfterWaiting,
        }
    }
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { detail } => {
                write!(f, "the control plane is not reachable: {detail}")
            }
            Self::Refused { reason } => write!(f, "refused: {reason}"),
            Self::Local { detail } => write!(f, "{detail}"),
            Self::NotLeading { leader: Some(id) } => {
                write!(f, "this node does not lead; the leader is {id}")
            }
            Self::NotLeading { leader: None } => {
                write!(f, "this node does not lead and knows no leader")
            }
        }
    }
}

impl std::error::Error for JoinError {}

pub(crate) struct Paths {
    pub(crate) dir: PathBuf,
}

impl Paths {
    pub(crate) fn new(data_dir: &Path) -> Self {
        Self {
            dir: crate::identity::dir(data_dir),
        }
    }

    fn at(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

fn node_key(paths: &Paths) -> Result<rcgen::KeyPair, JoinError> {
    let path = paths.at(tg_identity::layout::NODE_KEY);

    if let Ok(pem) = std::fs::read_to_string(&path) {
        return rcgen::KeyPair::from_pem(&pem).map_err(|err| JoinError::Local {
            detail: format!("{}: {err}", path.display()),
        });
    }

    let key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|err| JoinError::Local {
            detail: format!("the node key cannot be generated: {err}"),
        })?;
    write_secret(&path, &key.serialize_pem())?;

    Ok(key)
}

fn underlay_key(paths: &Paths) -> Result<tg_net::wireguard::Keypair, JoinError> {
    let path = paths.at(tg_identity::layout::UNDERLAY_KEY);

    if let Ok(text) = std::fs::read_to_string(&path) {
        return tg_net::wireguard::Keypair::from_private_base64(text.trim()).map_err(|err| {
            JoinError::Local {
                detail: format!("{}: {err}", path.display()),
            }
        });
    }

    let key = tg_net::wireguard::Keypair::generate();
    write_secret(&path, &format!("{}\n", key.private_base64()))?;

    Ok(key)
}

pub(crate) fn announced_key(data_dir: &Path) -> Option<String> {
    crate::rotate::key_to_announce(data_dir)
}

pub(crate) fn underlay_keypair(data_dir: &Path) -> Option<tg_net::wireguard::Keypair> {
    let path = Paths::new(data_dir).at(tg_identity::layout::UNDERLAY_KEY);
    let text = std::fs::read_to_string(path).ok()?;

    tg_net::wireguard::Keypair::from_private_base64(text.trim()).ok()
}

#[must_use]
pub(crate) fn announcement_is_current(
    peers: &[tg_store::session::UnderlayPeer],
    node: &str,
    public_key: &str,
    endpoint: &str,
) -> bool {
    peers
        .iter()
        .any(|peer| peer.node == node && peer.key == public_key && peer.endpoint == endpoint)
}

pub(crate) async fn fetch(
    data_dir: &Path,
    node: &str,
    domain: &str,
    endpoint: &str,
    underlay_endpoint: Option<&str>,
) -> Result<(), JoinError> {
    let paths = Paths::new(data_dir);
    std::fs::create_dir_all(&paths.dir).map_err(|err| JoinError::Local {
        detail: format!("{}: {err}", paths.dir.display()),
    })?;

    let key = node_key(&paths)?;
    let underlay = match underlay_endpoint {
        Some(endpoint) => Some(Underlay {
            // **The pending one, when one lies beside it** (ADR-0055, step 2).
            // `underlay_key` generates the first if there is none yet -- after
            // that `key_to_announce` takes the pending one.
            key: {
                let _ = underlay_key(&paths)?;
                crate::rotate::key_to_announce(data_dir).ok_or_else(|| JoinError::Local {
                    detail: "no underlay key to announce".to_owned(),
                })?
            },
            endpoint: endpoint.to_owned(),
        }),
        None => None,
    };
    // ADR-0043, determination 3: the node checks the control plane before it
    // shows it a token. Without an anchor no join -- fail-closed, and it does not
    // contradict ADR-0019: here it is about the first entry into a trust
    // boundary, not about existing, permitted work.
    let cluster = crate::cluster::Cluster::load(data_dir, domain, node)
        .map_err(|detail| JoinError::Local { detail })?;
    let channel = cluster
        .open_channel(endpoint)
        .map_err(|detail| JoinError::Local { detail })?;
    let client = IdentityClient::with_channel(channel);

    // A token lying there means: this node is **presumably** not yet admitted.
    // Certain that is not -- the invitation is consumed at the `AdmitNode`
    // (ADR-0037: check and consumption in the same application), and if the
    // **answer** is then lost, a token lies here that the cluster has already
    // devalued.
    let token_path = paths.at(tg_identity::layout::JOIN_TOKEN);
    let mut refused = None;
    if let Ok(token) = std::fs::read_to_string(&token_path) {
        match join(&client, &paths, node, token.trim(), &key, underlay.clone()).await {
            Ok(()) => {
                // Consumed. The server has devalued it anyway; leaving it lying
                // would be a secret without a purpose on a disk.
                let _ = std::fs::remove_file(&token_path);
            }
            // **And then renew all the same.** The join may have failed because
            // it has already succeeded: then our public key stands registered in
            // the log, and `renew` proves its possession. Whoever was never
            // admitted does not get through with it either -- the fallback can
            // grant nothing the token would not have granted.
            //
            // Without it the agent tries the join **forever** again while the
            // cluster takes it for admitted: a node that never gets a certificate
            // again without a `RemoveNode` and a new invitation.
            Err(err) => {
                // **Said, not kept quiet.** A refused join with a subsequently
                // successful renewal means: the invitation was already consumed
                // -- at some point an answer was lost. That is repaired and
                // nevertheless an event an operator shall know about.
                tracing::warn!(error = %err, "join refused, trying a renewal");
                refused = Some(err);
            }
        }
    }

    match renew(&client, &paths, node, &key, underlay).await {
        Ok(()) => {
            // The renewal succeeded, so this node is admitted. The token lying
            // there is thereby consumed or worthless -- and every further pass
            // would spare itself the futile join.
            if refused.is_some() {
                let _ = std::fs::remove_file(&token_path);
            }
            Ok(())
        }
        // **The join error weighs more** when there was one: for a fresh node
        // "wrong token" is the statement that helps on, while "not registered"
        // only names its consequence.
        Err(err) => Err(refused.unwrap_or(err)),
    }
}

async fn join(
    client: &IdentityClient,
    paths: &Paths,
    node: &str,
    token: &str,
    key: &rcgen::KeyPair,
    underlay: Option<Underlay>,
) -> Result<(), JoinError> {
    let credentials = client
        .join(JoinRequest {
            node: node.to_owned(),
            token: token.to_owned(),
            spki: spki_base64(key),
            underlay,
        })
        .await
        .map_err(|err| JoinError::Unreachable {
            detail: err.to_string(),
        })?;

    store(paths, credentials)
}

async fn renew(
    client: &IdentityClient,
    paths: &Paths,
    node: &str,
    key: &rcgen::KeyPair,
    underlay: Option<Underlay>,
) -> Result<(), JoinError> {
    let nonce = client
        .challenge(node)
        .await
        .map_err(|err| JoinError::Unreachable {
            detail: err.to_string(),
        })?
        .nonce;

    // For the intermediate a **fresh** key: it is renewed every three hours, and
    // a new key per renewal is cheap to have. The node key stays where it is.
    let intermediate_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|err| JoinError::Local {
            detail: format!("the key cannot be generated: {err}"),
        })?;

    // **First the request, then the signature** (ADR-0046). The other way round
    // -- first sign, then build the request -- was the order in which
    // `intermediate_spki` stayed uncovered: what does not yet exist at the moment
    // of signing cannot be signed along.
    // **The identity change travels along** (ADR-0055): if a new node key lies
    // beside it, the request carries its SPKI -- signed with the **old**,
    // registered one. The old one vouches for the new; that is the only chain
    // that carries without a ceremony.
    let identity = crate::rotate::Files::in_identity_dir(&paths.dir, tg_model::KeyKind::Identity);
    let carried_next_key = pending_node_key(&identity).as_ref().map(spki_base64);

    let mut request = RenewRequest {
        node: node.to_owned(),
        nonce,
        signature: String::new(),
        intermediate_spki: spki_base64(&intermediate_key),
        next_node_spki: carried_next_key.clone(),
        underlay,
    };
    let signature = key
        .sign(&renew_message(&request))
        .map_err(|err| JoinError::Local {
            detail: format!("the signature cannot be formed: {err}"),
        })?;
    request.signature = base64(&signature);

    let credentials = client
        .renew(request)
        .await
        .map_err(|err| JoinError::Unreachable {
            detail: err.to_string(),
        })?;

    // First the key, then the certificate: were it the other way round and the
    // run broke off in between, an intermediate would lie there whose key is
    // missing -- and the agent would no longer mint without anything being
    // obviously broken.
    write_secret(
        &paths.at(tg_identity::layout::INTERMEDIATE_KEY),
        &intermediate_key.serialize_pem(),
    )?;

    // **Only after the server's yes**, and "yes" means: `store` has filed
    // credentials. A refusal comes back in the `Credentials` and **not** as a
    // transport error -- overlooking it here was an error with a heavy
    // consequence: the agent took over a key the cluster never registered, and
    // could afterwards **never again** renew. It would have locked itself out
    // permanently.
    //
    // If the run breaks off between the yes and the takeover, the old key still
    // applies. The next attempt sends the same SPKI once more, `RotateTrust`
    // refuses it (the expected old one no longer stands there), and at the pass
    // after that the signature fits the new one. Level-triggered (ADR-0010), not
    // edge-driven.
    store(paths, credentials)?;

    // **What is taken over is only what *this* request carried.**
    //
    // Asking `has_pending()` here once more was an error with the same
    // consequence as the takeover before the yes: the pending key can have arisen
    // **between** the building of the request and its answer -- the session files
    // it when a slice decrees it. Then the node took over a key the server never
    // saw, and **every** further renewal failed on the signature. Measured under
    // load.
    if carried_next_key.is_some() {
        identity
            .promote()
            .map_err(|detail| JoinError::Local { detail })?;
        tracing::info!("node key rotated");
    }

    Ok(())
}

fn pending_node_key(files: &crate::rotate::Files) -> Option<rcgen::KeyPair> {
    let pem = std::fs::read_to_string(&files.pending).ok()?;

    rcgen::KeyPair::from_pem(&pem).ok()
}

fn store(paths: &Paths, credentials: Credentials) -> Result<(), JoinError> {
    match credentials {
        Credentials::Issued {
            // **The node SVID is not filed** (ADR-0056), and that is intent
            // instead of oversight.
            //
            // Nobody reads it: on the cluster transports the node identifies
            // itself with its **key** against a registration and puts a
            // self-signed leaf on the wire (ADR-0043) -- a check against the CA
            // would be a circle there, for it hangs on the leader and that on the
            // Raft port.
            //
            // And it carries only 15 minutes (ADR-0014), renewed every three
            // hours: on the disk it would be **expired** 92 % of the time -- in a
            // regulated data directory a false signal at exactly the place an
            // auditor looks.
            //
            // Whoever wants to judge this node's chain looks at the agent
            // intermediate: it is what is minted from, it carries twelve hours
            // and is valid in normal operation.
            node_svid_pem: _,
            intermediate_pem,
            bundle_pem,
            ordinal,
            data_key,
            previous_data_key,
        } => {
            write(&paths.at(tg_identity::layout::BUNDLE), &bundle_pem)?;
            if let Some(intermediate) = intermediate_pem {
                write(&paths.at(tg_identity::layout::INTERMEDIATE), &intermediate)?;
            }
            // The ordinal (ADR-0039). It lies beside the rest of the identity
            // material because it is the same thing: a setting the node does not
            // determine itself and without which it cannot work.
            //
            // If it is missing from the answer, the existing one is **not**
            // deleted: a control plane from before 9d shall not take a node's
            // subnet away.
            if let Some(ordinal) = ordinal {
                write(
                    &paths.at(tg_identity::layout::ORDINAL),
                    &format!("{ordinal}\n"),
                )?;
            }

            // The data key (ADR-0095). **With `write_secret`**, like the
            // intermediate beside it: it is a secret and no credential.
            //
            // If it is missing from the answer, the existing one is **not**
            // deleted -- the same consideration as with the ordinal: a control
            // plane without a key shall not take from a node the capability of
            // opening secrets it already has.
            if let Some(key) = data_key {
                write_secret(&paths.at(tg_identity::layout::SECRETS_KEY), &key)?;
            }

            // And the one **to be replaced**, while a rotation is running
            // (ADR-0100). If it is missing from the answer, it is **removed** --
            // unlike the primary one beside it, and that is the difference: its
            // absence is a statement ("the rotation is finished"), while the
            // primary one's means "this control plane has none right now". Were
            // it to stay lying, the node would still open values of a key the
            // cluster has filed away.
            let previous = paths.at(tg_identity::layout::SECRETS_KEY_PREVIOUS);
            match previous_data_key {
                Some(key) => write_secret(&previous, &key)?,
                None => {
                    if previous.exists() {
                        let _ = std::fs::remove_file(&previous);
                    }
                }
            }

            Ok(())
        }
        Credentials::Refused { reason } => Err(JoinError::Refused { reason }),
        Credentials::ForwardTo { leader } => Err(JoinError::NotLeading { leader }),
    }
}

fn write(path: &Path, contents: &str) -> Result<(), JoinError> {
    std::fs::write(path, contents).map_err(|err| JoinError::Local {
        detail: format!("{}: {err}", path.display()),
    })
}

pub(crate) fn write_secret(path: &Path, contents: &str) -> Result<(), JoinError> {
    write(path, contents)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        // 0600. A private key the group can read is one that knows the
        // group.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|err| {
            JoinError::Local {
                detail: format!("{}: {err}", path.display()),
            }
        })?;
    }

    Ok(())
}

pub(crate) async fn keep_fresh(
    data_dir: PathBuf,
    node: String,
    domain: String,
    // **Several addresses** (ADR-0077): the credential path goes to the leader,
    // and a follower only refers on. With a single address an agent would
    // **never** renew again after a leader change -- and after twelve hours no
    // SVID of this node is accepted any more (ADR-0014).
    mut endpoints: crate::endpoints::Endpoints,
    underlay_endpoint: Option<String>,
    wake: std::sync::Arc<tokio::sync::Notify>,
) {
    // How many failures in a row -- the backoff grows with it (see
    // [`backoff`]). A success resets it.
    let mut failures = 0_u32;
    loop {
        let started = tokio::time::Instant::now();
        // The announcement goes along at **every** renewal, not only the first
        // time. With that the key rotation from ADR-0039 is a question of cadence
        // and no ceremony: a new key is announced at the next pass.
        let wait = match fetch(
            &data_dir,
            &node,
            &domain,
            endpoints.current(),
            underlay_endpoint.as_deref(),
        )
        .await
        {
            Ok(()) => {
                failures = 0;
                RENEW_EVERY
            }
            Err(err) => {
                // A failure is no reason to stop: the intermediate carries
                // twelve hours, the renewal runs every three -- three further
                // opportunities remain (ADR-0014/0019).
                tracing::warn!(
                    error = %err,
                    endpoint = endpoints.current(),
                    "the identity was not renewed"
                );

                // **Move on, and with a referral without a waiting time**
                // (ADR-0077): the referral names the leader, so this endpoint is
                // demonstrably the wrong one.
                let next = err.forwarded();
                endpoints.advance();
                match next {
                    crate::endpoints::Next::Now => continue,
                    crate::endpoints::Next::AfterWaiting => {
                        let wait = backoff(failures);
                        failures = failures.saturating_add(1);
                        wait
                    }
                }
            }
        };

        // **A pending key shortens the cadence by itself.**
        //
        // Not only the wake-up below: that holds exactly one place, and two
        // rotations shortly after one another would fall together in it -- the
        // second announcement would have waited until the next stroke of the
        // clock, so up to three hours. Measured and deterministically reproduced
        // (ADR-0055).
        //
        // The pending key is **state** and lies on the disk until it is taken
        // over. Asking it can lose nothing.
        let wait = if crate::rotate::pending(&data_dir) {
            wait.min(ANNOUNCE_FLOOR)
        } else {
            wait
        };

        // **A wake-up speeds the cadence up, it does not lift it.** It is woken
        // when the cluster knows something else about this node than it announces
        // (ADR-0042) -- and that can be permanently so, because it is not
        // admitted at all, say. Without a lower bound one call per slice would
        // come of it, and slices come as often as the log moves. The lower bound
        // is `ANNOUNCE_FLOOR` and expressly not the one with which a failure is
        // repeated -- those are two intents, and they must not share one
        // number.
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = wake.notified() => {
                // `saturating_sub` and not `-`: if the floor has already
                // elapsed, nothing is waited. An unchecked subtraction would be a
                // panic here that depends on the clock.
                let rest = ANNOUNCE_FLOOR.saturating_sub(started.elapsed());
                if !rest.is_zero() {
                    tokio::time::sleep(rest).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod announcement_tests {
    use super::announcement_is_current;
    use tg_store::session::UnderlayPeer;

    fn peer(node: &str, key: &str, endpoint: &str) -> UnderlayPeer {
        UnderlayPeer {
            node: node.to_owned(),
            ordinal: 1,
            key: key.to_owned(),
            endpoint: endpoint.to_owned(),
        }
    }

    #[test]
    fn attaching_does_not_force_an_announcement() {
        let mine = peer("node-a", "kkk", "203.0.113.9:51820");

        // Detached: only its own entry.
        assert!(
            announcement_is_current(
                std::slice::from_ref(&mine),
                "node-a",
                "kkk",
                "203.0.113.9:51820"
            ),
            "a detached node wakes its renewer endlessly"
        );

        // Attached: all peers, its own among them.
        let attached = [mine, peer("node-b", "mmm", "203.0.113.10:51820")];
        assert!(
            announcement_is_current(&attached, "node-a", "kkk", "203.0.113.9:51820"),
            "after attaching the node does not find its own announcement"
        );

        // And the counter-check that shows the reconciliation says anything at
        // all: **another** node's entry does not count as its own -- without this
        // assurance an `any` without a name comparison would be just as green.
        assert!(
            !announcement_is_current(
                &[peer("node-b", "kkk", "203.0.113.9:51820")],
                "node-a",
                "kkk",
                "203.0.113.9:51820"
            ),
            "another node's entry counted as its own"
        );
    }

    #[test]
    fn an_entry_that_agrees_is_current() {
        let peers = [peer("node-a", "kkk", "203.0.113.9:51820")];

        assert!(announcement_is_current(
            &peers,
            "node-a",
            "kkk",
            "203.0.113.9:51820"
        ));
    }

    #[test]
    fn a_different_endpoint_is_not_current() {
        let peers = [peer("node-a", "kkk", "198.51.100.1:51820")];

        assert!(!announcement_is_current(
            &peers,
            "node-a",
            "kkk",
            "203.0.113.9:51820"
        ));
    }

    #[test]
    fn a_rotated_key_is_not_current() {
        let peers = [peer("node-a", "old", "203.0.113.9:51820")];

        assert!(!announcement_is_current(
            &peers,
            "node-a",
            "new",
            "203.0.113.9:51820"
        ));
    }

    #[test]
    fn an_absent_entry_is_not_current() {
        assert!(!announcement_is_current(&[], "node-a", "kkk", "1.2.3.4:1"));
    }

    #[test]
    fn another_nodes_entry_does_not_count() {
        let peers = [peer("node-b", "kkk", "203.0.113.9:51820")];

        assert!(!announcement_is_current(
            &peers,
            "node-a",
            "kkk",
            "203.0.113.9:51820"
        ));
    }
}

#[cfg(test)]
mod backoff_tests {
    use super::{RETRY_AFTER, RETRY_FLOOR, backoff};

    #[test]
    fn the_backoff_starts_at_the_floor_and_stops_at_the_ceiling() {
        assert_eq!(backoff(0), RETRY_FLOOR, "the first attempt waits too long");
        assert_eq!(backoff(1), RETRY_FLOOR * 2);
        assert_eq!(backoff(2), RETRY_FLOOR * 4);

        // And from some point on it stays at the ceiling -- with absurd numbers
        // too, without an overflow.
        for failures in [6, 7, 20, u32::MAX] {
            assert_eq!(
                backoff(failures),
                RETRY_AFTER,
                "after {failures} failures it does not hold at the ceiling"
            );
        }
    }

    #[test]
    fn the_backoff_never_shrinks() {
        let mut previous = std::time::Duration::ZERO;
        for failures in 0..24 {
            let wait = backoff(failures);
            assert!(
                wait >= previous,
                "the backoff got smaller at {failures}: {wait:?} < {previous:?}"
            );
            previous = wait;
        }
    }
}
