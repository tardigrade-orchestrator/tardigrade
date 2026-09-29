//! The SPIFFE server (ADR-0006, ADR-0037).
//!
//! ADR-0006 names four tasks for it; two of them stand here: **node attestation**
//! of joining agents and **signing/rotating** over the CA. The trust domain
//! ownership and the bundle publication fall out as a by-product -- every answer
//! carries the anchor along.
//!
//! # Three calls, and why there are three
//!
//! ```text
//! Join       { node, token, spki }              -> node SVID + bundle
//! Challenge  { node }                           -> nonce
//! Renew      { node, nonce, signature, spki }   -> node SVID + agent intermediate
//! ```
//!
//! **`Join`** is the one-time operation from ADR-0037. The token is checked
//! **here** against the hash in the replicated state and forgotten afterwards;
//! into the log goes only [`Command::AdmitNode`]. With that the secret never
//! reaches the audit substrate (ADR-0020).
//!
//! **`Challenge` and `Renew`** are the continuous operation. The agent proves
//! possession of its registered key -- over a signature on a nonce produced by the
//! server, not over the possession of a still valid certificate. That is the
//! reason why the node SVID may be short and a node comes back after an arbitrarily
//! long absence without an operator (ADR-0037).
//!
//! # Why a nonce and not mTLS
//!
//! ADR-0037 names as the target picture "agent <-> server over mTLS with node
//! SVIDs", and that is where it belongs. Today the Raft port carries neither TLS
//! nor authentication (phase 5c expressly left that open), and drawing in mTLS for
//! this one service alone would mean answering the question by half.
//!
//! The nonce is therefore no substitute but the property that matters as long as
//! the transport does not deliver it: **an intercepted `Renew` call cannot be
//! replayed.** It survives the switch to mTLS unharmed -- it then merely no longer
//! does any good.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use openraft::Raft;
use tg_consensus::net::JsonCodec;
use tg_consensus::{Command, Outcome, StateHandle, TypeConfig};
use tg_identity::control::{
    CHALLENGE, ChallengeRequest, ChallengeResponse, Credentials, IDENTITY_SERVICE, JOIN,
    JoinRequest, RENEW, RenewRequest, Underlay, unbase64,
};
use tg_identity::{Authority, Lifetime, LocalSigner, Purpose, Signer, SpiffeId, TrustDomain};
use tonic::body::Body;
use tonic::codegen::{BoxFuture, Service};
use tonic::server::NamedService;
use tonic::{Request, Response, Status};

const NONCE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

pub struct SigningCa {
    authority: Authority<Signer>,
    bundle_pem: String,
    domain: TrustDomain,
}

impl SigningCa {
    pub fn new(
        certificate_pem: &str,
        key_pem: &str,
        bundle_pem: String,
        domain: TrustDomain,
    ) -> Result<Self, String> {
        let signer = Signer::Local(Box::new(
            LocalSigner::from_pem(key_pem).map_err(|err| err.to_string())?,
        ));

        Self::with_signer(certificate_pem, signer, bundle_pem, domain)
    }

    pub fn with_signer(
        certificate_pem: &str,
        signer: Signer,
        bundle_pem: String,
        domain: TrustDomain,
    ) -> Result<Self, String> {
        let ca = tg_identity::Ca::from_pem(certificate_pem).map_err(|err| err.to_string())?;

        let (_, parsed) = x509_parser::parse_x509_certificate(ca.certificate_der())
            .map_err(|err| format!("the CA certificate is not readable: {err}"))?;
        // **The bit string, not `raw`** -- measured: `public_key().raw` is the
        // full SubjectPublicKeyInfo DER (44 bytes, with the AlgorithmIdentifier
        // `1.3.101.112`), `PublicKeyData::der_bytes` the raw key (32). The first
        // attempt compared the two and thereby refused **every** material; what
        // caught it was the test rig, with "the SPIFFE server is missing" as the
        // symptom.
        if parsed.public_key().subject_public_key.data.as_ref()
            != rcgen::PublicKeyData::der_bytes(&signer)
        {
            return Err(format!(
                "the signer ({}) does not belong to this CA certificate -- it \
                 would mint SVIDs no counterpart accepts",
                signer.kind()
            ));
        }

        let authority =
            Authority::new(ca, signer, Lifetime::default()).map_err(|err| err.to_string())?;

        Ok(Self {
            authority,
            bundle_pem,
            domain,
        })
    }

    #[must_use]
    pub fn signer_kind(&self) -> &'static str {
        self.authority.signer().kind()
    }

    #[must_use]
    pub fn domain(&self) -> &TrustDomain {
        &self.domain
    }
}

impl std::fmt::Debug for SigningCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningCa")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct IdentityService {
    raft: Raft<TypeConfig>,
    state: StateHandle,
    ca: Arc<SigningCa>,
    data_key: Option<String>,
    previous_data_key: Option<String>,
    nonces: Arc<Mutex<HashMap<String, (String, std::time::Instant)>>>,
}

impl std::fmt::Debug for IdentityService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityService").finish_non_exhaustive()
    }
}

impl IdentityService {
    #[must_use]
    pub fn new(raft: Raft<TypeConfig>, state: StateHandle, ca: Arc<SigningCa>) -> Self {
        Self {
            raft,
            state,
            ca,
            data_key: None,
            previous_data_key: None,
            nonces: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn with_data_key(mut self, key: Option<String>, previous: Option<String>) -> Self {
        self.data_key = key;
        self.previous_data_key = previous;
        self
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
            })
    }

    fn refuse(reason: impl Into<String>) -> Credentials {
        Credentials::Refused {
            reason: reason.into(),
        }
    }

    fn ordinal(&self, node: &str) -> Option<u32> {
        self.state.read().ordinal(node)
    }

    fn forward(&self) -> Credentials {
        Credentials::ForwardTo {
            leader: self.raft.metrics().borrow().current_leader,
        }
    }

    async fn join(&self, request: JoinRequest) -> Credentials {
        // The token is checked **here** and forgotten afterwards. Into the log
        // goes only the admission; the secret never reaches the audit substrate
        // (ADR-0020).
        let expected = {
            let state = self.state.read();
            state.invitation_digest(&request.node).map(str::to_owned)
        };
        let Some(expected) = expected else {
            // Deliberately the same wording as with a wrong token: whoever is not
            // invited does not learn whether they once were.
            return Self::refuse("no open invitation");
        };
        if tg_consensus::token_digest(&request.token) != expected {
            return Self::refuse("no open invitation");
        }

        let spki = match unbase64(&request.spki) {
            Ok(spki) => spki,
            Err(reason) => return Self::refuse(reason),
        };

        // Only now into the log. The state machine checks the invitation a second
        // time and consumes it -- the one-timeness lies there (ADR-0037), not in
        // this function.
        let command = Command::AdmitNode {
            node: request.node.clone(),
            spki: request.spki.clone(),
            at: Self::now(),
        };
        // Without an actor: no human stood here. A node has identified itself, and
        // the cluster writes on that basis (ADR-0042/0050).
        match self.raft.client_write(command.into()).await {
            Ok(response) => match response.data {
                Outcome::Applied => {}
                Outcome::Rejected(rejection) => return Self::refuse(rejection.to_string()),
                other => return Self::refuse(format!("an unexpected result: {other:?}")),
            },
            Err(_) => return self.forward(),
        }

        // **After** the admission, not before: `AnnounceUnderlay` demands an
        // admitted node (ADR-0039), and the other way round the announcement would
        // be a statement about a node that does not yet exist in the cluster.
        if let Some(underlay) = &request.underlay
            && let Err(refusal) = self.announce(&request.node, underlay).await
        {
            return refusal;
        }

        self.issue(&request.node, &spki, None)
    }

    fn challenge(&self, node: &str) -> ChallengeResponse {
        let mut bytes = [0_u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
        let nonce = tg_identity::control::base64(&bytes);

        let admitted = self.state.read().trust(node).is_some();
        metrics::counter!(
            tg_telemetry::names::IDENTITY_CHALLENGES,
            "outcome" => if admitted { "stored" } else { "unknown" }
        )
        .increment(1);

        if admitted && let Ok(mut nonces) = self.nonces.lock() {
            // Take expired ones along: a map that only grows is a leak with a
            // run-up. The **number** is bounded by the bar above.
            nonces.retain(|_, (_, issued)| issued.elapsed() < NONCE_TTL);
            nonces.insert(node.to_owned(), (nonce.clone(), std::time::Instant::now()));
        }

        ChallengeResponse { nonce }
    }

    async fn renew(&self, request: &RenewRequest) -> Credentials {
        let Some(registered) = self.state.read().trust(&request.node).map(str::to_owned) else {
            return Self::refuse("this node is not admitted");
        };

        // The nonce is **taken out**, not read: one that stayed lying could be used
        // a second time.
        let issued = self
            .nonces
            .lock()
            .ok()
            .and_then(|mut nonces| nonces.remove(&request.node));
        let Some((nonce, at)) = issued else {
            return Self::refuse("no open nonce; call Challenge first");
        };
        if at.elapsed() >= NONCE_TTL || nonce != request.nonce {
            return Self::refuse("the nonce has expired or does not belong here");
        }

        let (Ok(spki), Ok(signature)) = (unbase64(&registered), unbase64(&request.signature))
        else {
            return Self::refuse("key or signature unreadable");
        };
        // **What is checked is the whole request** (ADR-0046). ADR-0042 had
        // enumerated the scope and overlooked `intermediate_spki` in the process --
        // the key for which the agent intermediate is issued in a moment. The scope
        // now follows the request instead of a list.
        //
        // The nonce comes from **memory** and not from the request: it is checked,
        // its copy would be only a claim.
        let signed = RenewRequest {
            nonce: nonce.clone(),
            ..request.clone()
        };
        let message = tg_identity::control::renew_message(&signed);
        if !verify_ed25519(&spki, &message, &signature) {
            return Self::refuse("the signature does not fit the registered key");
        }

        let intermediate = match unbase64(&request.intermediate_spki) {
            Ok(spki) => spki,
            Err(reason) => return Self::refuse(reason),
        };

        // The announcement goes into the log **after** the signature check, and
        // exclusively for the node that made it: the name in the command comes from
        // `request.node`, and this name is the same one against whose registered
        // key the check was just made.
        if let Some(underlay) = &request.underlay
            && let Err(refusal) = self.announce(&request.node, underlay).await
        {
            return refusal;
        }

        // **The key change, after the old one has vouched** (ADR-0055). It stands
        // here and not before the check: only when the **old** key's signature fits
        // may the new one take its place.
        //
        // Issuance afterwards is for the **new** one -- otherwise the node would get
        // an SVID on a key the cluster no longer knows.
        let mut node_spki = spki;
        if let Some(next) = &request.next_node_spki {
            match unbase64(next) {
                Ok(bytes) => node_spki = bytes,
                Err(reason) => return Self::refuse(reason),
            }
            if let Err(refusal) = self.rotate(&request.node, &registered, next).await {
                return refusal;
            }
        }

        self.issue(&request.node, &node_spki, Some(&intermediate))
    }

    async fn announce(&self, node: &str, underlay: &Underlay) -> Result<(), Credentials> {
        let command = Command::AnnounceUnderlay {
            node: node.to_owned(),
            key: underlay.key.clone(),
            endpoint: underlay.endpoint.clone(),
            at: Self::now(),
        };

        // Without an actor: no human stood here. A node has identified itself, and
        // the cluster writes on that basis (ADR-0042/0050).
        match self.raft.client_write(command.into()).await {
            Ok(response) => match response.data {
                Outcome::Applied => Ok(()),
                Outcome::Rejected(rejection) => Err(Self::refuse(rejection.to_string())),
                other => Err(Self::refuse(format!("an unexpected result: {other:?}"))),
            },
            Err(_) => Err(self.forward()),
        }
    }

    async fn rotate(&self, node: &str, from: &str, to: &str) -> Result<(), Credentials> {
        // **Compare and set**, not write blindly (ADR-0055): a revocation that lies
        // between check and write must not be overtaken by a request that was still
        // in transit. Otherwise a compromised node would undo its own blocking.
        let command = Command::RotateTrust {
            node: node.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
        };

        match self.raft.client_write(command.into()).await {
            Ok(response) => match response.data {
                Outcome::Applied => Ok(()),
                Outcome::Rejected(rejection) => Err(Self::refuse(rejection.to_string())),
                other => Err(Self::refuse(format!("an unexpected result: {other:?}"))),
            },
            Err(_) => Err(self.forward()),
        }
    }

    fn issue(&self, node: &str, node_spki: &[u8], intermediate_spki: Option<&[u8]>) -> Credentials {
        let now = Self::now();
        let Ok(id) = SpiffeId::for_node(self.ca.domain(), node) else {
            return Self::refuse("no valid node name");
        };

        let node_svid =
            match self
                .ca
                .authority
                .certify(&id, node_spki, Purpose::Leaf, Lifetime::default(), now)
            {
                Ok(certified) => certified,
                Err(err) => return Self::refuse(err.to_string()),
            };

        let intermediate_pem = match intermediate_spki {
            None => None,
            Some(spki) => {
                // ADR-0014: 12 h lifetime, renewal every 3 h.
                let profile = tg_identity::IntermediateProfile::default();
                let lifetime = Lifetime {
                    ttl: profile.ttl,
                    rotate_after: profile.renew_after,
                    // The grace is **one** number from ADR-0014 and applies to
                    // every time window (ADR-0019) -- it once stood here inline and
                    // thereby invented.
                    grace: tg_identity::lifetime::SOFT_FAIL_GRACE,
                };
                match self
                    .ca
                    .authority
                    .certify(&id, spki, Purpose::Intermediate, lifetime, now)
                {
                    Ok(certified) => Some(certified.certificate_pem().to_owned()),
                    Err(err) => return Self::refuse(err.to_string()),
                }
            }
        };

        Credentials::Issued {
            node_svid_pem: node_svid.certificate_pem().to_owned(),
            intermediate_pem,
            bundle_pem: self.ca.bundle_pem.clone(),
            // It stands in consensus (ADR-0039) and is only passed on here. The
            // agent computes its subnet from it; a second call for that would be a
            // second opportunity to miss it.
            ordinal: self.ordinal(node),
            // **Never in the log** (ADR-0095, determination 1): it comes from this
            // `tgd`'s disk and goes the same way as `intermediate_pem` -- a private
            // key.
            data_key: self.data_key.clone(),
            // **During a rotation both travel** (ADR-0100, determination 1): as
            // long as the agent holds both, it opens every value -- no matter which
            // one it was sealed with. That is the reason why the rotation has no
            // window.
            previous_data_key: self.previous_data_key.clone(),
        }
    }
}

fn verify_ed25519(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // The last 32 bytes of an Ed25519 SPKI are the raw key; before them stands the
    // AlgorithmIdentifier. Shorter than an ASN.1 parser and sufficient here,
    // because the SPKI comes from our own state.
    if spki_der.len() < 32 {
        return false;
    }
    let key = &spki_der[spki_der.len() - 32..];

    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(message, signature)
        .is_ok()
}

impl NamedService for IdentityService {
    const NAME: &'static str = IDENTITY_SERVICE;
}

impl<B> Service<http::Request<B>> for IdentityService
where
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let this = self.clone();

        match request.uri().path() {
            JOIN => Box::pin(async move {
                let mut grpc =
                    tonic::server::Grpc::new(JsonCodec::<Credentials, JoinRequest>::default());
                Ok(grpc.unary(JoinSvc { inner: this }, request).await)
            }),
            CHALLENGE => Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(JsonCodec::<
                    ChallengeResponse,
                    ChallengeRequest,
                >::default());
                Ok(grpc.unary(ChallengeSvc { inner: this }, request).await)
            }),
            RENEW => Box::pin(async move {
                let mut grpc =
                    tonic::server::Grpc::new(JsonCodec::<Credentials, RenewRequest>::default());
                Ok(grpc.unary(RenewSvc { inner: this }, request).await)
            }),
            _ => Box::pin(async move {
                let (parts, ()) = Status::unimplemented("unknown method")
                    .into_http::<()>()
                    .into_parts();
                Ok(http::Response::from_parts(parts, Body::empty()))
            }),
        }
    }
}

struct JoinSvc {
    inner: IdentityService,
}

impl Service<Request<JoinRequest>> for JoinSvc {
    type Response = Response<Credentials>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<JoinRequest>) -> Self::Future {
        let inner = self.inner.clone();

        Box::pin(async move { Ok(Response::new(inner.join(request.into_inner()).await)) })
    }
}

struct ChallengeSvc {
    inner: IdentityService,
}

impl Service<Request<ChallengeRequest>> for ChallengeSvc {
    type Response = Response<ChallengeResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<ChallengeRequest>) -> Self::Future {
        let inner = self.inner.clone();

        Box::pin(async move { Ok(Response::new(inner.challenge(&request.into_inner().node))) })
    }
}

struct RenewSvc {
    inner: IdentityService,
}

impl Service<Request<RenewRequest>> for RenewSvc {
    type Response = Response<Credentials>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RenewRequest>) -> Self::Future {
        let inner = self.inner.clone();

        Box::pin(async move { Ok(Response::new(inner.renew(&request.into_inner()).await)) })
    }
}

#[cfg(test)]
mod signing_ca {
    use super::{SigningCa, TrustDomain};

    fn material() -> (String, tg_identity::LocalSigner, String, TrustDomain) {
        let domain = TrustDomain::new("cluster.local".to_owned()).expect("domain");
        let signer = tg_identity::LocalSigner::generate().expect("signer");
        let ca = tg_identity::self_signed_ca(&domain, &signer, 0, 4_000_000_000).expect("CA");

        let pem = ca.certificate_pem().clone();

        (pem.clone(), signer, pem, domain)
    }

    #[test]
    fn a_matching_signer_is_accepted() {
        let (certificate, signer, bundle, domain) = material();

        let ca = SigningCa::with_signer(
            &certificate,
            tg_identity::Signer::Local(Box::new(signer)),
            bundle,
            domain,
        )
        .expect("a matching signer must be accepted");

        assert_eq!(ca.signer_kind(), "local");
    }

    #[test]
    fn a_foreign_signer_is_refused() {
        let (certificate, _mine, bundle, domain) = material();
        let stranger = tg_identity::LocalSigner::generate().expect("signer");

        let err = SigningCa::with_signer(
            &certificate,
            tg_identity::Signer::Local(Box::new(stranger)),
            bundle,
            domain,
        )
        .expect_err("a foreign key must yield no signing CA");

        assert!(
            err.contains("does not belong to this CA certificate"),
            "the message must name the reason, not merely fail: {err}"
        );
    }
}
