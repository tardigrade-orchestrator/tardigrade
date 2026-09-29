//! The control path between the seats (ADR-0097).
//!
//! The seam ADR-0014 named as open: *"the gRPC path between the signers is
//! outstanding"*. Here it is -- as [`GrpcLink`], which steps beside
//! [`super::LocalLink`] without a line in the [`super::ThresholdSigner`] becoming
//! different.
//!
//! # Why the protocol carries bytes
//!
//! The FROST types have their own, documented byte-wise forms
//! (`serialize`/`deserialize`). Sending them over `serde` would be the obvious
//! choice and the worse one: `frost-core`'s `serde` derivations hang on a feature
//! flag, and their form is a property of the library version -- not one somebody
//! promised. The byte-wise form is FROST's own contract.
//!
//! The conversion thereby happens at the **boundary**, and a mess of bytes from the
//! network is refused there instead of deeper in the protocol (ADR-0025's stance,
//! applied here to a cluster transport).
//!
//! # What the port gives up
//!
//! **Whoever reaches it can order a group signature.** An attacker that reaches t
//! seats has a message of their choice signed -- and the group signature *is* the CA
//! (ADR-0014). That is why it demands mTLS against a filed list (ADR-0097,
//! determination 2), and that is why this module builds **no** channel: the anchor
//! lies with the caller on the disk, and whoever reads it is `tgd` -- the same
//! separation as at [`crate::control::IdentityClient`].

use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status};

use crate::threshold::error::ThresholdError;
use crate::threshold::group::Seat;
use crate::threshold::participant::SessionId;
use crate::threshold::signer::SignerLink;
use crate::threshold::{SignatureShare, SigningCommitments, SigningPackage};

/// A seat did not answer -- **and why** goes into the log.
///
/// The error type carries only the seat, and that is right: what it gives back over
/// the wire is a category. The reason belongs where an operator looks -- the same
/// separation as at `tg_proxy::tls::alert` and
/// `tg_identity::workload_api::refusal`. Without it a missing peer leaf looks like a
/// dead process, and an operator looks at the wrong place.
fn unreachable(seat: Seat, detail: &str) -> ThresholdError {
    tracing::warn!(seat = seat.number(), detail, "the seat is unreachable");
    ThresholdError::Unreachable { seat }
}

/// Round 1: a seat's commitment.
pub const COMMIT: &str = "/tardigrade.signer.v1.Signer/Commit";

/// Round 2: its share of the signature.
pub const SIGN: &str = "/tardigrade.signer.v1.Signer/Sign";

/// Abort a session.
pub const ABANDON: &str = "/tardigrade.signer.v1.Signer/Abandon";

/// Refresh, round 1: one's own zero polynomial (ADR-0107).
pub const REFRESH_START: &str = "/tardigrade.signer.v1.Signer/RefreshStart";

/// Refresh, round 2: **the seat sends itself.**
///
/// The call returns only once this seat has delivered its directed packages to
/// **all** the others. With that the coordinator knows that everyone has everything
/// without having seen the packages -- and precisely that is the point: if it saw
/// them, it would know every delta and would be the trusted dealer ADR-0107
/// discarded.
pub const REFRESH_DEAL: &str = "/tardigrade.signer.v1.Signer/RefreshDeal";

/// Refresh, round 2 from **seat to seat**: take a directed package.
///
/// The only path of this system on which a seat calls another in its own name.
/// `frost` demands a **confidential** channel for this package, and that is the
/// mTLS path from ADR-0097 -- between exactly these two seats and not over a
/// third.
pub const REFRESH_TAKE: &str = "/tardigrade.signer.v1.Signer/RefreshTake";

/// Refresh, round 3: form the new share and put it beside.
pub const REFRESH_FINISH: &str = "/tardigrade.signer.v1.Signer/RefreshFinish";

/// Abort a begun refresh.
pub const REFRESH_ABANDON: &str = "/tardigrade.signer.v1.Signer/RefreshAbandon";

/// Refresh, afterwards: discard old generations (ADR-0107, determination 6).
pub const REFRESH_RETIRE: &str = "/tardigrade.signer.v1.Signer/RefreshRetire";

/// RTS, step 1: **the helper sends itself** (ADR-0108).
///
/// Literally the same shape as [`REFRESH_DEAL`], and for the same, measured reason:
/// a delta is the part of a share, and a coordinator that passed them through would
/// see exactly the input of `repair::restore_seat` and reconstruct it.
pub const REPAIR_DEAL: &str = "/tardigrade.signer.v1.Signer/RepairDeal";

/// RTS, from **seat to seat**: take a delta.
pub const REPAIR_TAKE: &str = "/tardigrade.signer.v1.Signer/RepairTake";

/// RTS, step 2: the sigma -- **only to the seat it concerns**.
///
/// ADR-0108's one new authorization rule (determination 3): the service knows the
/// caller's seat from the connection's credential (ADR-0097) and compares it. `t`
/// passed-through sigmas yield the share.
pub const REPAIR_SIGMA: &str = "/tardigrade.signer.v1.Signer/RepairSigma";

/// Abort a begun repair.
pub const REPAIR_ABANDON: &str = "/tardigrade.signer.v1.Signer/RepairAbandon";

/// What is asked for -- a session.
///
/// **Strict**, like every cluster message (ADR-0072): whoever reaches the signer
/// port orders a group signature, and a field a seat does not understand it must
/// not pass over.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    /// The session the commitment applies to.
    pub session: u64,
    /// In which generation of the shares (ADR-0107, determination 4).
    ///
    /// **Without a default**: it stands in every request, and `deny_unknown_fields`
    /// beside it means that a message without it is refused. A default would be the
    /// case in which a coordinator of an old version silently let signing happen in
    /// epoch 0 while the group is further on -- and then the aggregation blames the
    /// wrong seat.
    pub epoch: u64,
}

/// The commitment, byte-wise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommitResponse {
    /// Which seat committed.
    pub seat: u16,
    /// `SigningCommitments::serialize`.
    pub commitments: Vec<u8>,
}

/// Round 2: the signing package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    /// The same session as in round 1.
    pub session: u64,
    /// `SigningPackage::serialize`.
    pub package: Vec<u8>,
}

/// The share of the signature, byte-wise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignResponse {
    /// `SignatureShare::serialize`.
    pub share: Vec<u8>,
}

/// Abort a session -- best effort.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AbandonRequest {
    /// Which one.
    pub session: u64,
}

/// The empty answer to it.
///
/// A type of its own and not `()`: the codec needs a named one, and a future field
/// in it would otherwise be a break at a place that has no name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AbandonResponse {}

/// Refresh, round 1: into which generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshStartRequest {
    /// The generation that is to arise -- the next one after the one held.
    pub epoch: u64,
}

/// The binding to one's own zero polynomial.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshStartResponse {
    /// Which seat.
    pub seat: u16,
    /// `dkg::round1::Package::serialize`.
    pub broadcast: Vec<u8>,
}

/// Refresh, round 2: the others' bindings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshDealRequest {
    /// The same generation as in round 1.
    pub epoch: u64,
    /// Seat -> `dkg::round1::Package::serialize`, **without** one's own.
    pub broadcasts: Vec<(u16, Vec<u8>)>,
}

/// The empty answer -- the seat has delivered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshDealResponse {}

/// A directed package from another seat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshTakeRequest {
    /// The same generation.
    pub epoch: u64,
    /// From whom.
    ///
    /// **A self-declaration -- and the crypto catches it.** Round 3 checks every
    /// directed package against the **binding** of its sender from round 1; a
    /// package in the wrong slot does not fit there and lets the run fail. A seat
    /// that lies thereby aborts the refresh -- and it can do that anyway by not
    /// answering. It shifts no share.
    ///
    /// Not taking it from the certificate is thereby no omission in the sense of
    /// ADR-0043: there it was about a name on which an authority hung. Here nothing
    /// hangs on it that the crypto does not already check. Whoever reaches the port
    /// is an admitted seat anyway (ADR-0097).
    pub from: u16,
    /// `dkg::round2::Package::serialize`.
    pub directed: Vec<u8>,
}

/// The empty answer to it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshTakeResponse {}

/// Refresh, round 3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshFinishRequest {
    /// The same generation.
    pub epoch: u64,
}

/// Which generation this seat now holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshFinishResponse {
    /// Which seat.
    pub seat: u16,
    /// The new generation.
    pub epoch: u64,
    /// Whether the new generation lies **on the disk** (ADR-0107, determination 6).
    ///
    /// Without `serde(default)`: the port is strict, and a default would be the
    /// dangerous direction here -- `true` would let the coordinator discard the old
    /// generation although a seat would need it after a restart.
    pub persisted: bool,
    /// `PublicKeyPackage::serialize` of the new generation.
    ///
    /// Public, and the coordinator needs it: without the new `verifying_shares` it
    /// cannot name a culprit. It is not believed -- all five must name the same
    /// one.
    pub group: Vec<u8>,
}

/// Abort a begun refresh -- best effort.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshAbandonRequest {
    /// Which generation.
    pub epoch: u64,
}

/// The empty answer to it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshAbandonResponse {}

/// Discard old generations (ADR-0107, determination 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRetireRequest {
    /// Discarded is **every generation below this one**.
    pub epoch: u64,
}

/// How many generations this seat has discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRetireResponse {
    /// The answering seat.
    pub seat: u16,
}

/// RTS, step 1: who helps, and for whom (ADR-0108).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepairDealRequest {
    /// The lost seat.
    pub lost: u16,
    /// The helpers -- **including the one called**.
    ///
    /// `frost` produces one delta per helper in step 1, and this seat is one of
    /// them; its own stays with it. Without the complete list the Lagrange weighting
    /// would be a different one, and the sigmas would yield a share that does not
    /// pass the check against the group key.
    pub helpers: Vec<u16>,
}

/// The empty answer -- the helper has delivered to everyone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepairDealResponse {}

/// A delta from another helper.
///
/// **No `from` field**, unlike at [`RefreshTakeRequest`]: the service knows the
/// sender from the connection's credential (ADR-0097), and it needs it for
/// [`REPAIR_SIGMA`] anyway. At the refresh the self-declaration is bearable because
/// the crypto catches it -- here the sender is only the inbox's key, so nobody
/// catches it, and a field a client fills when the service knows the answer better
/// is exactly what ADR-0043 removed from `NodeMessage::Hello` without replacement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepairTakeRequest {
    /// For which lost seat.
    pub lost: u16,
    /// `repair::Delta::serialize`.
    pub delta: Vec<u8>,
}

/// The empty answer -- accepted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepairTakeResponse {}

/// RTS, step 2: the sigma for this seat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepairSigmaRequest {
    /// The lost seat -- **and the caller must be it**.
    pub lost: u16,
}

/// A helper's sigma.
///
/// **Without `Debug`** -- the same as at `repair::Sigma` itself: `frost` gives the
/// type none, and that is right, for `t` sigmas yield the share (ADR-0108,
/// determination 3). A derived one would bring them into every log line that takes
/// an answer along in passing; the same line as the four `Debug` bolts in this
/// crate.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepairSigmaResponse {
    /// `repair::Sigma::serialize`.
    pub sigma: Vec<u8>,
}

impl std::fmt::Debug for RepairSigmaResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepairSigmaResponse")
            .field(
                "sigma",
                &format_args!("<{} bytes, not shown>", self.sigma.len()),
            )
            .finish()
    }
}

/// Abort a repair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepairAbandonRequest {
    /// The lost seat.
    pub lost: u16,
}

/// The empty answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepairAbandonResponse {}

/// A seat at the other end of a gRPC path (ADR-0097).
#[derive(Debug)]
pub struct GrpcLink {
    seat: Seat,
    channel: tonic::transport::Channel,
    runtime: tokio::runtime::Handle,
}

impl GrpcLink {
    /// A link to `seat` over this channel.
    ///
    /// **The channel comes from outside**, for the same reason as at
    /// [`crate::control::IdentityClient`]: the anchor for mTLS lies with the caller
    /// on the disk (ADR-0097, determination 2), and `tg-identity` does not read it.
    ///
    /// **And the runtime handle too.** [`SignerLink`] is synchronous -- that is no
    /// carelessness but the form in which `rcgen::SigningKey` signs (7a). A
    /// `block_on` on a runtime of its own would panic in a `#[tokio::main]` process
    /// (the finding from 9d); with a handle the call is run on **that** runtime.
    #[must_use]
    pub fn new(
        seat: Seat,
        channel: tonic::transport::Channel,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            seat,
            channel,
            runtime,
        }
    }

    /// Runs a unary call on the caller's runtime.
    fn unary<Req, Resp>(&self, path: &'static str, request: Req) -> Result<Resp, ThresholdError>
    where
        Req: Serialize + Send + Sync + 'static,
        Resp: serde::de::DeserializeOwned + Send + Sync + 'static,
    {
        let channel = self.channel.clone();
        let seat = self.seat;
        // **On a thread of its own**, and that is the finding from 9d: `block_on`
        // panics when a runtime is already running -- and the caller is `tgd`, so
        // `#[tokio::main]`. `block_in_place` would be the other answer and would
        // demand `rt-multi-thread` in this crate; a thread costs less, for a signing
        // happens every three hours (ADR-0014), not per request.
        //
        // `thread::scope` blocks until the end -- exactly what [`SignerLink`]
        // demands: it is synchronous because `rcgen::SigningKey` is (7a).
        let handle = self.runtime.clone();
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    handle.block_on(async move {
                        // `tg_wire::client` and not `Grpc::new`: the message limit
                        // stands **once** in the tree, and a guard records that. For
                        // signature shares (32 to 134 bytes) it is without meaning
                        // -- a limit that stands individually at every call site is
                        // one that is missing at the eleventh.
                        let mut client = tg_wire::client(channel);
                        client
                            .ready()
                            .await
                            .map_err(|err| unreachable(seat, &err.to_string()))?;
                        client
                            .unary(
                                Request::new(request),
                                http::uri::PathAndQuery::from_static(path),
                                tg_wire::JsonCodec::<Req, Resp>::default(),
                            )
                            .await
                            .map(Response::into_inner)
                            .map_err(|status: Status| unreachable(seat, &status.to_string()))
                    })
                })
                .join()
                .unwrap_or_else(|_| {
                    // The thread panicked. That is an error of this process and no
                    // statement about the seat -- it is reported as "unreachable",
                    // for nobody reached it.
                    Err(unreachable(seat, "the calling thread panicked"))
                })
        })
    }
}

impl SignerLink for GrpcLink {
    fn seat(&self) -> Seat {
        self.seat
    }

    fn commit(
        &self,
        session: SessionId,
        epoch: crate::threshold::Epoch,
    ) -> Result<SigningCommitments, ThresholdError> {
        let answer: CommitResponse = self.unary(
            COMMIT,
            CommitRequest {
                session: session.value(),
                epoch: epoch.number(),
            },
        )?;

        // **The seat is checked, not believed.** A seat that gives a commitment in
        // another's name would be one seat represented twice -- and the threshold
        // only apparently reached (`ThresholdSigner::new` refuses exactly that).
        if answer.seat != self.seat.number() {
            return Err(unreachable(
                self.seat,
                &format!(
                    "the answer comes from seat {}, asked was {}",
                    answer.seat,
                    self.seat.number()
                ),
            ));
        }

        SigningCommitments::deserialize(&answer.commitments)
            .map_err(|err| unreachable(self.seat, &format!("the commitment is unreadable: {err}")))
    }

    fn sign(
        &self,
        session: SessionId,
        package: &SigningPackage,
    ) -> Result<SignatureShare, ThresholdError> {
        let bytes = package.serialize().map_err(|err| {
            unreachable(
                self.seat,
                &format!("the signing package is not serializable: {err}"),
            )
        })?;

        let answer: SignResponse = self.unary(
            SIGN,
            SignRequest {
                session: session.value(),
                package: bytes,
            },
        )?;

        SignatureShare::deserialize(&answer.share)
            .map_err(|err| unreachable(self.seat, &format!("the share is unreadable: {err}")))
    }

    fn abandon(&self, session: SessionId) {
        // **Best effort**, as the trait says: a seat one does not reach clears its
        // commitment away itself as soon as it is back.
        let _: Result<AbandonResponse, _> = self.unary(
            ABANDON,
            AbandonRequest {
                session: session.value(),
            },
        );
    }

    fn refresh_start(
        &self,
        epoch: crate::threshold::Epoch,
    ) -> Result<crate::threshold::refresh::Broadcast, ThresholdError> {
        let answer: RefreshStartResponse = self.unary(
            REFRESH_START,
            RefreshStartRequest {
                epoch: epoch.number(),
            },
        )?;

        // **The seat is checked, not believed** -- the same rule as in round 1 of
        // the signing: a binding in another's name shifts that one's share against
        // the group key.
        if answer.seat != self.seat.number() {
            return Err(unreachable(
                self.seat,
                &format!(
                    "the binding comes from seat {}, asked was {}",
                    answer.seat,
                    self.seat.number()
                ),
            ));
        }

        crate::threshold::refresh::Broadcast::deserialize(&answer.broadcast)
            .map_err(|err| ThresholdError::frost("reading the binding", &err))
    }

    fn refresh_deal(
        &self,
        epoch: crate::threshold::Epoch,
        broadcasts: &std::collections::BTreeMap<Seat, crate::threshold::refresh::Broadcast>,
    ) -> Result<(), ThresholdError> {
        let mut wire = Vec::with_capacity(broadcasts.len());
        for (seat, broadcast) in broadcasts {
            let bytes = broadcast
                .serialize()
                .map_err(|err| ThresholdError::frost("writing the binding", &err))?;
            wire.push((seat.number(), bytes));
        }

        let _: RefreshDealResponse = self.unary(
            REFRESH_DEAL,
            RefreshDealRequest {
                epoch: epoch.number(),
                broadcasts: wire,
            },
        )?;

        Ok(())
    }

    fn refresh_take(
        &self,
        epoch: crate::threshold::Epoch,
        from: Seat,
        directed: &crate::threshold::refresh::Directed,
    ) -> Result<(), ThresholdError> {
        let bytes = directed
            .serialize()
            .map_err(|err| ThresholdError::frost("writing the package", &err))?;

        let _: RefreshTakeResponse = self.unary(
            REFRESH_TAKE,
            RefreshTakeRequest {
                epoch: epoch.number(),
                from: from.number(),
                directed: bytes,
            },
        )?;

        Ok(())
    }

    fn refresh_finish(
        &self,
        epoch: crate::threshold::Epoch,
    ) -> Result<crate::threshold::Reached, ThresholdError> {
        let answer: RefreshFinishResponse = self.unary(
            REFRESH_FINISH,
            RefreshFinishRequest {
                epoch: epoch.number(),
            },
        )?;

        if answer.seat != self.seat.number() {
            return Err(unreachable(
                self.seat,
                &format!(
                    "the answer comes from seat {}, asked was {}",
                    answer.seat,
                    self.seat.number()
                ),
            ));
        }

        let group = crate::threshold::PublicKeyPackage::deserialize(&answer.group)
            .map_err(|err| ThresholdError::frost("reading the group key", &err))?;

        Ok(crate::threshold::Reached {
            epoch: crate::threshold::Epoch::new(answer.epoch),
            group,
            persisted: answer.persisted,
        })
    }

    fn refresh_retire(&self, epoch: crate::threshold::Epoch) -> Result<(), ThresholdError> {
        let _: RefreshRetireResponse = self.unary(
            REFRESH_RETIRE,
            RefreshRetireRequest {
                epoch: epoch.number(),
            },
        )?;

        Ok(())
    }

    fn refresh_abandon(&self, epoch: crate::threshold::Epoch) {
        // **Best effort**, as the trait says -- and there stands too why the
        // failure remains without consequence.
        let _: Result<RefreshAbandonResponse, _> = self.unary(
            REFRESH_ABANDON,
            RefreshAbandonRequest {
                epoch: epoch.number(),
            },
        );
    }

    // --- RTS over the wire (ADR-0108) --------------------------------------

    fn repair_deal(&self, lost: Seat, helpers: &[Seat]) -> Result<(), ThresholdError> {
        let _: RepairDealResponse = self.unary(
            REPAIR_DEAL,
            RepairDealRequest {
                lost: lost.number(),
                helpers: helpers.iter().copied().map(Seat::number).collect(),
            },
        )?;

        Ok(())
    }

    fn repair_take(
        &self,
        lost: Seat,
        _from: Seat,
        delta: &crate::threshold::repair::Delta,
    ) -> Result<(), ThresholdError> {
        // **`from` does not travel along.** The service takes the sender from the
        // connection's credential (ADR-0097) -- the parameter stands in the seam
        // because `LocalLink` needs it, where there is no connection.
        let _: RepairTakeResponse = self.unary(
            REPAIR_TAKE,
            RepairTakeRequest {
                lost: lost.number(),
                delta: delta.serialize(),
            },
        )?;

        Ok(())
    }

    fn repair_sigma(&self, lost: Seat) -> Result<crate::threshold::repair::Sigma, ThresholdError> {
        let answer: RepairSigmaResponse = self.unary(
            REPAIR_SIGMA,
            RepairSigmaRequest {
                lost: lost.number(),
            },
        )?;

        crate::threshold::repair::Sigma::deserialize(&answer.sigma)
            .map_err(|err| ThresholdError::frost("reading the sigma", &err))
    }

    fn repair_abandon(&self, lost: Seat) {
        // **Best effort**, as the trait says -- and there stands too why the
        // failure remains without consequence.
        let _: Result<RepairAbandonResponse, _> = self.unary(
            REPAIR_ABANDON,
            RepairAbandonRequest {
                lost: lost.number(),
            },
        );
    }
}
