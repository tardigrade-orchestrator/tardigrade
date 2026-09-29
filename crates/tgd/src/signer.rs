//! The signing group's signer service (ADR-0097).
//!
//! A port of its own with a trust list of its own: what is checked is the **key**
//! against `<data-dir>/signers/<seat>.pem`, in the construction of ADR-0043. The
//! reason is the same there and compelling here -- the CA *is* the group, a check
//! against it would be a circle.
//!
//! **Whoever has no leaf in the list gets no commitment and no share.** That is
//! the statement everything hangs on: whoever reaches this port can order a group
//! signature.

use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

pub use tg_identity::seats::{Repair, Seats};
use tg_identity::threshold::{
    ABANDON, AbandonRequest, AbandonResponse, COMMIT, CommitRequest, CommitResponse, LocalLink,
    REFRESH_ABANDON, REFRESH_DEAL, REFRESH_FINISH, REFRESH_RETIRE, REFRESH_START, REFRESH_TAKE,
    REPAIR_ABANDON, REPAIR_DEAL, REPAIR_SIGMA, REPAIR_TAKE, RefreshAbandonRequest,
    RefreshAbandonResponse, RefreshDealRequest, RefreshDealResponse, RefreshFinishRequest,
    RefreshFinishResponse, RefreshRetireRequest, RefreshRetireResponse, RefreshStartRequest,
    RefreshStartResponse, RefreshTakeRequest, RefreshTakeResponse, RepairAbandonRequest,
    RepairAbandonResponse, RepairDealRequest, RepairDealResponse, RepairSigmaRequest,
    RepairSigmaResponse, RepairTakeRequest, RepairTakeResponse, SIGN, SignRequest, SignResponse,
};
use tg_wire::JsonCodec;
use tonic::body::Body;
use tonic::codegen::{BoxFuture, Service};
use tonic::server::NamedService;
use tonic::{Request, Response, Status};

const SIGNER_SERVICE: &str = "tardigrade.signer.v1.Signer";

#[must_use]
pub fn may_receive_sigma(caller: Option<u16>, lost: u16) -> bool {
    caller == Some(lost)
}

#[derive(Clone, Debug)]
pub struct SignerService {
    seat: Arc<LocalLink>,
    seats: Arc<Seats>,
}

impl SignerService {
    #[must_use]
    pub fn new(seat: Arc<LocalLink>, seats: Arc<Seats>) -> Self {
        Self { seat, seats }
    }

    fn caller(&self, extensions: &http::Extensions) -> Option<u16> {
        let info =
            extensions.get::<tonic::transport::server::TlsConnectInfo<
                tonic::transport::server::TcpConnectInfo,
            >>()?;
        let leaf = info.peer_certs()?.first()?.clone();

        seat_from_leaf(&self.seats, &leaf)
    }
}

#[must_use]
pub fn seat_from_leaf(seats: &Seats, leaf: &rustls_pki_types::CertificateDer<'_>) -> Option<u16> {
    let node = tg_identity::cluster::spiffe_id_of(leaf)
        .ok()?
        .node()
        .map(str::to_owned)?;

    seats.seat_of(&node)
}

impl<B> Service<http::Request<B>> for SignerService
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
            COMMIT => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<CommitResponse, CommitRequest>::default());
                Ok(grpc.unary(CommitSvc { inner: this }, request).await)
            }),
            SIGN => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<SignResponse, SignRequest>::default());
                Ok(grpc.unary(SignSvc { inner: this }, request).await)
            }),
            ABANDON => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<AbandonResponse, AbandonRequest>::default());
                Ok(grpc.unary(AbandonSvc { inner: this }, request).await)
            }),
            REFRESH_START => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    RefreshStartResponse,
                    RefreshStartRequest,
                >::default());
                Ok(grpc.unary(RefreshStartSvc { inner: this }, request).await)
            }),
            REFRESH_DEAL => Box::pin(async move {
                let mut grpc = tg_wire::server(
                    JsonCodec::<RefreshDealResponse, RefreshDealRequest>::default(),
                );
                Ok(grpc.unary(RefreshDealSvc { inner: this }, request).await)
            }),
            REFRESH_TAKE => Box::pin(async move {
                let mut grpc = tg_wire::server(
                    JsonCodec::<RefreshTakeResponse, RefreshTakeRequest>::default(),
                );
                Ok(grpc.unary(RefreshTakeSvc { inner: this }, request).await)
            }),
            REFRESH_FINISH => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    RefreshFinishResponse,
                    RefreshFinishRequest,
                >::default());
                Ok(grpc.unary(RefreshFinishSvc { inner: this }, request).await)
            }),
            REFRESH_RETIRE => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    RefreshRetireResponse,
                    RefreshRetireRequest,
                >::default());
                Ok(grpc.unary(RefreshRetireSvc { inner: this }, request).await)
            }),
            REPAIR_DEAL => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<RepairDealResponse, RepairDealRequest>::default());
                Ok(grpc.unary(RepairDealSvc { inner: this }, request).await)
            }),
            REPAIR_TAKE => Box::pin(async move {
                let mut grpc =
                    tg_wire::server(JsonCodec::<RepairTakeResponse, RepairTakeRequest>::default());
                Ok(grpc.unary(RepairTakeSvc { inner: this }, request).await)
            }),
            REPAIR_SIGMA => Box::pin(async move {
                let mut grpc = tg_wire::server(
                    JsonCodec::<RepairSigmaResponse, RepairSigmaRequest>::default(),
                );
                Ok(grpc.unary(RepairSigmaSvc { inner: this }, request).await)
            }),
            REPAIR_ABANDON => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    RepairAbandonResponse,
                    RepairAbandonRequest,
                >::default());
                Ok(grpc.unary(RepairAbandonSvc { inner: this }, request).await)
            }),
            REFRESH_ABANDON => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    RefreshAbandonResponse,
                    RefreshAbandonRequest,
                >::default());
                Ok(grpc.unary(RefreshAbandonSvc { inner: this }, request).await)
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

impl NamedService for SignerService {
    const NAME: &'static str = SIGNER_SERVICE;
}

fn refuse(err: &tg_identity::threshold::ThresholdError) -> Status {
    tracing::warn!(detail = %err, "signer call refused");
    Status::failed_precondition(err.to_string())
}

struct CommitSvc {
    inner: SignerService,
}

impl Service<Request<CommitRequest>> for CommitSvc {
    type Response = Response<CommitResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<CommitRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move {
            let answer = seat
                .answer_commit(&request.into_inner())
                .map_err(|err| refuse(&err))?;
            Ok(Response::new(answer))
        })
    }
}

struct SignSvc {
    inner: SignerService,
}

impl Service<Request<SignRequest>> for SignSvc {
    type Response = Response<SignResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<SignRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move {
            let answer = seat
                .answer_sign(&request.into_inner())
                .map_err(|err| refuse(&err))?;
            Ok(Response::new(answer))
        })
    }
}

struct AbandonSvc {
    inner: SignerService,
}

impl Service<Request<AbandonRequest>> for AbandonSvc {
    type Response = Response<AbandonResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<AbandonRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move { Ok(Response::new(seat.answer_abandon(&request.into_inner()))) })
    }
}

struct RefreshStartSvc {
    inner: SignerService,
}

impl Service<Request<RefreshStartRequest>> for RefreshStartSvc {
    type Response = Response<RefreshStartResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RefreshStartRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move {
            let answer = seat
                .answer_refresh_start(&request.into_inner())
                .map_err(|err| refuse(&err))?;
            Ok(Response::new(answer))
        })
    }
}

struct RefreshDealSvc {
    inner: SignerService,
}

impl Service<Request<RefreshDealRequest>> for RefreshDealSvc {
    type Response = Response<RefreshDealResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RefreshDealRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        // **On a blocking thread**, unlike the four neighbours: this call calls
        // four other seats before it answers (ADR-0107 -- round 2 goes from seat
        // to seat, not over the coordinator). On a worker of the runtime it would
        // block it for the duration of four connection setups.
        Box::pin(async move {
            let answer = tokio::task::spawn_blocking(move || {
                seat.answer_refresh_deal(&request.into_inner())
            })
            .await
            .map_err(|err| Status::internal(err.to_string()))?
            .map_err(|err| refuse(&err))?;

            Ok(Response::new(answer))
        })
    }
}

struct RepairDealSvc {
    inner: SignerService,
}

impl Service<Request<RepairDealRequest>> for RepairDealSvc {
    type Response = Response<RepairDealResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RepairDealRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move {
            let answer = seat
                .answer_repair_deal(&request.into_inner())
                .map_err(|err| refuse(&err))?;
            Ok(Response::new(answer))
        })
    }
}

struct RepairTakeSvc {
    inner: SignerService,
}

impl Service<Request<RepairTakeRequest>> for RepairTakeSvc {
    type Response = Response<RepairTakeResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RepairTakeRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        // **The sender comes from the credential, not from the message.** At the
        // refresh the self-declaration is bearable, because round 3 checks it
        // against the sender's binding; here the sender is the key of the inbox,
        // and whoever lies overwrites another's delta. The service knows it anyway
        // -- it needs it for `RepairSigma` (ADR-0108, determination 3).
        let Some(from) = self.inner.caller(request.extensions()) else {
            return Box::pin(async move {
                Err(Status::permission_denied(
                    "this connection's credential represents no seat of this \
 group -- a delta without a sender belongs in no inbox \
 (ADR-0108)",
                ))
            });
        };

        Box::pin(async move {
            let from = tg_identity::threshold::Seat::new(from).map_err(|err| refuse(&err))?;
            let answer = seat
                .answer_repair_take(from, &request.into_inner())
                .map_err(|err| refuse(&err))?;
            Ok(Response::new(answer))
        })
    }
}

struct RepairSigmaSvc {
    inner: SignerService,
}

impl Service<Request<RepairSigmaRequest>> for RepairSigmaSvc {
    type Response = Response<RepairSigmaResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RepairSigmaRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        // **The one new authorization rule of ADR-0108** (determination 3): a
        // sigma for seat `N` only to seat `N`. `t` passed-through sigmas *are* the
        // input of step 3 and yield the share.
        let caller = self.inner.caller(request.extensions());
        let lost = request.get_ref().lost;
        if !may_receive_sigma(caller, lost) {
            return Box::pin(async move {
                Err(Status::permission_denied(format!(
                    "a sigma for seat {lost} goes only to that seat itself \
 (ADR-0108, determination 3) -- this connection's \
 credential represents {}",
                    caller.map_or_else(|| "no seat".to_owned(), |seat| format!("seat {seat}"))
                )))
            });
        }

        Box::pin(async move {
            let answer = seat
                .answer_repair_sigma(&request.into_inner())
                .map_err(|err| refuse(&err))?;
            Ok(Response::new(answer))
        })
    }
}

struct RepairAbandonSvc {
    inner: SignerService,
}

impl Service<Request<RepairAbandonRequest>> for RepairAbandonSvc {
    type Response = Response<RepairAbandonResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RepairAbandonRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move {
            let answer = seat
                .answer_repair_abandon(&request.into_inner())
                .map_err(|err| refuse(&err))?;
            Ok(Response::new(answer))
        })
    }
}

struct RefreshTakeSvc {
    inner: SignerService,
}

impl Service<Request<RefreshTakeRequest>> for RefreshTakeSvc {
    type Response = Response<RefreshTakeResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RefreshTakeRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move {
            let answer = seat
                .answer_refresh_take(&request.into_inner())
                .map_err(|err| refuse(&err))?;
            Ok(Response::new(answer))
        })
    }
}

struct RefreshFinishSvc {
    inner: SignerService,
}

impl Service<Request<RefreshFinishRequest>> for RefreshFinishSvc {
    type Response = Response<RefreshFinishResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RefreshFinishRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move {
            let answer = seat
                .answer_refresh_finish(&request.into_inner())
                .map_err(|err| refuse(&err))?;
            Ok(Response::new(answer))
        })
    }
}

struct RefreshRetireSvc {
    inner: SignerService,
}

impl Service<Request<RefreshRetireRequest>> for RefreshRetireSvc {
    type Response = Response<RefreshRetireResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RefreshRetireRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move {
            seat.answer_refresh_retire(&request.into_inner())
                .map(Response::new)
                .map_err(|err| Status::failed_precondition(err.to_string()))
        })
    }
}

struct RefreshAbandonSvc {
    inner: SignerService,
}

impl Service<Request<RefreshAbandonRequest>> for RefreshAbandonSvc {
    type Response = Response<RefreshAbandonResponse>;
    type Error = Status;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RefreshAbandonRequest>) -> Self::Future {
        let seat = Arc::clone(&self.inner.seat);

        Box::pin(async move {
            Ok(Response::new(
                seat.answer_refresh_abandon(&request.into_inner()),
            ))
        })
    }
}
