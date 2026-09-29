//! The server side: the local `Raft` behind three gRPC methods.
//!
//! Without a `.proto` and without generated code — the mapping path → method
//! stands written out here. That is more text than a codegen line, but it is
//! the whole service: three unary calls, no streams, no options. What a
//! generator would make of it would stand there the same way anyway.

use std::convert::Infallible;
use std::task::{Context, Poll};

use openraft::Raft;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use tonic::body::Body;
use tonic::codegen::{BoxFuture, Service};
use tonic::server::NamedService;
use tonic::{Request, Response, Status};

use crate::config::{NodeId, TypeConfig};
use crate::net::codec::JsonCodec;
use crate::net::{APPEND_ENTRIES, INSTALL_SNAPSHOT, RAFT_SERVICE, VOTE};

/// A node's Raft service.
///
/// It holds the local [`Raft`] and forwards to it what comes in. It has no
/// logic of its own — every check that took place here would be a second
/// opinion beside that of consensus.
#[derive(Clone)]
pub struct RaftService {
    raft: Raft<TypeConfig>,
}

impl RaftService {
    /// The service over this instance.
    #[must_use]
    pub fn new(raft: Raft<TypeConfig>) -> Self {
        Self { raft }
    }
}

impl std::fmt::Debug for RaftService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaftService").finish_non_exhaustive()
    }
}

impl NamedService for RaftService {
    const NAME: &'static str = RAFT_SERVICE;
}

impl<B> Service<http::Request<B>> for RaftService
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
        let raft = self.raft.clone();

        match request.uri().path() {
            APPEND_ENTRIES => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    AppendEntriesResponse<NodeId>,
                    AppendEntriesRequest<TypeConfig>,
                >::default());
                Ok(grpc.unary(AppendEntriesSvc { raft }, request).await)
            }),
            VOTE => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    VoteResponse<NodeId>,
                    VoteRequest<NodeId>,
                >::default());
                Ok(grpc.unary(VoteSvc { raft }, request).await)
            }),
            INSTALL_SNAPSHOT => Box::pin(async move {
                let mut grpc = tg_wire::server(JsonCodec::<
                    InstallSnapshotResponse<NodeId>,
                    InstallSnapshotRequest<TypeConfig>,
                >::default());
                Ok(grpc.unary(InstallSnapshotSvc { raft }, request).await)
            }),
            // An unknown path is `UNIMPLEMENTED`, not 404: the caller speaks
            // gRPC and shall get a gRPC answer. An HTTP error would be a
            // transport problem to them — and they would retry it.
            _ => Box::pin(async move {
                let (parts, ()) = Status::unimplemented("unknown method")
                    .into_http::<()>()
                    .into_parts();
                Ok(http::Response::from_parts(parts, Body::empty()))
            }),
        }
    }
}

/// Produces the three forwarders. They differ only in type and method; written
/// out they would be the same twenty lines three times.
macro_rules! forward {
    ($name:ident, $req:ty, $resp:ty, $method:ident) => {
        struct $name {
            raft: Raft<TypeConfig>,
        }

        impl Service<Request<$req>> for $name {
            type Response = Response<$resp>;
            type Error = Status;
            type Future = BoxFuture<Self::Response, Self::Error>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, request: Request<$req>) -> Self::Future {
                let raft = self.raft.clone();
                Box::pin(async move {
                    raft.$method(request.into_inner())
                        .await
                        .map(Response::new)
                        // `internal`: an error here comes from the local Raft
                        // core, not from the other side. They shall see it but
                        // not take it for their own.
                        .map_err(|err| Status::internal(err.to_string()))
                })
            }
        }
    };
}

forward!(
    AppendEntriesSvc,
    AppendEntriesRequest<TypeConfig>,
    AppendEntriesResponse<NodeId>,
    append_entries
);
forward!(VoteSvc, VoteRequest<NodeId>, VoteResponse<NodeId>, vote);
forward!(
    InstallSnapshotSvc,
    InstallSnapshotRequest<TypeConfig>,
    InstallSnapshotResponse<NodeId>,
    install_snapshot
);
