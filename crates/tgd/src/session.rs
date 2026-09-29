//! The node service: the session to every agent (ADR-0040).
//!
//! **Not** the API from ADR-0018. An operator and a node are different callers
//! with different rights; laying them into one surface would mean building an RBAC
//! surface for two tenants that have nothing in common. This service has **one**
//! method.
//!
//! # To the leader, and followers refer onwards
//!
//! A follower answers with [`ControlMessage::ForwardTo`] -- the same pattern as
//! `Credentials::ForwardTo` in ADR-0037. The reason lies in the return direction:
//! per ADR-0004 the observed state does not belong in the log, and since ADR-0030
//! the projection lies in memory per node. A report to a follower would never be
//! seen by the scheduler.
//!
//! # No polling interval
//!
//! The stream hangs on `raft.metrics()` -- the same channel the projection already
//! hangs on (`crate::projection`). If `last_applied` changes, a new slice is
//! computed and sent. That is the difference ADR-0040 brings against option A
//! ("poll"), and it is what makes the time bound from ADR-0025 upholdable.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::StreamExt as _;
use openraft::Raft;
use tg_consensus::{ClusterState, NodeId, TypeConfig};
use tg_store::session::transport::{JsonCodec, SERVICE, SESSION};
use tg_store::session::{
    ClusterNetwork, ClusterView, ControlMessage, InstanceState, NodeMessage, NodeSlice,
    UnderlayPeer, slice_for,
};
use tg_store::{ActualStatus, Projection};
use tonic::body::Body;
use tonic::server::NamedService;
use tonic::{Request, Response, Status, Streaming};
use tower::Service;

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'static>>;

struct Granted {
    edges: Vec<(String, String)>,
    egress: Vec<(String, String, u16, tg_model::egress::Transport)>,
    secrets: Vec<(String, String, tg_identity::secrets::Sealed)>,
    registries: Vec<(String, String)>,
}

fn granted(state: &ClusterState) -> Granted {
    Granted {
        edges: state
            .traffic()
            .into_iter()
            .map(|(from, to)| (from.to_owned(), to.to_owned()))
            .collect(),
        egress: state
            .egress()
            .into_iter()
            .map(|(workload, host, port, transport)| {
                (workload.to_owned(), host.to_owned(), port, transport)
            })
            .collect(),
        // The read permissions together with the **sealed** value (ADR-0016,
        // ADR-0095). The plaintext lies nowhere in the cluster; `tgd` passes
        // ciphertext on and could not open it at all.
        secrets: state
            .secret_grants()
            .into_iter()
            .filter_map(|(workload, secret)| {
                state
                    .secret(secret)
                    .map(|value| (workload.to_owned(), secret.to_owned(), value.clone()))
            })
            .collect(),
        // Which secret applies for which registry (ADR-0096). The cutting happens
        // in `slice_for`; here stands the complete set.
        registries: state
            .registry_credentials()
            .into_iter()
            .map(|(registry, secret)| (registry.to_owned(), secret.to_owned()))
            .collect(),
    }
}

type Tombstones = std::collections::BTreeMap<String, Vec<String>>;

type SnapshotVerdicts = std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>>;

fn volume_verdicts(state: &ClusterState) -> (Tombstones, SnapshotVerdicts) {
    let deleted = state
        .deleted_volumes()
        .into_iter()
        .map(|(node, volumes)| {
            (
                node.to_owned(),
                volumes.into_iter().map(str::to_owned).collect(),
            )
        })
        .collect();

    let snapshots = state
        .snapshot_generations()
        .into_iter()
        .map(|(node, wanted)| {
            (
                node.to_owned(),
                wanted
                    .into_iter()
                    .map(|(volume, generation)| (volume.to_owned(), generation))
                    .collect(),
            )
        })
        .collect();

    (deleted, snapshots)
}

#[must_use]
pub fn view_of(
    state: &ClusterState,
    index: u64,
    endpoints: std::collections::BTreeMap<String, Vec<tg_store::session::RemoteEndpoint>>,
) -> ClusterView {
    let placements = state
        .placements()
        .into_iter()
        .map(|(workload, instance, node)| (workload.to_owned(), instance, node.to_owned()))
        .collect();

    let documents = state
        .workloads()
        .into_iter()
        .map(|entry| (entry.name().to_owned(), entry.document().to_owned()))
        .collect();

    let Granted {
        edges,
        egress,
        secrets,
        registries,
    } = granted(state);

    // Only nodes that have already announced are peers. One without a key and an
    // endpoint would be a peer that never answers (ADR-0039).
    let peers = state
        .underlay()
        .into_iter()
        .filter_map(|(node, entry)| {
            Some(UnderlayPeer {
                node: node.to_owned(),
                ordinal: entry.ordinal(),
                key: entry.key()?.to_owned(),
                endpoint: entry.endpoint()?.to_owned(),
            })
        })
        .collect();

    // Which key generations shall apply (ADR-0055).
    // From its own map and not from `nodes()`: the condition is the admission, not
    // the inventory (ADR-0055).
    let generations = state
        .underlay()
        .into_iter()
        .map(|(node, _)| (node.to_owned(), state.key_generations(node)))
        .collect();

    // Who does not belong to the data plane (ADR-0054). From `nodes()` and not
    // from `underlay()`: a node that has not yet announced anything can be
    // detached too.
    let detached = state
        .nodes()
        .into_iter()
        .filter(|(_, entry)| !entry.attachment().in_mesh())
        .map(|(node, _)| node.to_owned())
        .collect();

    let ordinals = state
        .underlay()
        .into_iter()
        .map(|(node, entry)| (node.to_owned(), entry.ordinal()))
        .collect();

    let (deleted_volumes, snapshot_generations) = volume_verdicts(state);

    // **The active-role leases** (ADR-0064). `slice_for` filters its own out of
    // them; here stands the whole map, because `view_of` is the cluster's view and
    // not a node's.
    let leases = state
        .workloads()
        .into_iter()
        .filter_map(|entry| {
            let lease = state.lease(entry.name())?;
            Some((
                entry.name().to_owned(),
                tg_store::session::Lease {
                    holder: lease.holder().to_owned(),
                    epoch: lease.epoch().get(),
                    expires_at: lease.expires_at().get(),
                },
            ))
        })
        .collect();

    ClusterView {
        index,
        leases,
        workload_generations: workload_generations_of(state),
        placements,
        documents,
        edges,
        egress,
        secrets,
        registry_credentials: registries,
        peers,
        deleted_volumes,
        snapshot_generations,
        generations,
        detached,
        ordinals,
        network: state.network().map(|(cidr, node_prefix)| ClusterNetwork {
            cidr: cidr.to_owned(),
            node_prefix,
        }),
        // **Observed, not replicated** (ADR-0073): the addresses come from the
        // projection and not from `state`. That is why they are a parameter and
        // are not fetched here -- `view_of` stays a pure function over its inputs,
        // and the caller decides which view of the observation it uses.
        endpoints,
        // ADR-0111: which instance carries the active role. Only the deviations
        // -- a missing entry means instance 0.
        active_instances: state
            .active_instances()
            .into_iter()
            .map(|(workload, instance)| (workload.to_owned(), instance))
            .collect(),
        // ADR-0086: from it the node forms the limit of its sidecars.
        sidecar_overhead: state
            .sidecar_overhead()
            .entries()
            .into_iter()
            .map(|(name, amount)| (name.to_owned(), amount))
            .collect(),
    }
}

fn workload_generations_of(
    state: &ClusterState,
) -> std::collections::BTreeMap<String, tg_model::rollout::Generations> {
    state
        .workloads()
        .into_iter()
        .map(|entry| {
            (
                entry.name().to_owned(),
                state.workload_generations(entry.name()),
            )
        })
        .filter(|(_, generations)| !generations.is_empty())
        .collect()
}

#[derive(Clone)]
pub struct NodeService {
    id: NodeId,
    raft: Raft<TypeConfig>,
    state: tg_consensus::StateHandle,
    projection: Arc<Projection>,
}

impl NodeService {
    #[must_use]
    pub fn new(
        id: NodeId,
        raft: Raft<TypeConfig>,
        state: tg_consensus::StateHandle,
        projection: Arc<Projection>,
    ) -> Self {
        Self {
            id,
            raft,
            state,
            projection,
        }
    }
}

impl std::fmt::Debug for NodeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeService").finish_non_exhaustive()
    }
}

impl NamedService for NodeService {
    const NAME: &'static str = SERVICE;
}

impl<B> Service<http::Request<B>> for NodeService
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
        let service = self.clone();

        match request.uri().path() {
            SESSION => {
                // **Here** the node name arises (ADR-0043, determination 7): from
                // the connection's credential, not from the first message. Whoever
                // has none does not get this far at all -- the port demands it
                // (`client_auth_mandatory`).
                let Some(node) = peer_node(&request) else {
                    return Box::pin(async move {
                        let (parts, ()) =
                            Status::unauthenticated("no node credential on the connection")
                                .into_http::<()>()
                                .into_parts();
                        Ok(http::Response::from_parts(parts, Body::empty()))
                    });
                };

                Box::pin(async move {
                    let mut grpc =
                        tg_wire::server(JsonCodec::<ControlMessage, NodeMessage>::default());
                    Ok(grpc.streaming(SessionSvc(service, node), request).await)
                })
            }
            // As with the Raft service: an unknown path is `UNIMPLEMENTED` and no
            // 404 -- the caller speaks gRPC.
            _ => Box::pin(async move {
                let (parts, ()) = Status::unimplemented("unknown method")
                    .into_http::<()>()
                    .into_parts();
                Ok(http::Response::from_parts(parts, Body::empty()))
            }),
        }
    }
}

fn peer_node<B>(request: &http::Request<B>) -> Option<String> {
    let info = request
        .extensions()
        .get::<tonic::transport::server::TlsConnectInfo<tonic::transport::server::TcpConnectInfo>>(
        )?;
    let certs = info.peer_certs()?;
    let leaf = certs.first()?;

    tg_identity::cluster::spiffe_id_of(leaf)
        .ok()?
        .node()
        .map(str::to_owned)
}

struct SessionSvc(NodeService, String);

impl tonic::server::StreamingService<NodeMessage> for SessionSvc {
    type Response = ControlMessage;
    type ResponseStream = tokio_stream::wrappers::ReceiverStream<Result<ControlMessage, Status>>;
    type Future = BoxFuture<Response<Self::ResponseStream>, Status>;

    fn call(&mut self, request: Request<Streaming<NodeMessage>>) -> Self::Future {
        let service = self.0.clone();
        let node = self.1.clone();

        Box::pin(async move {
            // The buffer is small and on purpose: a node that does not keep up
            // shall produce backpressure and not memory (ADR-0030 names the
            // broadcast lag as an open point).
            let (sender, receiver) = tokio::sync::mpsc::channel(8);
            let incoming = request.into_inner();

            tokio::spawn(async move { service.run(node, incoming, sender).await });

            Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
        })
    }
}

impl NodeService {
    async fn run(
        self,
        node: String,
        mut incoming: Streaming<NodeMessage>,
        sender: tokio::sync::mpsc::Sender<Result<ControlMessage, Status>>,
    ) {
        // The name already stands fixed -- it comes from the connection's
        // credential (ADR-0043, determination 7). `Hello` says only how far the
        // node is.
        // **Three cases, not one** (ADR-0072, determination 4). A `let ... else`
        // stood here that pulled everything together into "the first message must
        // be a Hello" -- and that is precisely the place at which a version skew
        // stands out first: `Hello` is the first thing an agent sends. A newer
        // agent thereby got a rejection that told it something false, and the
        // server wrote nothing.
        let applied = match incoming.next().await {
            Some(Ok(NodeMessage::Hello { applied })) => applied,
            Some(Ok(NodeMessage::Report(_))) => {
                let _ = sender
                    .send(Ok(ControlMessage::Refused {
                        reason: "the first message must be a Hello".to_owned(),
                    }))
                    .await;
                return;
            }
            Some(Err(status)) => {
                tracing::warn!(
                    %node,
                    %status,
                    "the session's inbound is unreadable -- a version skew or a \
                     transport error (ADR-0072)"
                );
                // The reason goes **out with it**: the agent reports it on its side
                // (`session ended`), and an operator who looks only there shall not
                // read "no Hello" when the server could not read the message at
                // all.
                let _ = sender
                    .send(Ok(ControlMessage::Refused {
                        reason: "the first message was unreadable (ADR-0072)".to_owned(),
                    }))
                    .await;
                return;
            }
            // A client that says nothing and leaves. There is nothing to report
            // about that -- and nobody one could answer.
            None => return,
        };

        let mut metrics = self.raft.metrics();
        if metrics.borrow().current_leader != Some(self.id) {
            let leader = metrics.borrow().current_leader;
            let _ = sender.send(Ok(ControlMessage::ForwardTo { leader })).await;
            return;
        }

        let mut sent = applied;

        loop {
            // `borrow_and_update`, not `borrow` -- and the rationale is not the
            // one that stood here for a long time. It read "otherwise `changed()`
            // returns at once, a hot loop that burns a core": **measured,
            // `changed()` marks the state itself**, so the number of rounds is the
            // same in both worlds. The comment came with the code (ADR-0040) --
            // there never was a checked-in `borrow` here, the hot loop was not
            // substantiated.
            //
            // What carries the shape is the case beside it: **`has_changed()` does
            // not mark.** Whoever one day replaces the `changed()` below with a
            // query or takes it out of the loop gets with `borrow` exactly the loop
            // the old comment claimed -- and with `borrow_and_update` not. Both
            // facts have a witness in `tgd/tests/watch_marking.rs`.
            let index = metrics
                .borrow_and_update()
                .last_applied
                .map_or(0, |log_id| log_id.index);

            // **`> sent`, not `> 0`.** `sent` begins with the state the node
            // named in its `Hello` -- a leader that is still catching up thereby
            // sends nothing at all.
            //
            // This line stands between "the leader lies behind" and "every
            // container of this node is ended": the slice is a snapshot, what it
            // does not name is cleared out of the cache by `session::apply`
            // (ADR-0040, determination 6), and what does not stand in the cache is
            // ended by the clearer (ADR-0058). Measured, without it an
            // `instances: []` comes out at state 6 while the node is at 200.
            // Guarded by `a_lagging_leader_sends_no_slice`.
            tokio::select! {
                // **A fixed order, no dice.** `select!` chooses randomly among
                // ready branches; without this here a slice that is due would be
                // lost as soon as the other side closes its send direction -- in
                // about every second run. Before ADR-0068 the send stood before the
                // selection and thereby had the same priority; `biased` restores it
                // without fetching the coupling back. Found by
                // `a_renewal_carries_the_underlay_announcement_into_the_log`.
                //
                // The branch cannot starve: after the send `sent == index` stands,
                // and the precondition switches it off.
                biased;

                // **Room in the outbound -- and only then compute** (ADR-0068).
                //
                // The send once stood here *before* the selection, with an `.await`
                // on the channel. As long as that hangs, `incoming` is not polled,
                // so nothing is absorbed, so `report_seen` is not set -- the node
                // drops out of `reporting_since`, `leases()` skips the renewal, and
                // a **healthy** single writer fences itself (ADR-0064, ADR-0010).
                // Triggered by the leader's backlog, not by a partition.
                //
                // `reserve` is promised cancel-safe in `tokio` and thereby belongs
                // in a branch. The slice is computed **after** the reservation: that
                // way it is as fresh as possible instead of as old as the waiting
                // time.
                permit = sender.reserve(), if index > sent => {
                    let Ok(permit) = permit else { return };
                    // **One span per slice** (ADR-0133, D3), and it hangs on the
                    // command that triggered it: the note beside the state carries
                    // its `traceparent` (D4). It names the **last** applied entry
                    // -- there is one slice per state, not per command.
                    let span = tracing::info_span!("slice", node = %node, index);
                    tg_telemetry::trace::adopt(&span, self.state.trace().as_deref());
                    let _entered = span.enter();

                    let mut slice = slice_for(
                        &node,
                        &view_of(
                            &self.state.read(),
                            index,
                            self.projection.reported_endpoints(),
                        ),
                    );
                    // And it travels along: the pass on the node hangs on it.
                    // Without an exporter that is `None` and costs a field `serde`
                    // leaves out.
                    slice.trace = tg_telemetry::trace::of(&span);
                    permit.send(Ok(ControlMessage::Slice(Box::new(slice))));
                    sent = index;
                }
                // A change in the log -- the next pass sends.
                changed = metrics.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    // The leadership can have changed in the meantime. Then this
                    // node is no longer responsible, and the agent shall learn it
                    // instead of quietly getting stale slices.
                    if metrics.borrow().current_leader != Some(self.id) {
                        let leader = metrics.borrow().current_leader;
                        let _ = sender.send(Ok(ControlMessage::ForwardTo { leader })).await;
                        return;
                    }
                }
                message = incoming.next() => {
                    match message {
                        Some(Ok(NodeMessage::Report(report))) => self.absorb(&node, &report),
                        Some(Ok(NodeMessage::Hello { .. })) => {
                            // A second Hello is a protocol error. Taking it
                            // silently would mean allowing a node to become another
                            // one in the middle of the stream.
                            let _ = sender
                                .send(Ok(ControlMessage::Refused {
                                    reason: "Hello comes exactly once".to_owned(),
                                }))
                                .await;
                            return;
                        }
                        // **An unreadable inbound is reported** (ADR-0072,
                        // determination 4). `Some(Err(_)) | None => return` stood
                        // here -- two cases in one, and the more interesting of
                        // them silently: a decoding error means that the other side
                        // sends something this `tgd` does not understand. That is
                        // the one place at which a version skew becomes visible on
                        // the server side, and it was mute.
                        Some(Err(status)) => {
                            tracing::warn!(
                                %node,
                                %status,
                                "the session's inbound is unreadable -- a version \
                                 skew or a transport error (ADR-0072)"
                            );
                            return;
                        }
                        // A proper end: the node has closed the stream, say because
                        // its process ends. There is nothing to say about that.
                        None => return,
                    }
                }
            }
        }
    }

    fn absorb(&self, node: &str, report: &tg_store::session::NodeReport) {
        // The reported capacity goes into the projection and **nowhere else**
        // (ADR-0049, determination 2). From there the leader fetches it when it
        // applies a policy; the planner never sees it.
        //
        // The name comes from the connection's **credential** (ADR-0043) and not
        // from the report: otherwise a node would report capacity for another.
        if !report.capacity.is_empty() {
            self.projection
                .report_capacity(node, report.capacity.clone());
        }

        // **When it reported** (ADR-0057, determination 4). A point in time and
        // no age: an age somebody would have to carry forward and it would be wrong
        // between two carryings-forward. The age is computed by the query.
        //
        // It replaces the rejected auto-detach: here an operator sees who keeps
        // quiet -- deciding is their business.
        if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            metrics::gauge!(
                tg_telemetry::names::NODE_LAST_REPORT,
                "node" => node.to_owned()
            )
            .set(now.as_secs_f64());

            // **And into the projection** (ADR-0064): the active-role lease is
            // renewed for a node that **reports**. A metric alone does not suffice
            // for that -- the planner reads no metrics.
            self.projection
                .report_seen(node, i64::try_from(now.as_secs()).unwrap_or(i64::MAX));
        }

        // And the reported key generations (ADR-0055, determination 5). Likewise
        // only into the projection: the planner never sees them, and the log goes
        // on saying alone what **shall** apply.
        self.projection
            .report_key_generations(node, report.generations);

        // And what it builds its sidecars with (ADR-0059). Likewise only into the
        // projection -- the setting stays one per node, what becomes visible is
        // only when two drift apart.
        self.projection
            .report_proxy_image(node, report.proxy_image.as_deref());

        // **The metric arises here and not in the scheduler**, and that is
        // measured: the scheduler hangs on `raft.metrics()` and runs only when the
        // log moves. A report does not move it -- the backlog would therefore have
        // stayed too **high** after the catching up, until something else is
        // written at some point. A metric that falls too late is worse than none.
        //
        // Here is at the same time the place at which only the leader stands: the
        // session runs against it (ADR-0040).
        // **Which slice this node has applied** (ADR-0040).
        //
        // The number has stood in every report since ADR-0040 and was read by
        // **nobody**. The backlog to the leader's log is the one number at which a
        // node stands out that gets slices and does not apply them: its report
        // keeps coming, so `tg_node_last_report` moves, and from the cluster it
        // looks healthy.
        //
        // **The slice's index is the log index** it was computed from (`view_of`)
        // -- the two numbers are thereby comparable.
        self.projection.report_slice(node, report.applied);
        let log = self
            .raft
            .metrics()
            .borrow()
            .last_applied
            .map_or(0, |log| log.index);
        metrics::gauge!(
            tg_telemetry::names::NODE_SLICE_LAG,
            "node" => node.to_owned()
        )
        // **No `warn!` beside it**, unlike with the generation backlog: there the
        // number changes only when an operator has decreed something, here at
        // **every** write -- between a log entry and the next report the backlog is
        // temporarily positive. An alarm rule therefore reads the **duration**, as
        // with `tg_workload_active_role`.
        // A backlog of more than 2^53 slices is no situation a metric would have to
        // save -- the same bound as with the generation backlog beside it.
        .set(f64::from(
            u32::try_from(log.saturating_sub(report.applied)).unwrap_or(u32::MAX),
        ));

        let wanted = self.state.read().key_generations(node);
        for kind in tg_consensus::KeyKind::ALL {
            let lag = wanted.of(kind).saturating_sub(report.generations.of(kind));
            metrics::gauge!(
                tg_telemetry::names::KEY_GENERATION_LAG,
                "node" => node.to_owned(),
                "kind" => kind.as_str()
            )
            // A backlog of more than 2^53 generations is no situation a metric
            // would have to save.
            .set(f64::from(u32::try_from(lag).unwrap_or(u32::MAX)));

            if lag > 0 {
                tracing::warn!(
                    %node,
                    kind = kind.as_str(),
                    lag,
                    "a decreed key rotation has not arrived"
                );
            }
        }

        // **Which instances run stale** (ADR-0070). Likewise only into the
        // projection: it is an observation, and the planner never sees it -- a
        // changed declaration must not move a placement.
        //
        // A metric of its own does **not** arise here: the node exports
        // `tg_workload_stale` itself already, and Prometheus asks every node
        // anyway. What was missing here was the **one** place to look at, and that
        // is `tgctl cluster show`.
        self.projection.report_stale(node, report.stale.clone());

        // **And which do not serve** (ADR-0080). Without this line
        // `reported_endpoints` computes the health from the states alone -- and a
        // **foreign** node offers the address of an unready instance while its own
        // keeps it quiet (ADR-0073). Visibly different answers for the same name,
        // depending on who asks.
        self.projection.report_unready(node, report.unready.clone());

        // **And why a reconciliation failed** -- the class, not the text
        // (ADR-0015). Without it `tgctl cluster show` says only `Failed`, and the
        // first question in operation would demand shell access to the right
        // node.
        self.projection
            .report_failures(node, report.failures.clone());

        // **And what it could not classify** (ADR-0062, determination 6). The node
        // reports it per pass into its log; without this line a broken declaration
        // is to be found only there, and the leader reads "never seen" for the
        // workload -- the same as with a node that has never reported.
        //
        // **The names do not stand at the label**: they come from file names in the
        // data directory, and their number is bounded by nothing the cluster knows
        // (the cardinality rule in `tg_telemetry::names`). Which ones they are is
        // said by `tgctl cluster nodes`.
        metrics::gauge!(
            tg_telemetry::names::NODE_ISOLATED,
            "node" => node.to_owned()
        )
        .set(f64::from(
            u32::try_from(report.isolated.len()).unwrap_or(u32::MAX),
        ));
        self.projection
            .report_isolated(node, report.isolated.clone());

        // **And which tombstones it has executed** (ADR-0104). The leader makes a
        // `RetireTombstone` of it -- the same construction as with the capacity
        // above: the node reports observed state, the leader writes. ADR-0040
        // determination 7 stays untouched.
        //
        // The name comes from the **credential**, not from the report: otherwise a
        // node would confirm another's deletion.
        self.projection.report_retired(node, report.retired.clone());

        // **The endpoints** (ADR-0073). The node that handed out the address is
        // the only one that knows it (phase 9a) -- here it lands in the
        // projection, and `slice_for` gives it to the nodes whose workloads may
        // dial it. No log entry: ADR-0040 determination 7 stays untouched.
        self.projection
            .report_endpoints(node, report.endpoints.clone());

        // **And which zone it serves** (ADR-0013). Visibility, no decision -- the
        // same construction as with the proxy image (ADR-0059).
        self.projection
            .report_dns_zone(node, report.dns_zone.as_deref());
        // **And whether it maps** (ADR-0091). The same construction, the same
        // reason: `--userns-base` is a setting per node, and a skew in the security
        // posture would otherwise be seen by nobody.
        self.projection.report_userns(node, report.userns);

        // The instance number goes in. It once stood here as `_instance` -- the
        // node reported it, and the leader threw it away; together with the zero the
        // agent sent until then that meant: the leader's projection did not know
        // instances at all.
        //
        // **Replacing per node**, like the neighbours above. Previously it was
        // reported per instance and only `materialize` ever cleared up -- so every
        // movement of the log lost the whole actual state, while `stale`, `unready`
        // and `failures` survived.
        self.projection.report_instances(
            node,
            report
                .states
                .iter()
                .map(|(workload, instance, state)| {
                    let status = match state {
                        InstanceState::Running => ActualStatus::Running,
                        InstanceState::Stopped => ActualStatus::Stopped,
                        InstanceState::Failed => ActualStatus::Failed,
                    };
                    (workload.clone(), *instance, status)
                })
                .collect(),
        );
    }
}

#[must_use]
pub fn slice_of(state: &ClusterState, index: u64, node: &str) -> NodeSlice {
    slice_for(
        node,
        &view_of(state, index, std::collections::BTreeMap::new()),
    )
}
