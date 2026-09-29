//! The names of the metrics — in **one** place.
//!
//! A metric name is an interface: it stands in dashboards, in alert rules and
//! in reports somebody has to retain. Writing it twice in the code means
//! changing it at one of the two places eventually.
//!
//! # The rule on cardinality
//!
//! ADR-0015 names cardinality as an open point. Here stands the answer:
//!
//! > **A label may take only values whose number the cluster bounds.**
//!
//! Permitted is thereby exactly what [`LABELS`] enumerates — and **because** it
//! enumerates it: an enumeration in prose lags behind reality, and that was
//! exactly the case here (the rule named seven, thirteen were set). The list is
//! the mechanism, this table the justification, and a guard holds both together
//! with the setting places.
//!
//! | Label | What bounds its number |
//! |---|---|
//! | `node` | the cluster's nodes — five (ADR-0031) |
//! | `workload` | the declared workloads |
//! | `replica` | a declaration's `replicas` (ADR-0034) — and the name is not `instance`, because Prometheus sets that (ADR-0118) |
//! | `volume` | the declared volumes (ADR-0027) |
//! | `resource` | declared capacity and workload definitions (ADR-0034) |
//! | `domain` | the nodes' failure domains (ADR-0011) |
//! | `kind` | the command kinds (ADR-0004) |
//! | `outcome` | a fixed set of words in the code, no setting of the requester |
//! | `class` | the error classes from `RuntimeError::class` and the rejection reasons from `PlacementError::class` — each a `match` without a catch-all arm |
//! | `direction` | `ingress` and `egress` |
//! | `rpc` | the three Raft calls |
//! | `task` | the supervised tasks, fixed names in the code |
//! | `peer` | a node's **id**, not its address |
//! | `fingerprint` | a cluster has one data key and one signing group (ADR-0095/0107) |
//! | `reason` | the four variants of `Refusal` in the QUIC egress (ADR-0121) |
//! | `listener` | a sidecar's **three** listeners, an `enum` in the code (ADR-0114) |
//!
//! The last row is the one that most looks like a violation of the prohibition
//! list below, and the second to last likewise: forbidden are peer
//! **addresses**, connection ids, SPIFFE IDs, instance ids from requests and
//! everything that stems from a payload — of those there are as many as anyone
//! cares to produce, and a metric with an unbounded label is a memory leak with
//! a Prometheus connection.
//!
//! # The rule on cadence
//!
//! The second half of the same question, answered in **ADR-0088**: gauges decay
//! after 15 minutes, so that an alert about something that no longer exists
//! falls silent.
//!
//! > **Whoever introduces a gauge answers along with it at what cadence it is
//! > set.** Either clearly below the deadline — a reconcile pass, a report, a
//! > scheduler step —, or it registers a refresh: `Health::on_scrape`.
//!
//! For **counters** the decay does not apply, and that is no symmetry exercise:
//! disappearing and returning reads to `rate()` as a reset.
//!
//! Whoever does not answer the question gets a time series that silently
//! disappears.
//!
//! **A guard for that is expressly not built, and the reason is a different one
//! than once stood here.** It said gauges were not enumerable — they very much
//! are, via their `gauge!` setting places in the production part. What cannot
//! be decided mechanically is the **classification**: whether `reconcile::step`
//! lies "clearly below the deadline" a reader knows and a guard does not — and
//! the list of functions that count as a cadence would be exactly the
//! hand-maintained one this tree knows as a source of error.
//!
//! A **number** once stood here ("35, found mechanically"). It is struck, and
//! the reason belongs to the rule: re-measured, neither the setting places nor
//! the names yield it — a number about the tree that nobody can recompute is
//! the next one to become wrong. And a guard over it would be one that goes red
//! on **every** new metric without anything being wrong: work instead of a
//! caught error.
//!
//! One subtlety belongs to it, because it misleads a naive measurement:
//! `Health::on_scrape` takes **one** name as the key, and the callback may set
//! several metrics — [`SIGNER_EPOCHS`] hangs on the key [`SIGNER_EPOCH`],
//! [`VOLUME_SNAPSHOT_AT`] on [`VOLUME_SNAPSHOTS`]. Whoever asks "does the name
//! stand in an `on_scrape`?" reports those two as missing.
//!
//! **The reverse direction is by contrast guarded** (`tests/refreshed.rs`): it
//! does not ask "does this metric need a registration?" but reads the
//! registrations from the source and nails them down. Whoever removes one must
//! justify it; the classification stays with the reader, and the subtlety above
//! does not interfere, because no name stands in the list that nobody
//! registered.
//!
//! # The label `node` means two things
//!
//! `tg_telemetry::init` hangs a global `node` on **every** metric — the process
//! that reports it. A few metrics, however, carry `node` themselves: the
//! `tg_node_*` family means by it the **observed** node the leader speaks
//! about.
//!
//! Measured against `metrics-exporter-prometheus`: the local label **wins**,
//! and the global one is **silently discarded** for these series:
//!
//! ```text
//! add_global_label("node", "tgd-1") + gauge!("tg_node_attached", "node" => "node-9")
//!   → tg_node_attached{node="node-9"} 0
//! ```
//!
//! For the alert rules that is the right meaning — `{{ $labels.node }}` names
//! the node at issue. But it means: **which process reported it does not stand
//! in `node` for these series**, but only in Prometheus's own `instance`.
//! Whoever reads `tg_node_slice_lag{node="tgd-1"}` and means "as tgd-1 sees it"
//! reads something else.
//!
//! From that follows the rule for new metrics: **`node` is the observed node.**
//! Whoever means the *reporting* process does not call it that — otherwise they
//! cover the global label and nobody sees it.
//!
//! # And the global label is not called `node` everywhere
//!
//! The rule above held for a while only for the local labels. Measured, all
//! three binaries filled the **global** one with three different meanings:
//! `tgd` with its Raft id (`1`), `tg-agent` with the node name (`node-11`) and
//! `tg-proxy` with the **workload** (`journal`). An alert text
//! `{{ $labels.node }}` thereby named something different per process — with a
//! sidecar a node that does not exist.
//!
//! Since [`crate::init::Reporter`], every process says **whom** its metrics
//! concern:
//!
//! | Process | global label |
//! |---|---|
//! | `tgd`, `tg-agent` | `node` — the **name** from ADR-0043 |
//! | `tg-proxy` | `workload` |
//!
//! With the sidecar that is no exercise in precision: it runs in the container
//! and **cannot** know the node name (ADR-0059). And it pairs its metrics with
//! the agent's `tg_workload_*`, which carry the same label.
//!
//! The rule for new metrics thereby reads in full: **a label is named after
//! what stands in it.** Whoever introduces a metric in the sidecar gets
//! `workload` and not `node` — the call is held fast by a guard in
//! `crates/tg-syscall/tests/invariants.rs`.

pub const LABELS: &[&str] = &[
    "class",
    "direction",
    "domain",
    "fingerprint",
    "kind",
    // **A sidecar's three listeners** (ADR-0114). The set is
    // `tg_proxy::sidecar::Listener` -- an `enum` with three variants, hence
    // bounded by the code and not by a connection. The **port number**
    // expressly does not belong here: it comes from a setting and would be
    // different per node (the same argument as with `PROXY_WRONG_PORT`).
    "listener",
    "node",
    "outcome",
    "peer",
    // **Why a datagram was not allowed out** (ADR-0121, determination 6). The
    // set is `tg_proxy::quic_egress::Refusal`, and since ADR-0131 one of its
    // variants fans out into the six of `quic::QuicError`: nine values, all
    // bounded by the code, none from a datagram. The **version number** of an
    // unread initial expressly does not belong to it — it comes from a
    // container and stands in the log. `outcome` would be the wrong name for
    // it: there stands a state machine's verdict, and a label is named after
    // what stands in it.
    "reason",
    // **The instance number, and it is not called `instance`** (ADR-0118,
    // determination 2). The name is barred above because Prometheus sets it;
    // the thing itself satisfies this list's rule: its values are bounded by
    // the declaration's `replicas`, hence by a number in the log.
    "replica",
    "resource",
    "rpc",
    "task",
    "volume",
    "workload",
];

pub const APPLIED: &str = "tg_consensus_applied_total";

pub const AUDIT_RECORDS: &str = "tg_audit_records_total";

pub const AUDIT_BYTES: &str = "tg_audit_bytes";

pub const AUDIT_SEGMENTS: &str = "tg_audit_segments";

pub const RECONCILE: &str = "tg_agent_reconcile_total";

pub const RECONCILE_SECONDS: &str = "tg_agent_reconcile_seconds";

pub const WORKLOAD_RESTARTS: &str = "tg_workload_restarts_total";

pub const SVID_ISSUED: &str = "tg_identity_svid_issued_total";

pub const WORKLOAD_API_CALLS: &str = "tg_identity_workload_api_calls_total";

pub const PROXY_DECISIONS: &str = "tg_proxy_decisions_total";

pub const PROXY_POLICY_REFRESHED_AT: &str = "tg_proxy_policy_refreshed_at_timestamp_seconds";

pub const PROXY_EGRESS_REFRESHED_AT: &str = "tg_proxy_egress_refreshed_at_timestamp_seconds";

pub const CLUSTER_ORDINALS_USED: &str = "tg_cluster_ordinals_used";

pub const CLUSTER_ORDINALS_CAPACITY: &str = "tg_cluster_ordinals_capacity";

pub const CLUSTER_VOLUME_TOMBSTONES: &str = "tg_cluster_volume_tombstones";

pub const CLUSTER_UDP_EGRESS_WORKLOADS: &str = "tg_cluster_udp_egress_workloads";

pub const DOMAIN_ABSORBS: &str = "tg_scheduler_domain_absorbs";

pub const DOMAIN_AT_RISK: &str = "tg_scheduler_domain_at_risk";

pub const DOMAIN_ELSEWHERE: &str = "tg_scheduler_domain_elsewhere";

pub const SCHEDULER_UNPLACEABLE: &str = "tg_scheduler_unplaceable";

pub const NODE_ATTACHED: &str = "tg_node_attached";

pub const ACTIVE_ROLE: &str = "tg_workload_active_role";

pub const LEASE_CLOCK_SKEW: &str = "tg_lease_clock_skew_seconds";

pub const DNS_ANSWERS: &str = "tg_dns_answers_total";

pub const WORKLOAD_FAILURES: &str = "tg_workload_failures_total";

pub const PROXY_IMAGES: &str = "tg_cluster_proxy_images";

pub const DNS_ZONES: &str = "tg_cluster_dns_zones";

pub const DATA_KEY: &str = "tg_identity_data_key_info";

pub const SECRETS_PREVIOUS: &str = "tg_cluster_secrets_previous";

pub const SIGNER: &str = "tg_identity_signer";

pub const SIGNER_SEATS: &str = "tg_identity_signer_seats";

pub const SIGNER_EPOCH: &str = "tg_identity_signer_epoch";

pub const SIGNER_GROUP: &str = "tg_identity_signer_group_info";

pub const SIGNER_EPOCHS: &str = "tg_identity_signer_epochs";

pub const SIGNER_SEALED: &str = "tg_identity_signer_share_sealed";

pub const USERNS_POSTURES: &str = "tg_cluster_userns_postures";

pub const KEY_GENERATION_LAG: &str = "tg_node_key_generation_lag";

pub const NODE_SLICE_LAG: &str = "tg_node_slice_lag";

pub const IDENTITY_CHALLENGES: &str = "tg_identity_challenges_total";

pub const NODE_ISOLATED: &str = "tg_node_isolated_entries";

pub const VOLUME_SIZE: &str = "tg_volume_size_bytes";

pub const CONTAINER_MEMORY: &str = "tg_container_memory_bytes";

pub const CONTAINER_CPU: &str = "tg_container_cpu_seconds_total";

pub const CONTAINER_MEMORY_PEAK: &str = "tg_container_memory_peak_bytes";

pub const CONTAINER_MEMORY_LIMIT: &str = "tg_container_memory_limit_bytes";

pub const CONTAINER_CPU_LIMIT: &str = "tg_container_cpu_limit_cores";

pub const VOLUME_DECLARED: &str = "tg_volume_declared_bytes";

pub const VOLUME_ENCRYPTED: &str = "tg_volume_encrypted";

pub const VOLUME_SNAPSHOTS: &str = "tg_volume_snapshots";

pub const VOLUME_SNAPSHOT_AT: &str = "tg_volume_snapshot_timestamp_seconds";

pub const RAFT_RPC_SECONDS: &str = "tg_raft_rpc_seconds";

pub const RAFT_RPC_FAILURES: &str = "tg_raft_rpc_failures_total";

pub const RAFT_RPC_DEADLINE: &str = "tg_raft_rpc_deadline_seconds";

pub const NODE_LAST_REPORT: &str = "tg_node_last_report_timestamp_seconds";

pub const INTERMEDIATE_EXPIRES_AT: &str = "tg_identity_intermediate_expires_at_timestamp_seconds";

pub const PROXY_SVID_EXPIRES_AT: &str = "tg_proxy_svid_expires_at_timestamp_seconds";

pub const OPEN_FDS: &str = "tg_process_open_fds";

pub const MAX_FDS: &str = "tg_process_max_fds";

pub const PROTOCOL_FIELDS: &str = "tg_process_protocol_fields";

pub const WORKLOAD_STALE: &str = "tg_workload_stale";

pub const WORKLOAD_READY: &str = "tg_workload_ready";

pub const WORKLOAD_PROBED: &str = "tg_workload_probed";

pub const WORKLOAD_PLACED: &str = "tg_workload_placed";

pub const WORKLOAD_REPLICAS: &str = "tg_workload_replicas";

pub const PEERS_MISSING: &str = "tg_raft_peers_missing";

pub const RAFT_LEADER: &str = "tg_raft_leader";

pub const TASK_ALIVE: &str = "tg_task_alive";

pub const TASK_RESTARTS: &str = "tg_task_restarts_total";

pub const PROXY_ROLE_EXPIRES_AT: &str = "tg_proxy_active_role_expires_at_timestamp_seconds";

pub const QUIC_EGRESS_REFUSED: &str = "tg_proxy_quic_egress_refused_total";

pub const QUIC_EGRESS_FLOWS: &str = "tg_proxy_quic_egress_flows";

pub const PROXY_WRONG_PORT: &str = "tg_proxy_wrong_port_total";

pub const PROXY_CONNECTIONS: &str = "tg_proxy_connections";

pub const PROXY_CONNECTIONS_TOTAL: &str = "tg_proxy_connections_total";

pub const EGRESS_UNROUTABLE: &str = "tg_proxy_egress_unroutable_total";

pub const EGRESS_ATTEMPTS_FAILED: &str = "tg_proxy_egress_attempts_failed_total";

pub const WORKLOAD_UNCLEAR: &str = "tg_workload_unclear_total";

pub const CONTENT_RECLAIMED_BYTES: &str = "tg_content_reclaimed_bytes_total";

pub const CONTENT_RECLAIMED_LAYERS: &str = "tg_content_reclaimed_layers_total";

pub const NODE_PRESSURE: &str = "tg_node_pressure";

pub const NODE_FREE: &str = "tg_node_free";

pub const NODE_DEVICES_ASSIGNED: &str = "tg_node_devices_assigned";
