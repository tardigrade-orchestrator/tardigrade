# Architecture Decision Records — Tardigrade Container Orchestrator (pure Rust)

This folder holds the project's architecture decisions. For format & process see
**ADR-0001**, for the template see **0000-template.md**.

## Product guard rails (requirements)

- SPIFFE identity per container, zero-trust mTLS
- Startup dependency management (systemd-analogous: Wants/Requires/After/Before …)
- Clustering / HA-capable
- Monitoring-capable
- **Entirely userspace, no eBPF**
- Definitions via XML + XSD
- Dependencies modelled as a **graph** (not as foreign-key fields)
- **Pure Rust**

### Operational context (frames all ADRs)

- **REMIT/DORA-regulated.** Demonstrable operational resilience, a
  tamper-evident audit trail, retention obligations, controllable third-party /
  concentration risk.
- **Target workload availability: 4-9 to 5-9 (99.99–99.999 %).**
- **Exclusions with a rationale:** no Go (GC jitter → non-deterministic tail
  latency), no Kubernetes (opacity/audit, concentration risk, control plane in
  the critical path). Both "broken by design" for this case.
- **Guiding principle:** static stability — the workload SLO is decoupled from
  the control plane (ADR-0019).

## Decision backlog

| ADR | Title | Status |
|-----|-------|--------|
| 0001 | ADR format and process | accepted |
| 0002 | Language, async runtime, process model | accepted |
| 0003 | OCI runtime & image distribution (youki + Rust puller) | accepted — youki+crun; the layer store has held overlayfs-native layers since 0052 |
| 0004 | Configuration store (role & bounds) | accepted — option B; store choice replaced by 0030 |
| 0005 | **Cluster consensus, leader election, HA** | accepted — `openraft` |
| 0006 | Workload identity per SPIFFE (without SPIRE) | accepted — path form replaced by 0036; attestation basis made precise by 0053 |
| 0007 | Zero-trust mTLS data plane (userspace, no eBPF) | accepted — the sidecar has run since 0059, derived on the node |
| 0008 | Definition format XML + XSD (via codegen) | accepted |
| 0009 | Startup dependency semantics (systemd-analogous as a graph) | accepted — orthogonal axes; the runtime evaluation and the damping decided in 0061 |
| 0010 | Reconciliation model & autonomy boundary | accepted — fenced-autonomous; the path of the active-role lease into the log decided in 0064; the list of autonomous actions extended by 0058 and 0061; what a pass error may cost decided in 0062 |
| 0011 | Scheduler / placement | accepted — declarative-explicit, no auto-rebalancing |
| 0012 | Container networking (kernel data path veth/bridge/nftables, no eBPF) | accepted — kernel WireGuard full mesh; nftables mechanism replaced by 0038; the underlay carries **container** traffic, not the management ports (measured in 0043); the containers have really hung on it since "The containers onto the network", the redirect has lain since 0060 |
| 0013 | Service discovery & DNS | accepted — DNS front end, graph-backed |
| 0014 | PKI / CA hierarchy (air-gapped root + threshold signing/FROST) | accepted — completed before phase 7, implemented in 7a/7b |
| 0015 | Observability (metrics/tracing/probes) | accepted |
| 0016 | Secrets management & registry credentials | accepted — SPIFFE-native, in-memory; the **delivery mechanism** decided in 0098 (tmpfs instead of an API), registry credentials in 0096 |
| 0017 | Privilege model & workload hardening | accepted — privileged agent, hardened workloads, hardening on by default |
| 0018 | API surface (tgctl, gRPC/tonic) | accepted — access local first, refined by 0044 |
| 0019 | **Availability / resilience model (static stability)** | accepted — keystone |
| 0020 | Audit trail & data retention (Raft log as a WORM substrate, REMIT/DORA) | accepted |
| 0021 | Failure domains & topology | accepted — covered in 0011 |
| 0022 | Data plane runtime & latency determinism | accepted — tokio thread-per-core; measured in 0114: the tail advantage is unsubstantiated, `io_uring` rejected, the pinning a setting |
| 0023 | Supply chain governance (SBOM, crate pinning, exit strategy, concentration risk) | accepted |
| 0024 | Time source & traceable timestamps (REMIT reporting) | accepted |
| 0025 | Service-to-service authorization (meshing policy) | accepted — statically selective |
| 0026 | XSD codegen — supply chain of the definition path | accepted — vendoring + quick-xml 0.41 |
| 0027 | Storage & volumes | accepted — writable exclusive, shared read-only; the resize part of the PV lifecycle decided in 0063 |
| 0028 | Device access via CDI (accelerator inference) | accepted — seam defined, implementation deferred |
| 0029 | SurrealDB under BSL 1.1 — licence acceptance | superseded by 0030 |
| 0030 | Projection without a database — replacing SurrealDB | accepted — in-process projection |
| 0031 | Cluster size five, quorum three | accepted |
| 0032 | Consensus implementation (version, log storage, simulation approach) | accepted |
| 0033 | Time/determinism in the DST harness, runtime bound of replication | accepted — the three decisions are built, enforced and measured; open is **one number per installation** (`RTT(p99)`) |
| 0034 | Placement model — instances, capacity, anti-affinity default | accepted — closes the open points from 0011 |
| 0035 | Surface of the workload API (own protocol vs. SPIFFE standard) | accepted — SPIFFE standard, implemented in 7c |
| 0036 | Identity of the sidecar and form of the SPIFFE path | accepted — delegation, path without a namespace |
| 0037 | Node attestation and bootstrap | accepted — join token one-time, the key is the identity; signature scope changed by 0042, then by 0046 |
| 0038 | The nftables path (licence collision 0012 ↔ 0023) | accepted — `nft` as its own process |
| 0039 | The WireGuard underlay (control path, keys, peers, ordinal) | accepted — netlink, no program; connected in the agent, routes without an address; rotation decided in 0055 |
| 0040 | The path from the control plane to the node | accepted — one session, established by the node |
| 0041 | Egress policy — traffic out of the mesh | accepted — the sidecar decides by SNI |
| 0042 | Events between node and log | accepted — the credential path carries them, deletions as tombstones; determination 2 (signature scope) replaced by 0046; the announcement asks back since the comparison in the slice |
| 0043 | mTLS on the cluster transports | accepted — the key is the credential, anchor depending on the position relative to consensus; its rotation decided in 0055, the unused node SVID in 0056 |
| 0044 | The operator surface — transport and access | accepted — Unix socket now, mTLS when there is a client |
| 0045 | The verdict in the chain | accepted — the `outcome` into the sealed payload |
| 0046 | The signature covers the request, not a list | accepted — scope follows the request, completeness as a test |
| 0047 | Reserved capacity — a reserve for the outage, not for the standby | accepted — reserve per node as a setting, the sufficiency as a metric; the **numbers** behind it since "A bit has no almost" |
| 0048 | The path of a warning — lints beyond `tgctl apply` | accepted — into the admin service's answer, not into the log; client including read and withdrawal path built |
| 0049 | Who reports a node's capacity — and who decides it | accepted — the node reports, a policy decides, the leader writes |
| 0050 | The identity of an operator — and who stands in the log | accepted — key against a registration; actor as an envelope around the command |
| 0051 | The original destination port — `SO_ORIGINAL_DST` in egress | accepted — port from the kernel, address discarded; substantiated on a real redirect; the own port is forcibly excluded |
| 0052 | Whiteouts on unpacking — deleted files that reappear | accepted — translation on unpacking, semantics with the kernel; marker with a version number |
| 0053 | Attestation at the handle — closing the PID reuse | accepted — `SO_PEERPIDFD`, the number is derived instead of remembered |
| 0054 | Detach and attach — a node leaves the data plane | accepted — one intent in the log, two independent convergences; substantiated at the kernel; auto-detach permanently rejected by 0057 |
| 0055 | Key rotation — as desired state, not as a shout | accepted — one generation per node and key kind, the node follows; the switch is a compare-and-set, substantiated at the kernel; the backlog is a metric; the policy decided in 0057 |
| 0056 | The node SVID without a task | accepted — the file is dropped, the SVID stays in the answer |
| 0057 | What a policy may read | accepted — present observations and the clock yes, absence no; auto-detach permanently rejected, rotation by age built |
| 0058 | What is no longer wanted | accepted — the reconciler clears away, level-triggered against the runtime's actual state; extends the list in 0010 section 3; determination 3 extended by 0062 |
| 0059 | Where the sidecar comes from | accepted — the **node** derives, co-location is a consequence; fixed paths in the container, proxy image per node |
| 0060 | The mesh redirect | accepted — destination from the kernel (`SO_ORIGINAL_DST`), exception via an **identifier of its own** for the sidecar |
| 0061 | The requirement edge at runtime | accepted — one condition per pass, against the outcome of that same pass; foreign targets are mute, `Conflicts` at ingest; the hardness of the node view made precise by 0062 |
| 0062 | What a broken entry may cost | accepted — it costs its workload, not the node; the node view isolates instead of failing, and an incomplete desired state does not clear away |
| 0063 | The declared size of a volume | accepted — it takes effect at start before the mount; no autonomous stop, shrinking never, and a failed growth does not cost the start |
| 0064 | How the active-role lease reaches the log | accepted — the **leader** grants and renews, the node learns it in the slice; renewal is on an observation, expiry is time |
| 0065 | How an attestation reaches its workload | accepted — resolved **forwards** against a handed-in mapping; `Attestation` names an identifier, not a name |
| 0066 | Where the active role is enforced | accepted — the sidecar enforces **locally**: without an active role there is no talking, in both directions |
| 0067 | The sidecar in the capacity calculation | accepted — a cluster-wide surcharge per **mesh instance**, in the log; default zero |
| 0068 | Backpressure in one direction must not halt the other | accepted — the send goes into the `select!`; the node discards a report, the server waits for room, and the order is fixed; the decoupling has had a run on **both** sides since the backpressure witness and not merely a chain read back afterwards |
| 0069 | The address plan belongs under consensus and under the node | accepted — the calculation moves to `tg-model`; `SetClusterNetwork` is checked, and where there is no subnet left, no node is admitted any more |
| 0070 | A changed declaration and a running container | accepted — it takes effect at the **next start**, and as long as it is outstanding the instance is visibly **stale**; no autonomous restart |
| 0071 | The trigger for a changed declaration | accepted — a **generation** in the log, monotonic and named by the operator; `instance` is the surge control, the execution autonomous |
| 0072 | The strictness of the session messages | accepted — an unknown field means an error; every extension is a format break and goes into a window **bundled**, and the skew is reported on both sides |
| 0073 | The endpoints of foreign workloads | accepted — the address is **observed** state: it travels upwards in the report and filtered back in the slice; assignment stays node-local |
| 0074 | What a mesh member may speak besides TCP | accepted — UDP is discarded, except to its own resolver; deny-by-default applies to the data plane and not to one protocol within it |
| 0075 | UDP outbound | **superseded by 0092** — 0075 forbade plain UDP permanently, and the measurement behind it still carries (the need was empty per protocol or had a TCP path); it was reversed not by a new need but by the **perverse incentive** the ban left behind. The counter at the discard outlives its ADR |
| 0079 | The workload API socket in the workload container | accepted — **every** container gets it: the boundary is the attestation, not the mount |
| 0076 | Fence detection does not hang on the reconcile interval | accepted — the comparison wakes lease-aware; the distance is `grace period + floor` and hangs on no setting; the ordering condition from 0064 D7 was necessary and not sufficient |
| 0077 | How the agent finds the leader | accepted — `--control-plane` and `--node-session` become repeatable; a referral moves on immediately, every other outcome after the waiting time |
| 0078 | The clock a lease holds against | accepted — **wall clock**, expressly: an absolute deadline across two machines cannot be monotonic; the ordering condition `skew < FENCE_MARGIN` is written out, an implausible lease is not believed, and the skew is made visible |
| 0080 | The readiness of a workload | accepted — an **axis of its own** beside the actual state: TCP connect on a declared port, **in the namespace** over loopback, once per pass; the effect is the resolution, and a restart stays a human's action |
| 0081 | One socket per instance | accepted — **the socket is the attestation**: one per container, mounted into exactly it; `SO_PEERPIDFD` and the cgroup read are dropped, and the kernel lower bound from 0053 falls |
| 0082 | What the release profile promises | accepted — it must promise the same as the tests: `panic = "unwind"` (a panic costs its task, not the node) and `overflow-checks = true`; the overflow check has been **substantiated cheap** since the measurement for ADR-0114 (below the spread at p99, +0.74 % binary size) |
| 0087 | The base64 reader of the credential path | accepted — the crate instead of our own hand, **strict apart from whitespace**: apart from formatting, exactly one text belongs to every value |
| 0088 | How long a time series lives | accepted — gauges expire after 15 minutes, counters do not; whoever sets rarely announces a refresh in the scrape |
| 0089 | What a requirement edge may know about readiness | accepted — it is satisfied when the target **runs**; readiness takes effect via the resolution |
| 0090 | The seccomp profile of the workloads | accepted — **denylist**: `ALLOW` as the default, a small substantiated set with `EPERM`; all the platform's ABIs, for every container, a way out only at the node |
| 0091 | The user namespace of the workloads | accepted — a **fixed mapping per node**, `chown` instead of idmapped mounts, an explicit setting with default **off**: with youki a user namespace alongside a netns given by a path is measured to be impossible |
| 0092 | Egress for QUIC and UDP | accepted — **replaces 0075**: an allowlist with a **transport**; QUIC gets the name from the packet (`ring::aead::quic`, zero new crates), plain UDP the address from the agent. **Both cuts built** (D7: QUIC first) |
| 0093 | The policy hangs on the instance, not on the sidecar | accepted — the **filter chains** lie at the connection to the network, for **every** instance; the redirect stays with the sidecar. The sidecar is the only door: whoever has none does not go out |
| 0094 | How a QUIC datagram reaches the sidecar | accepted — `redirect` **without** a port setting: the port comes from the kernel, one listener per permitted port, and the redirection follows the allowlist |
| 0095 | The data key for secrets at rest | accepted — **one cluster-wide key**, delivered on the credential path and held in `identity/`; unblocks ADR-0016 and thereby the registry credentials |
| 0096 | Registry credentials — the consumer is the agent | accepted — mapping `registry → secret` in consensus, permission at the workload; the plaintext **never** leaves the agent, and ADR-0016's question about the delivery mechanism is moot for this case |
| 0101 | The active-role lease and readiness | accepted — it stays on the **report**: the lease is a security and not an availability tool, and a role change lets the standby start up on its **own** volume (ADR-0027) |
| 0102 | The HTTP readiness probe | accepted — `<readiness path="…">` turns the connection attempt into a `GET`; ready means **`2xx`**, the status line is read and nothing else, and **one** deadline applies to the whole operation |
| 0103 | The transport of an operator | accepted — **a port of its own with a registration of its own**: checked are the SPKI against an entry in the log and the role `operator` in the certificate; the socket stays the bootstrap and the recovery path |
| 0100 | The rotation of the data key | accepted — **two keys at the same time**: one for sealing, both for opening, so that the rotation has no window; re-keying happens in the **client**, and the number of outstanding values makes it completable |
| 0099 | Snapshot and restore of a volume | accepted — a **copy of the image** with `std::fs::copy` (CoW via `copy_file_range`, zero new programs), **frozen** when mounted; snapshot as a generation in the log, restore node-local and destructive |
| 0097 | The control path of the signing group | accepted — **a port of its own with a trust list of its own**: checked is the key against `signers/<seat>.pem`, because the CA *is the group* and a check against it would be a circle; seat and Raft identifier stay independent, and the place stands in the **share** |
| 0098 | How a secret gets into a container | accepted — **a tmpfs, filled by the agent**: the mount *is* the authorization, and a foreign image reads a file instead of speaking mTLS |
| 0104 | Tombstones are instructions, not records | accepted — a tombstone lives **until it is executed**: the node reports the execution as observed state, the leader clears the instruction away; a **deadline** would be the wrong answer |
| 0105 | Authorization per command class | accepted — **five classes**, checked at the **transport** (the policy writes without an actor): the path decides, and for `Write` additionally `Command::class()`; `operators` is a class of its own, because `write` would otherwise be `admin` |
| 0106 | The DNS zone stays a setting per node | accepted — **not** into consensus: a node is consistent in itself, so a bare name resolves on every one; the skew is made visible, and what a zone leaves over is said by the start |
| 0107 | Proactive refresh of the signer shares | accepted — **DKG instead of a dealer**: no process knows all the deltas, and the way cannot shrink the group; **all five or none**, two shares at the same time, and the epoch lies beside the share instead of in the log |
| 0108 | The replacement of a signer seat (RTS) | accepted — the **lost seat** coordinates, and nobody else: measured, passed-through deltas **and** passed-through sigmas yield the share |
| 0109 | What "least occupied" means with several resources | accepted — the **pressure**: the utilization of the scarcest resource, in integers; `Resources` loses its derived `Ord` |
| 0110 | System work in the slice arm | accepted — `apply` **writes**, the reconciler **executes**: a `select!` arm does not touch the kernel, and a broken volume costs neither an active role nor the session |
| 0111 | Which instance carries the active role | accepted — **the operator says it, not the instance number**: `SetActiveInstance` in the log, default instance 0; `RevokeLease` is dropped, because it lifts the fence |
| 0112 | What it means to retire a command | accepted — remove **only** if a producer never existed; what stays becomes **inert**: `apply` refuses it, and the attempt thereby stands in the audit trail |
| 0113 | The encryption of a volume | accepted — **LUKS2 on the loop device**, passphrase per volume **derived** from the data key (HKDF), always and without a switch; rotation is a keyslot swap |
| 0114 | The tail of the data plane, measured | accepted — the measurement from 0022 is built (`cargo xtask bench`) and shows **no** tail difference between work-stealing and thread-per-core; `io_uring` is thereby rejected instead of deferred, and "pinned" becomes a setting per node with default off |
| 0115 | The permissions of the data directory | accepted — the directories are set to `0700` **expressly** instead of being left to the umask; what is sealed is the directory, not the file (the sidecar reads as 65532 from `network/`), and a MAC over the entries is **rejected**: whoever can write them is root |
| 0116 | Who restarts a dead task | accepted — **on a panic yes, on a return no**: `supervise` gets a factory instead of a handle, backoff up to a minute and **no** hard giving up; a counter carries the visibility, because the gauge now comes back |
| 0117 | The class of a placed workload | accepted — a class change is **refused at ingest** as long as the workload is placed: measured, it got through in both directions, and the cluster afterwards granted a lease that the running sidecar did not enforce |
| 0118 | What a container consumes | accepted — a **metric** per container from the cgroup (`memory.current`, `cpu.stat`), not a field in the report: that has been an expensive place since 0072, and the planner must never see the number anyway; new label `replica`, because `instance` belongs to Prometheus |
| 0119 | What remains of the bundle | accepted — the bundle is **released** where `reap` already releases network, socket and secrets: first unmount, then remove. The rationale from 0058 (the sibling instance) was measured to be moot, and the ephemeral volume thereby outlived the workload |
| 0120 | A new image reaches the rootfs | accepted — a changed declaration **remounts** and discards `upper` in the process: measured, `build` took the existing mount, so an image change reached the `config.json` and not the file system; an unchanged declaration keeps both |
| 0121 | What a QUIC flow may cost | accepted — what is bounded are **bytes, not pieces**: the datagram gets the size of the path (2048 instead of 65 535), a truncation ends the flow instead of silently passing it on, and the flow limit applies to the **sidecar** instead of to the listener; measured, the most expensive case falls from 255 MiB to 9.2 MiB; the allocation per datagram is **measured and left alone**: 23.4 ns against 3757 ns for the `recvmsg` beside it |
| 0122 | What "I do not know" about a container means | accepted — `Unknown` is **not** `Absent`: measured, the path unmounted the rootfs under a **running** container and threw its ephemeral volume away, silently and with `Ok`; from here on nothing is touched, nothing resolved and the cascade from 0061 not triggered — the precondition from 0120 is an exhaustive `match` instead of a comment |
| 0123 | The peak, and not just the moment | accepted — `memory.peak` **beside** `memory.current`: measured, the cgroup of a process that went to 200 MiB shows 0.5 MiB half a second later (factor 425), and from this number an operator sets the memory limit from 0086; the rationale for the deferral ("one more kernel lower bound") was wrong — the read is already an `Option` |
| 0124 | A star that permits nothing | accepted — wildcards are **accepted and take effect nowhere**: `permits` and `Forwarding::allows` compare exactly, so the destination is forbidden *and* the name does not resolve (two silent failures), and with `udp` a wildcard freezes the workload's entire rule set. From here on `AllowEgress` checks the name, and permitted is exactly the form from RFC 6125: a `*` as a whole leftmost label, covering exactly one label, never for `udp` |
| 0125 | Who pulls from a registry | accepted — the registry host is **lower-cased** (measured, a login failed silently on a capital letter), `registry_of` moves to `tg-model` with a differential witness against `oci_client`, and `ClearRegistryCredential` is **answered instead of refused**: the answer names who pulls anonymously from now on (ADR-0048) — the state afterwards is valid, unlike with `RemoveSecret` |
| 0126 | What the store keeps | accepted — the **oldest** open point (0003, image GC): measured, the store grows linearly and never shrinks, and half of it (`blobs/`) is never read and saves no pull. From here on the blob is **checked, not kept**; the rest is cleared away by the reconciler as the second direction of the same comparison (0058) — with three guards that cost only deferral; a pass without a find costs a measured 378 µs, so it needs no remembered position |
| 0127 | How full a node is | accepted — the **pressure** from 0109 was computed at every placement and thrown away; nobody reported the fullness, and the first signal was a failed placement. From here on `Plan` carries its occupancy out — **one** derivation, the planner's — and two metrics say *how full* and *what it is still enough for* |
| 0128 | Who notices that the other is gone | accepted — in the whole tree **one** place set a keepalive (the client in the agent), **no** server; on a resting cluster the detection time was thereby unbounded. The three network listeners get the same number from the same source, the Unix socket expressly none — and it catches the **dead** client, not the slow one |
| 0129 | What may stand before the fence | accepted — the self-fence sat **behind** the clearing away, and `FENCE_MARGIN` (3 s) only reckons with the wake-up and the fence stop: measured, **one** hanging container costs 10.16 s, sequentially. The fence moves to the front, stopping happens concurrently, the grace period stays — and a guard nails the order down |
| 0130 | A broom that sweeps only on traffic | accepted — `Flows::expire` had **one** caller, and that was `absorb`: measured, one listener held 512 flows over 100 x `IDLE`, and because the budget belongs to the whole sidecar (0121), **another** permitted port got `TooMany` for it — permanently, for the only broom sat in the loop that was precisely no longer running. From here on every listener sweeps by the clock, the cadence comes from `IDLE` |
| 0131 | Three causes, one label | accepted — `QuicError` has six distinguishable causes, `Flows::absorb` mapped **all** of them to `malformed`, and the manual read that as "no QUIC client is speaking there": measured, underneath lay a connection migration, an unread version (the number stood in the code and had no reader) and a retry before the decision. From here on the label comes from the error; **migration is permanently refused** (a short header does not name its CID length), retry carries itself, and whether anyone speaks QUIC v2 will in future be said by a number instead of a guess |
| 0132 | What the archive costs on disk | accepted — measured, 414 B per record and one lease renewal every 9.1 s per single writer: **1.34 GiB a year for one workload**, and nothing deletes it, nothing reports it. The first signal was an `apply` that could no longer write — and that stops the node. From here on two metrics (bytes and sealed segments); **nothing** is deleted, because evidence lies here that nobody has yet exported (the reversal from 0104) |
| 0133 | A trace that leaves the process | accepted — `--otlp-endpoint` killed **all three** binaries at startup (the exporter builds a hyper channel, `init` ran before `block_on`), and even repaired it would have sent nothing: in the whole tree there was **not a single span**. What is built is the one chain that neither the log nor the audit trail delivers — command → slice → pass, via a W3C `traceparent` in the slice (format break, window from 0072). The sidecar gets **no** spans and refuses the setting; sampling is thereby **rejected** instead of open |
| 0134 | The bill of materials of what is shipped | accepted — ADR-0023's first deliverable (SBOM) did not exist, and `cargo-cyclonedx`, `cargo-vet` and `cargo-auditable` are not even installed. From here on it is written from `cargo metadata` **without a second tool**, in the ecosystem's format, undated and checked in the gate against drift. Only the **normal** closure per delivery unit: 386 instead of 493. `cargo vet` is **rejected** — an attestation nobody performs looks like a statement |
| 0135 | A client that is none | accepted — the finding from 0134 was diagnosed correctly and justified wrongly: the rebuild (command set under consensus, admin protocol into `tg-admin`, seat list to identity, audit read path to telemetry) saves **one** crate. `tgctl` carries 125 of the 368, because it has two **capabilities** — reading a Raft log (61) and reconciling locally (57). The layering is right now; whether the capabilities stay is a product question |
| 0136 | Which address of an endpoint | accepted — the sidecar took `lookup_host(…).next()`, i.e. the **first**: with a dual-stack name the AAAA, and a container has no IPv6 route (0012). An endpoint with a flawless A record was thereby a **silent** egress failure, and several A records got a single attempt. From here on: all addresses in turn, IPv6 drops out **before** the attempt and is counted; QUIC takes the first usable one (a UDP `connect` does not fail visibly) |
| 0137 | Whoever owns the log reads it | accepted — **viewing** stops nothing (the archive is a file, measured with `tgd` running); only the **export** opens the Raft log, and `redb` lets exactly one process at it. It becomes a one-shot mode of `tgd`; `tgctl audit export` is dropped without replacement, and the CLI carries 307 instead of 368 crates — without `openraft` and `redb` |
| 0138 | A binary that names its build machine | accepted — the last open deliverable from 0023: measured, the release build is **not** reproducible, and it is not down to the source path, the target directory or the clock, but to `CARGO_HOME` — 2355 absolute paths of the build machine stand in the four binaries (the `file!()` locations of the `panic!` sites **of the dependencies**; our own crates contribute zero, and `strip` does not clear them away). `trim-paths` is measured to be unstabilized, so `--remap-path-prefix` in a named run (`cargo xtask release`) that counter-checks its own product; the digests are printed and **not** checked in |
| 0139 | The licence that stood nowhere | accepted — **Apache-2.0**, the second and last open point from 0134: the bill of materials listed **fifteen** components as `NOASSERTION`, and they were our own. Measured, the delivery closure is permissive throughout (no GPL/LGPL/AGPL, not even MPL), none of the 372 foreign components brings a `NOTICE` along, and the GPL programs stay processes (0003/0038/0039). `license.workspace = true` per member, the text as `LICENSE`, **no** `NOTICE` of our own (it would be an obligation we invent and pass on); what is guarded is the **artifact**, not the manifest |
| 0140 | The share that does not fit into the TPM | accepted — ADR-0014's sub-decision 2 had been a **seam** since 7b: measured, the share does not fit in (`KeyPackage` 134 B against a 128 B limit, substantiated at the TPM), so an **envelope** — 32 B sealed, the share thereby encrypted with the ChaCha20-Poly1305 from 0095 (zero new crates). `tpm2_*` as a **process** (0038/0113), primary **derived** from the owner seed instead of persisted. **No PCR policy** — the price is substantiated at the TPM (extend a PCR → the share is gone), and firmware updates come by themselves: at t = 3 a rolling fwupd hits three seats in one window, and then the CA has not failed but is gone. **No auth value**, because every source lies beside the blob (the data key is measured to be **optional**) — the argument from 0115. The rest is visibility: open at **startup**, no silent fallback, one metric with an alarm at **t + 1** |
| 0141 | The port of a mesh edge | accepted — the open point from 0025 ("identity **and** port/proto") dissolves on measuring: per target there is **one** port (`<mesh port>`, the schema allows exactly one) and **one** protocol (0074), so a port setting on the edge would have nothing to decide and would be a second source. What is measured to be missing is something else: **all** TCP is redirected, without a port filter, and the inbound sidecar connects to `upstream_port` — whoever dials `B:9999` gets `B:8080`, silently. The finding from 0051, one layer further; the existing witness `mesh_netns.rs` substantiates it without reading it. Decided: **refuse instead of redirect**, in the inbound sidecar from `SO_ORIGINAL_DST` — no field, no format break |
| 0142 | UDP in the mesh | accepted — the open point from 0074 ("UDP in the mesh (DTLS/QUIC) — option C, an ADR of its own"): **QUIC datagrams** between the sidecars. Measured, the choice is clear — `quinn` brings **11** new crates and runs on **`rustls`** (the SPIFFE verifier fits unchanged), `webrtc-dtls` **33** including a second crypto stack, and a tunnel through the TCP channel would have made something reliable out of UDP (head-of-line blocking). The budget is measured: **1162 B** before MTU discovery, ~1354 after it on the overlay, and what is too large is **refused** (`datagram too large`) instead of truncated. The edge stays `{from, to}` (0141), the UDP port stands in `<mesh udp=…>`; **one** endpoint instead of shards, because QUIC multiplexes over CIDs and not over the 4-tuple |
| 0143 | The path of a device into the container | accepted — **builds ADR-0028**, the last deferred one: measured, **youki 0.7.0 knows no CDI**, so the agent injection is not the better but the only possibility. The cut is determined by `permissions` — the specification expressly calls it *cgroup permissions*, and in cgroup v2 the controller is eBPF and thereby out per invariant 1 (ADR-0090). It therefore becomes the **file mode**; the barrier is the **presence** of the node, and it carries, because `CAP_MKNOD` is measured to be missing. `hooks`, `netDevices`, `intelRdt` and `additionalGids` cost the **whole spec** (a filtered hook would be ADR-0090 anew), `annotations` get through — they can have no effect on the container. **JSON, not YAML**: no parser in the tree, and the file determines device nodes. The inventory travels as an ordinary resource `device:<kind>` via ADR-0049 — **zero lines in the planner**, because ADR-0034/0109 made it generic |
| 0144 | The limit beside the consumption | accepted — **resolves the open point from 0123** and corrects its conjecture: the limit does not lie elsewhere but in **the same cgroup** from which the consumption is already read (`memory.max`, `cpu.max` -- two more `read`s). And there it is **something else** than in the declaration: the cgroup names what the kernel **enforces**, and between the two lie 0063 and 0070 -- a ratio from the declaration would be wrong exactly when it matters. Two numbers instead of a ratio, the CPU in **cores**; **no limit means no time series** (an infinity would become arbitrarily much room in a division). With that the **first alarm rule of this tree without a threshold**: `memory_peak >= memory_limit` means "ceiling touched", and that is a fact and not a number somebody chooses. The CPU deliberately gets none -- reaching a quota is slowness, not loss (0086) |
| 0145 | What is visible of a device | accepted — the **node side** to ADR-0143: how many devices are assigned as a number (`tg_node_devices_assigned`, the **same** `resource` label as `tg_node_free` -- a device has been a resource since 0143), **which** one an instance holds as a log line (as a label the name would be the memory leak from 0015). In addition: a device that has disappeared from the host costs the **next start** with a message that names the path -- a running instance stays untouched (0019). And the finding that for FPGA or HSM there is **nothing to build**: all witnesses have run against `example.com/probe` since 0143, so no path knows the word GPU |
| 0083 | The strictness of the admin protocol | accepted — **strict everywhere**: the envelope is as strict as its cargo, and a version skew between `tgctl` and `tgd` aborts instead of truncating |
| 0084 | A name that blocks a derivation | accepted — the node view **isolates** the mesh member instead of losing the pass, and the state machine refuses the pair at ingest |
| 0085 | The decree reaches the sidecar | accepted — the derived sidecar inherits the **generation of its principal**; without it, it stood still at every decree |
| 0086 | What the sidecar may consume | accepted — **no CFS quota** (ADR-0022's tail target), a **memory limit** from the surcharge; built, the format break goes into the window from 0072 ; the quota has been **substantiated dangerous** since the measurement for ADR-0114: a cliff, not a rise — p99.9 jumps by a factor of 70 to 120 as soon as it bites |

## Decision log (decisions taken)

| # | Decision | Choice | Short rationale |
|---|--------------|--------|----------------|
| 0002 | Language/runtime | Rust, tokio/tonic/rustls, 3 binaries | largest ecosystem, gRPC streams, OpenSSL-free |
| — | Exclusions | no Go, no K8s, no eBPF; C FFI within narrow bounds ok | GC jitter, opacity/concentration risk; FFI ≠ Go |
| 0004 | Config store role | option B: projection, not a consensus backend (for the store choice see 0030) | separates truth from a queryable view |
| 0005 | Consensus/HA | embed `openraft` | self-contained, pure Rust; no Go/K8s foreign daemon |
| 0031 | Cluster size | five nodes, quorum three, across ≥3 failure domains | with three nodes every rolling update has zero reserve; latency cost bearable through SLO decoupling |
| 0032 | Consensus implementation | `openraft` 0.9.25 (no alpha), Raft log on `redb`, our own bus for the DST | an alpha in the consensus core is not defensible; do not write the storage engine ourselves; fault injection exactly at the `RaftNetwork` level |
| 0033 | Time in the harness | a virtual global clock; election timeouts fixed instead of rolled; clock skew in the UTC of the commands | `openraft` rolls from an unseeded `thread_rng`; a real monotonic skew per node would have demanded a rebuild of the consensus core |
| 0033 | Runtime bound | `RTT(p99) < heartbeat_interval < election_timeout_min`, with a factor of 3 in both steps | `openraft` uses `heartbeat_interval` as the RPC timeout of replication — a slower path never replicates, and quietly at that |
| 0034 | Instances | `replicas` in the definition, instance number in the log command; the lease stays per workload | anti-affinity between instances is otherwise not expressible; one lease per instance would abolish single-writer |
| 0034 | Capacity | a generic resource map `name → amount` at the node, selection: least occupied, then name | the `device` type from 0028 fits without a rebuild; the rule is explainable in one sentence (no scoring) |
| 0034 | Anti-affinity | default `rack`, raisable per workload to `hall`/`site` | the smallest level with a real common outage, satisfiable in a single-hall cluster too |
| 0019 | Reliability model | static stability, SLO decoupling | decouple workload availability from the riskiest component |
| 0006 | Identity | our own SPIFFE server (a subsystem in tgd), X.509 SVID, minted locally | pure Rust instead of SPIRE; no secret in the image; hot path kept free |
| 0007 | mTLS data plane | sidecar (rustls, SPIFFE verifier), enforced locally | transparent for foreign images; userspace, no eBPF |
| 0025 | Meshing authorization | statically selective, deny-by-default, graph edges | least privilege, graph-native, locally enforceable |
| 0014 | PKI/CA | air-gapped root + threshold signing (FROST/Ed25519, DKG) | root never in the runtime; no node ever holds the full key |
| 0008 | Definition format | XML/XSD via codegen (`xsd-parser`) | compile-time type safety, pure Rust |
| 0010 | Autonomy boundary | fenced-autonomous: self-fence autonomous, activation via a quorum lease epoch | split-brain structurally out, fast failover on the majority side |
| 0004 | Desired/actual boundary | desired + consensus-critical in Raft; actual/observational eventual in the projection | read-eventual/write-linearizable; audit trail on desired |
| 0003 | OCI runtime | youki-first, crun as a fallback | pure-Rust runtime; crun (C, not Go) catches youki's gaps |
| 0009 | Dependency semantics | orthogonal axes (ordering vs. requirement separated) | avoids systemd's pitfalls; graph-native |
| 0014 | Security metrics | a tight profile: SVID 15 min, soft fail 2 min, revocation ~60 s, agent intermediate 12 h, lease 15 s | a narrower compromise window; failover latency on the lease, not on the SVID |
| 0014 | Signing group | **decoupled** from the Raft membership: fixed 5 seats, t = 3, replacement via RTS, N/t only by ceremony | `frost-core` cannot change t afterwards and cannot add participants — otherwise every membership change would be a root ceremony |
| 0014 | Custody | root in the HSM (air-gapped), runtime shares TPM-sealed | keeps the PKCS#11 FFI on the offline path; a share below the threshold is worthless |
| 0011 | Scheduler & failure domains | declarative-explicit, no auto-rebalancing; site→hall→rack→host, hard standby anti-affinity | predictable/auditable, no churn/surprise fencing |
| 0012 | Networking | kernel data path (veth/bridge/nftables), no eBPF; **kernel WireGuard full mesh** across all nodes | low latency; a uniform encrypted/node-authenticated underlay, zero trust locally too |
| 0013 | Service discovery | DNS front end, backed by the projection, health-aware | compatible with foreign images; the graph stays the source of truth |
| 0017 | Privilege & hardening | privileged agent, hardened unprivileged workloads, userns/seccomp/no-new-privs on by default | least privilege as the default; loosening explicit + audited |
| 0022 | Data plane runtime | tokio thread-per-core for the proxy; io_uring only benchmark-driven | tail gain without breaking the ecosystem, no immature runtime |
| 0016 | Secrets | a SPIFFE-native service: SVID auth, in-memory, never on disk/env | dogfoods identity + authz; keeps secrets away from disk and config store |
| 0015 | Observability | tracing→OTLP, Prometheus, probes, per node locally | standard stack, failure-decoupled |
| 0018 | API | tgctl + gRPC/tonic, secured with SPIFFE mTLS, gRPC primary | a uniform auth layer, dogfoods identity |
| 0020 | Audit | Raft log = tamper-evident WORM substrate, export before compaction | audit trail structurally, DORA/REMIT retention |
| 0023 | Supply chain | SBOM, cargo-deny, pinning/vendoring, exit strategy, reproducible | concentration risk + exit paths documented (DORA) |
| 0024 | Time source | traceable UTC (PTP/chrony), monotonic separated for leases | REMIT timestamps + robust consensus timeouts |
| 0026 | XSD supply chain | vendor `xsd-parser(-types)`, quick-xml to 0.41 | RUSTSEC-2026-0194/-0195 in the ingest path; the patch is one line per crate |
| 0027 | Storage | writable volumes exclusive + node-pinned, shared ones read-only; shared mutable state → external S3 | structurally closes storage split-brain; no storage fence needed, no network storage in the orchestrator |
| 0028 | Device access | CDI spec injected by the agent into `config.json`; a generic `device` resource type in the scheduler | vendor-neutral and Go-free; vendor vagueness stays below the CDI line |
| 0041 | Egress | deny-by-default; the sidecar reads the SNI, resolves the name **itself** and dials it; does **not** terminate in the process | an address list is right on the day it is created and not afterwards; a DNS-fed firewall puts the trust boundary in the wrong place |
| 0042 | Events node ↔ log | the announcement travels on the join/renewal path (ADR-0037), the signature covers it; deletions as a tombstone in the state and in the slice | the node identifies itself there anyway — no second auth system and no softening of ADR-0040 determination 7 |
| 0043 | Cluster transports | mTLS everywhere between the processes; checked is the **key** against a registration, not the chain against a CA; anchor locally before consensus (Raft), from the log behind it (session); three listeners | the CA hangs on the leader and the leader on the Raft port — a check against it would be a circle; a port that demands the credential admits no forgetting |
| 0044 | Operator access | admin on a Unix socket (`0700`, `SO_PEERCRED` as a counter-check), no TCP port; role `operator` and authorization per command class fixed, not built | there was no caller — a fully privileged, unauthenticated port without a client; mTLS says who calls, not what they may do |
| 0045 | Verdict in the digest | the `outcome` moves into the sealed payload of `Event`; `digest_of` stays untouched | the chain covered the attempt, not the outcome — forgeable was exactly the part for whose sake 11a archives what is rejected |
| 0046 | Scope of the signature | `renew_message` gets the **request** instead of a selection; completeness is checked by a test over its own fields | ADR-0042 enumerated and overlooked `intermediate_spki` — the enumerating is the cause, not the field |
| 0047 | Reserved capacity | a reserve per node in the same resource map, as a **setting**; whether it suffices is said by a metric per failure domain, not by the planner | the warm standby is running and already consuming its place — what is missing is room for the **outage**; a computed N+1 rule would take away the planner's one-sentence explainability (ADR-0011) |
| 0048 | Lints on the cluster path | into the **answer** of the admin service plus a standing query; not into the `Outcome` | the log preserves events (ADR-0020), a lint is a transient statement about a state — and it belongs to the set, so it does not always have a sender |
| 0049 | Capacity report | the node reports it as **observed** state; a policy of the operator turns it into the usable one, and the **leader** writes it into the log | reported is `actual`, usable is `desired` (ADR-0004) — the report reaches the planner **never**, otherwise determinism falls (ADR-0011) and the blast radius from ADR-0037 grows to "all workloads" |
| 0050 | Operator identity | an operator is a **registered key** (like a node, ADR-0043), not a certificate out of a chain; the log entry gets an **envelope** `{ actor, command }` | the uid is good for "who was it" and not for "who may"; and a field per command would be the enumeration that ADR-0046 named as the cause of the error |
| 0051 | Original destination port | `SO_ORIGINAL_DST` via the safe rustix wrapper; **only the port**, the address is discarded | the port came from the allowlist and was thereby silently **redirected**; taking the IP would be the DNS-fed firewall that ADR-0041 rejected |
| 0052 | Whiteouts | translated into overlayfs-native form on **unpacking** (character device 0:0, `trusted.overlay.opaque`), position-independent; the marker is **input** and is checked | at mount time the setting is gone; position-dependent it would be two unpackings of the same digest, i.e. the end of sharing — and `.wh...` yielded `..`, a whiteout **above** the layer |
| 0053 | Attestation | `SO_PEERPIDFD` instead of `SO_PEERCRED`: the connection carries a **handle**, the PID is derived from it at every call; without a living process no SVID | a remembered number can be reassigned by the kernel, and the window is **the lifetime of the connection** — measured, it outlives the process that established it |
| 0054 | Detach/attach | an **axis of its own** beside placeability; the peers drop the detached one, it tears down its underlay, ordinal and trust stay; **no** auto-detach | a trigger gets lost if the node does not hear it — an intent in the log does not, and with that the catch-up protocol is dropped; a timeout would turn a network wobble into a topology change |
| 0055 | Key rotation | a **generation** per node and key kind in the log, monotonic; announce first, then switch over; the identity key changes on the credential path, and the **old one vouches** for the new | a shout gets lost; the order makes the window small, and the old key is the only chain that carries without a ceremony |
| 0056 | Node SVID | the **file** is dropped, the SVID stays in the answer and in the tests | nobody reads it (ADR-0043 checks the key), and with a 15 min lifetime at a 3 h renewal it would be expired on disk 92 % of the time — a false signal where an auditor looks |
| 0060 | Mesh redirect | the sidecar takes **address and port** from `SO_ORIGINAL_DST`; the exception in the rule set stays `meta skuid`, and the sidecar container gets the identifier 65532 for it; the rule set is laid at the **start of the sidecar** | the outbound path **never** had an expected counterpart (measured: `Route.peer` carries only the SNI placeholder), so the redirect changes nothing about the authorization; and `socket cgroupv2` would be the better expression, but `nft` **prints** it and does not take it back |
| 0059 | Place of the sidecar derivation | the **node** derives from its slice; the sidecar shares its workload's namespace and address; program and file paths in the container are constants, the proxy image stays a setting per node | the inherited placement provides **no** co-location (the planner works per workload), and a leader that derived would be a policy — `UpsertWorkload` does not stand on ADR-0057's list |
| 0058 | Clearing away | the reconciler ends what the local desired state no longer names; the actual side is the runtime's **state directory**, not a memory; an **empty** desired state clears away only with an occupied marker | a drain did not drain and a withdrawal did not withdraw — `OciRuntime::kill` had no caller; and distinguishing "nothing wanted" from "nothing heard yet" is the whole security question (ADR-0019) |
| 0061 | Requirement edge at runtime | a **condition** per pass, evaluated against the outcome of that same pass; only a **failed** target pulls others down, a deferred one and a just-restarted one do not; an edge onto a workload this node does not have is **mute**; `Conflicts` is refused at ingest | `cascade_stop` had been built since phase 3 and had **no caller** — and `from_workloads` demands referential integrity, whereby an edge across the node boundary **ended the agent**; the damping needs no counter, because a crash that the same pass repairs does not count in the first place |
| 0062 | Cost of a broken entry | it costs **its workload, not the node**: no pass error ends the agent any more; the node view **isolates** (an unreadable document, a duplicate name, a self-reference, a cycle) instead of failing; isolated means neither started nor stopped; an incomplete desired state **does not clear away**; the watchdog is beaten, readiness withdrawn | measured, **one** unreadable entry ended the process — at startup and in operation —, and the exit code turned that into a crash loop; with the agent went the workload API socket (SVIDs carry 15 min), the resolver and the session: the reversal of ADR-0019 for the well-formedness of **one file** |
| 0064 | Active-role lease | the **leader** grants and renews (the same construction as the scheduler and the capacity policy), the lease travels back in the slice; without a valid lease a single writer does not start up, and on expiry it fences **autonomously** against the local clock | an agent cannot write into the log (ADR-0040 D7), and the credential path carries every three hours — a lease fifteen seconds; renewal is on a **present** observation, expiry is **time** and not silence (ADR-0057) |
| 0069 | Address plan | the pure calculation (capacity, ordinal → subnet) lies in `tg_model::network`; `tg-net` delegates, consensus checks `SetClusterNetwork` with it and bounds `AdmitNode` | consensus must not link `tg-net` and did not know the address plan **at all**: an arbitrary CIDR string was `Applied` and failed only on every node fail-soft, and `next_free_ordinal` handed out numbers for which there is no subnet -- a second copy of the arithmetic would be exactly the source of error at issue |
| 0068 | Backpressure in the session | the send stands in **every** case in a `select!` branch: the node **discards** a report the channel does not take, the server **waits** for a reservation of room, and the send branch is `biased` | an `.await` on the outbound outside the selection halted the **inbound** -- on the server side that ended in a fenced healthy single writer (full outbound → no `absorb` → no `report_seen` → no lease renewal); the report may fall because it is a snapshot, the slice may not, because only a log change produces it |
| 0070 | Changed declaration | no autonomous restart: it takes effect at the **next start** (like ADR-0063); the deviation is made **visible** per pass — a digest of the canonical declaration in the bundle, `stale` in the report, a metric per workload; the trigger stays an action | measured, a new image tag reached a running container **never** -- `step` returned immediately at `Running`, nothing compared, and the report called the instance `untouched`; an autonomous restart would make a number in the XML into an outage trigger and would, without surge and without a health gate per workload (ADR-0015 knows none), be a restart with hope |
| 0071 | Trigger for a declaration | a **generation** in the log in the form of ADR-0055, monotonic, named by the operator; `instance` is the surge control, the execution autonomous like `StopUnwanted` | without it there was **no** delivery path for a workload with a writable volume: a drain cannot move it (node-pinned, ADR-0027), and ending the container by hand leaves nothing in the audit trail -- who restarted production is the question an auditor asks; the order lies with the human, because there is no health gate per workload |
| 0072 | Strictness of the session | `deny_unknown_fields` stays — and comes onto `ControlMessage` as well; the strictness gets a guard, and an unreadable inbound message is reported with the node name | the slice is a **decree** (tombstones 0042, leases 0064, generations 0071): whoever understands it half executes it half, and that is the state an auditor cannot reconstruct; the manual claimed the opposite -- `serde(default)` covers only **one** direction --, and the question had never been decided |
| 0073 | Endpoints of foreign workloads | the node **reports** its endpoints, the leader holds them in the projection, the slice carries those this node **may dial** (edge filter, ADR-0025); health travels along, assignment stays node-local | measured, discovery ended at the node: for a workload the cluster runs, the resolver answered `NXDOMAIN` -- and nobody could name a foreign container address, while ADR-0011 distributes there with spread=rack and the underlay is built for it; a computed address would make the assignment a position (9a), and resolver-asks-resolver would be a new trust boundary with one round trip per resolution |
| 0074 | UDP in the mesh | a **filter** rule set in the namespace discards UDP in both directions, the node's own (DNS) stays excepted; only for mesh members, ICMP stays, discarded instead of refused | measured, **every** redirect rule carried `l4proto == tcp`: a mesh member talked by UDP past the certificate with every container and phoned outside without a permission -- with that ADR-0025 and ADR-0041 were without effect for a whole protocol; to *mesh* UDP is not possible with `rustls` (no DTLS) and would be a different data plane (ADR-0022) |
| 0075 | UDP outbound | **replaced by ADR-0092** — at the time: stays forbidden, **decided** instead of deferred; the discard carries a `counter`, not a Prometheus metric | ADR-0074 left the way out open and thereby created a **perverse incentive**: the only evasive move is to leave `<mesh>` out, and that switches off precisely the enforcement for whose sake the mesh exists -- measured, the need is however empty or has a TCP path (NTP is the node's business per ADR-0024, DNS goes to the excepted resolver, telemetry is OTLP/TCP, QUIC falls back to TCP); an address list would be exactly the DNS-fed firewall that ADR-0041 rejected, and silence without ICMP is the most expensive diagnosis -- so it gets a number in the rule set instead of a polling interval |
| 0076 | Fence detection | the detection latency becomes a **floor** instead of `--interval`: the comparison sleeps until the earliest fence threshold, at most one interval; the condition reads `margin < lease/2 - lease/3` and is a build assurance | measured, a healthy single writer with the **default configuration** counted as fenced two thirds of the time and flapped: the leader renews only at a remaining time of `<= lease/2` and ticks every `lease/3`, so the remaining time falls to 5 s while the distance was 10+2 s -- ADR-0064's condition `margin < lease` is necessary and not sufficient, and the test that supported it checks **one point in time** instead of a cycle |
| 0077 | Finding the leader | a **list** of endpoints per path, and a referral lets one move on -- the identifier in it stays diagnostic | ADR-0040 names as the price a gap during every election; measured it is **permanent**: the referral carries an identifier, the agent knows an address and tries it again. Two real nodes, the agent pointed at the follower: 25 s, no slice -- and with that no withdrawal reaches it any more (ADR-0025), every single writer fences (ADR-0064), tombstones stay lying (ADR-0042), and after twelve hours no SVID of the node is accepted any more (ADR-0014). The trigger is normal operation: every election, every rolling restart |
| 0082 | What the release profile promises | `panic = "unwind"` and `overflow-checks = true`; the panic strategy is guarded by the compiler, the overflow check by a test on the manifest | both settings came with the scaffolding from phase 0 and had **never been decided** — the template names "smaller binary" as the rationale. Measured, `dev` catches a panic in a task (`JoinError::is_panic()`, the process lives) and `release` does not (the process dies); and `1000u64 - 2000u64` yields 18446744073709550616 as shipped. Six handling paths were thereby dead code, and **two comments claimed the property in writing** — one of them names ADR-0019. Per package `panic` is not settable (measured), so the binary with the strictest requirement determines it: `tg-proxy` runs four shards so that a part may fail (ADR-0022). Cost: +12.4 % binary size |
| 0087 | base64 in the credential path | the crate `base64` (`STANDARD`, with padding); before decoding, **whitespace** is removed, nothing else | the hand-written reader sat at the **least authenticated** boundary of this system -- the credential port demands no client certificate (ADR-0043 D3) --, and its rationale ("the alphabet is shorter than the dependency") was measured to be moot: `tg-net` uses the crate for the same task, so it lies in the tree anyway. Measured, it was **not injective**: `QUJD`, `QUJD=`, `QUJ` and `QU JD` yielded the same bytes -- not exploitable today (the checks compare bytes), but the trap for the next person who builds a check on the **text**. The tolerance has no user today (`NodeTrust::from_base64` reads the **log**, not an operator's hand -- the first draft claimed the opposite and was corrected before acceptance); whitespace nevertheless stays permitted, because it is formatting and costs nothing. The encoder's output is byte for byte the same |
| 0088 | Lifetime of a time series | `idle_timeout(MetricKindMask::GAUGE, 15 min)`; every gauge has a known cadence, and whoever does not have one registers a refresh (`Health::on_scrape`) | ADR-0015 names **cardinality** as an open point, and 11b answered it; the second half of the same question was never asked. Measured, a series lives **forever**: after `tgctl cluster remove api`, `tg_workload_ready{workload="api"} 0` stays until the process ends, and `TardigradeSingleWriterWithoutActiveRole` (`critical`) thereby fires permanently for a workload an operator deliberately withdrew -- the alarm could only be silenced with a restart. An alarm rule one can no longer silence is one that gets switched off. Expiry for **everything** is rejected: a counter that disappears and comes back reads for `rate()` like a reset. Four gauges are set too rarely for that (`tg_task_alive` exactly **twice** in a process's life) -- they announce their refresh in the scrape, in the same place and with the same rationale as `sample_process`: there no intermediate state arises that could go stale |
| 0089 | Readiness and the requirement edge | a `requires`/`bindsTo` edge is satisfied when the target **runs**; readiness takes effect via the **resolution** (ADR-0013), not via the gate; `Inactivity` stays at two values, and the probe runs behind the gate | ADR-0080 left the question open, and it has been the same since phase 3: healthy meant *the container is running*. Measured, three things speak against the gate. **Structure:** the gate evaluates against the outcome of the same pass (ADR-0061 D2), the probe runs behind the `start_order` loop -- because an instance this pass starts cannot answer beforehand; a gate with readiness would get the state of the **previous** pass, i.e. edge-driven on stale state. **Blast radius:** a misjudgement by the probe would cost a **second** workload, and a mistyped port in `<readiness>` would be one line of XML that halts a whole chain -- ADR-0080 deliberately built the probe with few consequences. **Granularity:** readiness already takes effect, and correctly -- `health_of` takes an unready instance out of the resolution, a dependant gets `NODATA` with one second of negative deadline (phase 9a) and retries at the individual **connection**. A fourth edge kind is rejected: it would duplicate the requirement axis that ADR-0009 deliberately kept narrow |
| 0057 | Boundary of a policy | it may read only inputs that an **outage does not produce** — observation and clock yes, **absence** no; permitted are exactly `UpsertNode` and `SetKeyGeneration` | auto-detach would make the partition, against which ADR-0019 protects the workloads, itself the trigger of a topology change; a calendar does not fail, so rotation by age is the same construction as ADR-0049 |
| 0065 | Attestation → workload | the node **hands in** the mapping container identifier → workload; `Attestation::workload()` is dropped, a refusal names the identifier | since ADR-0034 the identifier carries the instance number — read backwards, **no second instance** got an SVID, and `tg-api-3` is indistinguishable from instance 0 of a workload `api-3` |
| 0067 | Sidecar capacity | a cluster-wide surcharge per mesh instance (`SetSidecarOverhead`), added by the planner to the demand; default zero | the planner does **not see** the sidecar at all — it arises on the node (ADR-0059) and stands in no log; the consequence goes in the dangerous direction: overpacked nodes, a too optimistic reserve (ADR-0047) and a metric that reports more room than there is |
| 0066 | Enforcement of the active role | the sidecar refuses mesh traffic as long as its workload does not hold the lease; being affected is a setting (`--single-writer`), not in the file | the sidecar sits on the **same machine** and has the same clock — for a detached, **honest** node no propagation is needed; an epoch on the wire would be a sixth format change, one in the SVID twenty times as much minting work |
| 0063 | Size of a volume | it takes effect at the **start** of an instance, before the mount; no autonomous stop, shrinking refused and reported, a failed growth does not cost the start | measured, after creation it was **ornament** — `declare` discarded the declared size, and `resize` had no caller; halting a running container for it would make a number in the XML into a restart trigger (ADR-0010) |
| 0040 | Control plane → node | a bidirectional gRPC stream to the leader, established by the node; a slice per node from the SVID; actual back, but not into the log | three building sites with one cause; the stream is a refresh of the local cache, not a dependency (ADR-0019) |
| 0039 | WireGuard underlay | `netlink-packet-wireguard` on the existing stack; X25519 generated locally; `AnnounceUnderlay` in the log, `AllowedIPs` computed from the ordinal | here there is a licence-clean netlink way, unlike with nftables; two sources for the same fact would be two opportunities to diverge |
| 0038 | nftables binding | `nft` as its own process, JSON over `nft -j -f -`; no netlink binding | every netlink way is copyleft — `rustables` GPL-3, `libnftnl` GPL-2; the FFI way would be **invisible** to `cargo deny` |
| 0030 | Projection | in-process instead of SurrealDB: a graph from `tg-model`, state in memory, watches over gRPC streams | 292 of 566 crates are dropped; no BSL; ADR-0004's "throwaway projection" becomes literally true |
| 0109 | "Least occupied" | the **pressure** — per resource `occupied / capacity`, and the **maximum** applies; in integers (millionths, `u128`), computed over the **capacity**; `Resources` no longer derives `Ord` | ADR-0034 says "least occupied" and with a resource **map** that is not a statement — the gap was filled by a derived `Ord` that compares **lexicographically**, i.e. first the alphabetically first resource **name**. Measured on real `Resources`: a node with a **million occupied millicores** counted as emptier than one with **five bytes** of memory (`cpu-millicores` stands before `memory-bytes`, and the key comparison comes before the value), and a node with 9 GB occupied won against one with 200 millicores. It is reachable, not constructed: the schema gives `<cpu>` and `<memory>` each `minOccurs="0"`. A sum would not be a number (millicores plus bytes), a weighting exactly the scoring ADR-0011 excludes, and the number of instances would ignore the sizes. The pressure is a sentence without parameters and carries a `device` type from ADR-0028 without anyone extending a list |
| 0110 | System work in the slice arm | `apply` writes both lists as a file, the **reconciler** executes; a failure no longer ends anything | ADR-0068 set up the rule for this loop — backpressure in one direction must not halt the other — and it applied to the **send**; blocking work *within* an arm was never considered. Measured, it halts the neighbouring arm for exactly its duration (a 50 ms ticker, a 1000 ms blockage: gap 1000 ms), and `apply` carries up to **60 s per volume** (`TOOL_TIMEOUT`, in a loop) — after that the node drops out of `reporting` after 15 s, the leader skips the renewal (ADR-0064), and after a further 15 s every single writer fences itself: a **healthy** node loses its active roles because it copied a volume. The second finding is sharper: `apply` propagates with `?`, so **a failed `losetup` ends the session** and sends the agent to a different endpoint (ADR-0077) — literally ADR-0062 one layer further. Both executions are level-triggered (ADR-0104, ADR-0099) and can therefore be deferred without loss; the reconciler is the strand that **may** block (watchdog, ADR-0082). Lowering `TOOL_TIMEOUT` is rejected: the minute is measured and substantiated |
| 0111 | Active instance | a **declared fact in the log** (`SetActiveInstance`, default 0), from whose placement the leader derives the holder; **no policy** may set it; `RevokeLease` is struck | ADR-0064 determination 8 ("only instance 0") stood as a constant in **three** places in the code and nowhere in the state — with that there was no lever for "arm a replica", although ADR-0027 prescribes exactly that as the HA path (volume migration is excluded). Measured, the state machine can do the promotion long since — `grant_lease` does not ask about the instance —, it only does not **hold**: the scheduler derives the holder from the placement of instance 0 and takes the role back after a deadline (t=31000: `GrantLease` to the old node). The obvious way would have been `RevokeLease` — measured, that lifts the **fence**: after the revocation a grant to another node *within* the old deadline is accepted (`LeaseGranted`), while the old holder carries on against its local clock (ADR-0078). It has no producer, so no log can contain it, and the retention objection from ADR-0020 is empty. An automatism is rejected: the input would be an **absence** (ADR-0057) and auto-rebalancing through the back door (ADR-0011) |
| 0112 | Retiring a command | two rules: a variant may be **removed** exactly when it never had a producer (measured from the **history**, not from the tree); what stays is **readable and without effect** — `apply` refuses it, unconditionally. `Command::retired()` is the one source, and the guard from 0111 derives its exceptions from it | three times a command lost its caller, three times it was treated differently: `ClearPlacement` stays and executes, `RegisterTrust` likewise, `RevokeLease` was removed (0111) -- the shape of ADR-0057. Measured against the **history**, exactly one ever had a producer: `RegisterTrust` in `tgd/src/identity.rs` (`07e4304`..`351bc87`, replaced by `RotateTrust`). With that the deletion from 0111 is substantiated in retrospect and `RegisterTrust` really unremovable. The sharper finding is what it can still **do**: ADR-0055 removed the producer and named the danger, the capability stayed -- whoever reaches the admin service with `write` enters node trust without an invitation, past the gate from ADR-0037. Refusing at the **access** is rejected: then the attempt never reaches the log and leaves no audit entry (11a). At the **actor** likewise: that would make provenance part of the decision (ADR-0050/0105). Price: a log from that window replicates differently, and that belongs in the same coordinated window as a format change |
| 0113 | Volume at rest | **LUKS2**, passphrase `HKDF(DataKey, "tardigrade:volume:v1:" + name)` — one custody model, one backup obligation, domain separation nevertheless; over **stdin**, never argv; the derivation lies with the **agent**; every new writable volume, without a switch; existing plaintext volumes stay and are made **visible** | ADR-0027 demands it and carries the custody question as an open point of its own; built was only the **seam** (`volume.rs`: "a LUKS container lies exactly where the naked file system lies today"). ADR-0095 resolved the blocker and names this goal in its own consequences. Taking the data key **directly** as the passphrase is rejected (the pitfall from 9d: the same key in two uses), a **second** cluster-wide key likewise (a second backup asset is one somebody forgets). A switch in the declaration would mean that unencrypted is selectable and the failure **silent** — the construction of ADR-0017 and ADR-0090. Silent conversion of existing volumes is rejected: a data migration without a way back, precisely where an outage is most expensive; the way is snapshot/restore (ADR-0099). Rotation costs a keyslot swap instead of a copy and fits ADR-0100's two-key window. Price: `cryptsetup` as an operational prerequisite, the **first** start of a stateful workload hangs on the credential path, and the loss of the data key costs from here on **data** and not only secrets |
| 0102 | HTTP readiness probe | `<readiness path="…">` in the **declaration** (not a switch per node); the status line is read and at most 64 bytes; ready means `2xx`, `3xx` does not; **one** deadline for connecting, sending and reading together | ADR-0080 deferred it with **one** argument: an HTTP probe would need a TLS decision, and that hangs on `<mesh>`. Measured, that is moot — the probe runs **in the namespace** over loopback and reaches the workload **in the clear**, because `prerouting` does not fire on loopback (the same kernel property on which the sidecar's path to its workload rests, ADR-0059). What was missing is the thing a connect **cannot** see: a process that binds and does not answer — the normal case of a workload that loads something at startup. A switch per node is rejected (the same definition would yield two probes on two nodes); following `3xx` likewise, for then the probe would be an HTTP client with a trust boundary of its own. The 64 bytes are the boundary to a container: whoever quoted the whole answer would let the sender determine the length of our log line (the finding out of which `tg-wire` arose) |
| 0103 | Transport of an operator | a port of its own (`--operator-listen`, optional) with mTLS; checked are the **SPKI** against `EnrolOperator` in the log and the **role** `operator` in the certificate; registration goes over the Unix socket, the actor arises in the service; authorization per command class stays unbuilt | ADR-0050 decided the identity and separated its implementation: **authorization only bites on a transport that authenticates** -- and there was none. Measured, `EnrolOperator` and `Role::Operator` occur **zero** times in the whole tree, and `Actor::Operator` is never produced. What that costs is not the authorization but the **reach**: `tgctl` reaches its node, so every command needs a shell on exactly the machine on which the leader currently runs. A check against the CA (ADR-0018's intent) is rejected -- it would be the circle ADR-0043 avoided, and since ADR-0097 the CA hangs on a group with a threshold; a bearer token would be a secret with a retention period (ADR-0020) and replayable; sharing the list of nodes would let a compromised **node** administer and would widen the blast radius from ADR-0037 to "may do anything" |
| 0080 | Readiness per workload | an **axis of its own** (not a fifth `ActualStatus`), TCP connect on `<readiness port>`, **in the namespace** over loopback, once per reconcile pass without a counter; without a declared probe, ready applies; the effect is solely the resolution | ADR-0015 decided probes per workload and never built them — measured, healthy simply meant *the container is running*, and three consumers concluded too much from that (the resolver offered a mute endpoint, a `requires` edge counted as satisfied, a standby did not take over). From outside, the probe cannot measure: after the redirect (ADR-0060) it lands at the sidecar, and that one refuses without an active role (ADR-0066); in the namespace it works, because `prerouting` does **not** fire on loopback (measured — the sidecar's path to its workload also rests on that). A restart on a failed probe is rejected: the input is an **absence**, an overloaded workload does not answer, and a restart would make the overload worse — the trigger exists anyway (ADR-0071), and then the audit trail says **who** it was |
| 0081 | Attestation at the socket | one socket per instance (`<data-dir>/sockets/<container-id>.sock`) in a `0700` directory, mounted into exactly its container; the connection carries the identifier, `SO_PEERPIDFD` and the cgroup read are dropped; the socket arises before the bundle and dies with the instance | ADR-0053 itself calls it the better answer and says why it was not possible then — the mount path was missing; since ADR-0079 it exists. Today's way costs **kernel >= 6.5** as an operational prerequisite, and below that **no workload gets an SVID** — the default kernels of widespread long-term distributions lie below it. Measured, the new construction carries: a socket in a `0700` directory is reachable over the bind mount and not over the host path (`Permission denied` as an unprivileged user), and another container does not have the path in its mount namespace. The price is named: security moves from a kernel property to a property of our code — bearable, because mount and container identifier arise from **one** derivation, and substantiated with a witness. `root` on the node can thereby fetch an SVID; it reads the intermediate from disk anyway (the same argument as ADR-0044) |
| 0078 | Clock of the lease | wall clock, expressly; ordering condition `skew < FENCE_MARGIN`; a lease that reaches further than `2 x LEASE` is not honoured; the skew as a metric | ADR-0024 demands a **monotonic** clock for leases -- measured, the active-role lease runs on the wall clock, and monotonic is not buildable: an `Instant` has no common zero point, and a deadline shared by two machines must be absolute (ADR-0064). With that the security statement rested on an assumption noted nowhere: if the node's clock lies more than the safety margin behind the leader's, it holds the role while the leader passes it on -- **two writers**, exactly what the lease is meant to prevent. A relative duration would move the clock to the right place and break the chain (the leader does not know when the node began counting) |
| 0079 | Socket in the container | every workload container gets the workload API socket, writable; the agent hands in the path | ADR-0035 built the standardized surface so that the ecosystem's client libraries speak it -- measured, the sidecar is the **only** one that reaches it, because the mount arose in the `principal.is_some()` branch. `<mesh>` does not help: it identifies the sidecar, not the workload. The restriction was decided nowhere. An opt-in buys nothing, for the SVID a container can fetch is **its own** (ADR-0053/0065), and the ways out stay at the rule set (ADR-0060/0074) and at the target sidecar (ADR-0025) |
| 0104 | Lifetime of a tombstone | **until executed**, no deadline: the node reports the execution (observed state), the leader writes `RetireTombstone` -- the same construction as ADR-0049 and ADR-0064; `RemoveNode` takes its node's tombstones along | ADR-0042 built the tombstone and coupled its lifetime to ADR-0020 -- **measured, that is the wrong coupling**: the record is the `DeleteVolume` entry in the log and stays anyway; in the state lies the not yet executed **instruction**. Measured, it disappears only when the same volume is declared again -- the normal case leaves it **forever**, in every snapshot and in every slice. A **deadline** would be actively harmful: it would leave the data lying on a node that was away for a week while the cluster considers it deleted -- the reversal of the promise from ADR-0027, and silently. The same shape with the snapshots: `--keep-snapshots` bounds the **number**, and an age limit would delete there the oldest restore point an operator deliberately kept -- there too the deadline is not the open question but a wrong one |
| 0083 | Strictness of the admin protocol | every serialized type carries `deny_unknown_fields`, the empty requests too; answers likewise | ADR-0072 decided the rule and named its scope **by name** -- the admin service did not appear in it. Measured, exactly **one** of eleven types carried the attribute (`LintsResponse`), while the payload within it (`Command`, `Submission`) is strict: strict the cargo, lenient the envelope. The case is `MembershipChange` -- a field that an old `tgd` discards means, with `blocking`, promoting a learner that knows nothing yet. The asymmetric solution (requests strict, answers lenient) is rejected: a `tgctl` that silently truncates an answer gives an incomplete picture in the recovery case -- and precisely then an operator can check it least |
| 0084 | Blocked sidecar derivation | `reconcile::expand` isolates the mesh member (ADR-0062) instead of failing; `validate_names` checks the set at ingest and in the client | measured against a real `tg-agent` with `api` (mesh), `api-proxy` and an uninvolved `harmlos`: **none** of the three was reconciled, and that anew every second -- nothing started, nothing restarted, nothing cleared away, no single writer fenced (ADR-0064). Three lines above the place stands the comment that names the rule for the neighbouring case (ADR-0062), and the documentation of `once` says the same. What is isolated is the mesh member and not the declared workload: its definition is complete in itself -- no guessing as with the duplicate name. The refusal is `UnplaceableDefinition`, the variant that already carries this class; a new one would be a format break for the same statement |
| 0085 | Restart of the sidecar | the reconciler reads the generation under the name of the **principal** | measured, `generation("api-proxy", 0)` returned **zero** while `api` stood at 7: the generations stem from `slice.instances` (ADR-0040), and a derived sidecar stands in no log (ADR-0059). `tgctl cluster restart api` thereby restarted `api` and left `api-proxy` standing. Heaviest weighs a change of **class**: the workload then runs as a single writer, and its sidecar does not rein it in (ADR-0066), because it lacks `--single-writer` -- and nobody sees it. A trigger of its own from the staleness (ADR-0070) would be an **autonomous** restart and is rejected |
| 0086 | Limits of the sidecar | no CFS quota; a memory limit from the surcharge (ADR-0067), built with the bundled format change | ADR-0067 **booked** the sidecar and said nothing about enforcement. Measured, `mesh::build` produces no `<resources>`, so its `config.json` carries no `linux.resources` -- while a declared workload gets a CFS quota and a memory limit. The workload is bounded, its sidecar is not. A quota would be exactly the price that ADR-0022's tail target must not pay and whose benchmark is missing; a missing **memory limit**, by contrast, hits the keystone -- a sidecar under the OOM killer takes all the node's workloads with it (ADR-0019). The source is the surcharge and not a second setting; it stands in consensus and not in the slice, so the build waits for the window from ADR-0072 |

**All core decisions taken.** What remains are only phase-coupled implementation
details, no architecture blockers: the XSD subset (0008, in phase 1, done) as
well as various "start values/details" points in the individual ADRs.

**The metrics from ADR-0014 stand** — SVID TTL 15 min, soft fail 2 min,
revocation ~60 s, agent intermediate 12 h, lease 15 s, signing group 5 seats
with t = 3. Open is no longer their choice but their **substantiation**: soft
fail and agent intermediate are to be checked against a CP recovery statistic
that exists only once the cluster runs.

## Dependencies between the core decisions

```
0002 (Rust/tokio)
  ├─> 0003 (youki/OCI) ──> 0008 (XSD → config.json)
  ├─> 0005 (consensus/HA) <──> 0004 (desired vs actual) ──> 0030 (projection)
  │        └─> 0010 (reconciler) ─> 0011 (scheduler)
  └─> 0007 (mTLS) <── 0006 (SPIFFE) ── 0014 (PKI/CA)
0008 (XSD) ──> 0004 (schema) ──> 0009 (dependency graph) ──> 0010
0007 (sidecar) ──> 0009 (BindsTo/After coupling)
0003 (content store) ──> 0027 (volumes) ──> 0011 (node pinning)
0027 (at-rest encryption) <── 0014/0016 (key custody)
0004 (projection) ──> 0030 (in-process) ──> 0018 (gRPC as the read path)
0003 (config.json) ──> 0028 (CDI injection) ──> 0011 (device resource type)
```

## Status: architecture decisions concluded

All architecture ADRs are `accepted` — **every single one** since 2026-09-07
(0029 and 0075 `superseded`). ADR-0014 has been complete since 2026-08-21,
ADR-0033 since 2026-09-07: it stood for over a year on `proposed` with the note
"time values in phase 5c", while its timing profile was the default, its
ordering condition aborts the start and an alarm rule watches it. Open there is
not the decision but **one number per installation** (`RTT(p99)`). **ADR-0042**
is the youngest and came afterwards: it arose while wiring the last gaps from
phases 9 and 10, not beforehand — the slice from ADR-0040 carries a snapshot and
not an **event**, and precisely that is what the underlay announcement and the
volume deletion need. It changes ADR-0037 (the signature now covers more than the
nonce) and is thereby not merely additive.

**ADR-0043** is the youngest. Like 0042 it came afterwards, but for a different
reason: not because a capability was missing, but because four open points from
four phases had the same cause — no transport between this cluster's processes
authenticated its counterpart. It is additive to 0037 and redeems ADR-0040
determination 8. It brings two corrections along: the mitigation on which the
Raft port relied did not exist (the underlay carries container traffic, not the
management ports), and the node name has been a SPIFFE identifier since 0036 —
whereby the default value `HOSTNAME` was unusable on every FQDN machine.

**ADR-0044** closes the exception 0043 had named. It is the first in which a
**finding shifted the question**: sought was "how does one authenticate
operators", measured it was "there is no caller" — `AdminClient` occurred in
`crates/*/src` exactly once, in its own definition. With that the situation was
not an auth problem but a fully privileged, unauthenticated port without a
client, and the cheapest solution the right one: no port. What ADR-0018 later
needs — the role `operator`, authorization per command class — is fixed there and
expressly not built; **both have since been decided and built** (ADR-0103 for the
transport, ADR-0105 for the classes).

**ADR-0045** is the second after 0044 in which a **finding poses the question**
instead of a capability being missing: while building `tgctl audit` it was looked
up what the sealing from 11a covers — and the state machine's verdict lay beside
it, not within it. It corrects the implementation of 11a, not ADR-0020: that
one's promise "tamper-evident" is only thereby fully redeemed. The cut stays
small, because the verdict moves into the **payload** and not into `digest_of` —
the DST evidence from 11c is thereby unaffected. Its costs stand in the ADR:
archives of the old form are no longer read.

**ADR-0046** is the youngest and the answer to the question 0045 left behind: do
**further** fields lie beside a digest and claim something? Asked systematically
it had two answers — `intermediate_spki` in the renewal request and the verdict
of the DST report. The ADR concerns the first, and it does not add the field
afterwards but closes the trap: ADR-0042 had **enumerated** the scope of the
signature and in doing so left out a field that was already there. The scope now
follows the request, and the completeness is a test over its own fields — whoever
adds one and does not touch the function makes it red. The finding was not
exploitable (the transport covers it, measured), and the ADR says that instead of
leaving it out: the property afterwards no longer hangs on an assumption nobody
had noted.

**ADR-0047 and ADR-0048** are the youngest, and both belong to the sort ADR-0044
began: **a finding shifts the question.**

With **0047** the open point from ADR-0011 read "reserved capacity for warm
standbys" — and measured, exactly that is long since there: a warm standby is a
**running** instance (ADR-0010 itself names the doubled resources as a cost), it
is placed, it consumes its place. What is missing is room for the **outage**: if a
domain fails, the planner carries its instances elsewhere, and whether there is
room there nobody checks beforehand — the message `NoRoom` comes at the moment of
the outage, i.e. when it is of no use any more. Decided is a reserve per node as a
setting; the question "does it suffice?" is answered by a metric and not by the
planner, for a metric may compute what a planner should not: it decides nothing,
it shows.

With **0048** it was the second finding of the same sort as in 0044: the linter
warning from ADR-0009 has since phase 3 reached only `tgctl apply`, the
node-local path — and a client that writes workloads into the **cluster** does not
exist at all (the only `UpsertWorkload` in production code stands in a
`#[cfg(test)]` module). Fixed is the form: the answer of the admin service, plus a
standing query — for a lint belongs to the set and does not always have a sender.
It will be built with the first client. What applies immediately is the one
source: new lints belong in `DependencyGraph::lints()` and nowhere else.

**ADR-0049** is the youngest and closes the last point of the list below. It arose
from a question asked in conversation — can the node not report and the operator
decide? — and the answer is yes, with one boundary: **the report reaches the
planner never.** Otherwise the determinism from ADR-0011 falls (an eventual
projection as a planner input), and the blast radius from ADR-0037 grows from "one
node onto which nothing is placed" to "all workloads". Out of report and policy
the **leader** therefore makes an ordinary `UpsertNode` — the same construction as
the scheduler with `AssignPlacement`, and thereby no break of ADR-0040
determination 7. A share per node is rejected: it would make the report
indirectly binding.

**ADR-0050** is the youngest and closes the last decided, unbuilt point — with a
separation that became apparent only while cutting the build and was added
**before** the build: authorization only bites on a transport that authenticates,
and there is none. A registration including classes would thereby have been a
mechanism without a caller — exactly the error ADR-0044 named. What is built is
therefore the **attribution**: the log entry carries an envelope with the actor,
and because the archive has sealed the whole payload since ADR-0045, an auditor
reads "who" from here on without anything having been changed at the archive.

**ADR-0051** is the youngest, and its finding was sharper than the note that
triggered it. Open stood "several ports per name are ambiguous"; measured, the
situation was **redirecting**: with exactly one listed port that one was taken,
regardless of what the container had chosen. Whoever dialled `:8443` while `:443`
was permitted got silently a connection they had not demanded — and because the
sidecar does not terminate, at most the endpoint noticed. The port now comes from
the kernel; the **address** is discarded, for taking it would be the DNS-fed
firewall that ADR-0041 rejected. And the objection "that needs `unsafe`", which
kept the point open, was moot: `rustix` has a safe wrapper.

**ADR-0052** is the youngest, and it belongs to the sort ADR-0044 began — only
here the finding did not shift the question but its **scope**. Open stood a note
from phase 10c: whiteouts would not be evaluated in shared volumes, without
consequence for reference data, and what was to be decided was whether to refuse
multi-layer sources. Measured, `Content::unpack_layer` serves the volumes **and**
the container images — exactly 10c's point, one store and one mechanism — and both
mount `lowerdir=`. So it concerned **every multi-layer image since phase 2**, and
refusing was not a choice. Decided is the translation on **unpacking**: the
semantics stay with the kernel (ADR-0003), `bundle.rs` and `volume.rs` stay
untouched, and safe `rustix` wrappers uphold invariant 2. While building, a second
finding came along that weighs more heavily: the marker name stems from a foreign
tar, and `.wh...` yields after the prefix `..` — a whiteout **above** the layer
directory, on whose path a `remove_dir_all` lay. It stands as a determination in
the ADR and not merely in the code.

**ADR-0053** is the youngest, and it is this session's clearest case of "the
finding is larger than its note". Open stood since phase 7c a subordinate clause:
the attestation reads `/proc/<pid>/cgroup` via the PID from `SO_PEERCRED`, and
between the two the process could have died and the PID been reassigned. That
reads like a race over microseconds. **Measured it is none:** the credentials
arise at the `accept`, `/proc` is read per call, and the connection **outlives the
process that established it** — a connector that forks and dies leaves it to its
child. The window is thereby the lifetime of the connection, and an attacker
chooses it: connect, fork, let it die, wait until the PID is reassigned to a
container process, then ask. Decided is therefore a **handle** instead of a number
(`SO_PEERPIDFD`, Linux 6.5): as long as it is open, the kernel cannot reassign the
PID, and if the requester has gone, there is no identity. The price stands in the
ADR instead of being left out — a kernel lower bound that applies to the
**identity path** and not to the node (the admin socket authorizes via the uid and
stays the recovery path). And the better answer is named: one socket per instance,
mounted into its container, would make the question moot — it waits for the mount
path from 9d.

**ADR-0054** is the youngest, and it is the first that arose from a **question
back** instead of from a finding: the key rotation was to be triggered over the
control plane — but how does one then operate reconciliation when a node drops out
of the group? The answer is that the question **falls away**. A trigger gets lost
if the node does not hear it, and then one needs the catch-up protocol; an
**intent in the log** does not get lost — whoever was away reads it on return. The
same step as with the deletion in ADR-0042 (a tombstone instead of an absence).

Decided is an **axis of its own** beside placeability: "not in the mesh" is a
different question from "may something be placed here", and blocked with a full
mesh is the normal case before an update. Two convergences without an order — the
others drop the detached one without its participation; it tears down its underlay
when it sees it. Ordinal and trust stay, so that it can come back by itself;
whoever wants the key dead takes `RevokeTrust`. And **no auto-detach**: no timeout
turns an observation into an intent, otherwise a network wobble becomes a topology
change.

The ADR has a precondition that was fulfilled only shortly before: the content of
"detached" is **not being in the data plane** — and that did not exist as long as
`wireguard::configure` had no caller. A detach before that would have been a state
that nothing applies, i.e. the error ADR-0044 named.

**ADR-0055** is the youngest and closes two identically worded open points — the
one from ADR-0039 and the one from ADR-0043. Measured, the situation was sharper
than both notes: **neither** of a node's two keys had a replacement path; both are
read when the file is there, and generated only when it is missing.

Decided is a **generation** per node and key kind in the log, monotonic, with the
comparison at the node — the same form as detach (ADR-0054) and the tombstone
(ADR-0042), and for the same reason: a shout gets lost if the node does not hear
it. The order is the actual work — announce first, then switch over —, and it
needs no trigger of its own: after generating, log and announcement diverge, and
the comparison from ADR-0042 wakes the renewer. The identity key changes on the
credential path, where the **old one vouches for the new**; that is a consequence
of ADR-0046, for the signature covers the request and thereby the new field
without any action.

Detach is expressly **not** a precondition, even though it was first presented
that way in conversation: it includes emptying out, and emptying a node for a key
change would be a sledgehammer.

**ADR-0056** is the youngest and the smallest, and it belongs to the sort ADR-0044
began: sought was "does the node SVID have a task", measured it was **worse than
useless**. It carries 15 minutes (ADR-0014) and is renewed every three hours — on
disk it is thereby **expired** 92 % of the time, and an expired certificate in the
data directory of a regulated system is what an auditor reads as a finding.

That it has no consumer is thereby **right** and not forgotten: ADR-0043 checks on
the cluster transports the key against a registration, and giving it a task there
would mean making a consensus recovery dependent on the CA — the circle that ADR
avoided. Decided is therefore: the **file** is dropped, the SVID stays in the
answer. It was not taken out of the protocol, and not out of caution: the field is
the only place at which the issuance of a node leaf is checked at all.

**ADR-0057** is the youngest, and it is the first to answer a question that had
been deferred **three times**: may a program issue a decree that otherwise a human
takes? ADR-0049 answered it for the capacity with yes, ADR-0054 (determination 3)
and ADR-0055 (determination 6) each left it open once — three times the same
question, three times no rule.

The rule reads: **a policy may read only inputs that an outage does not produce.**
Present observations and the clock yes, **absence** no. With that the three cases
fall apart without having to weigh them individually: a capacity report is there
or not there and is read only when it is there; a calendar does not fail; a
**silence**, however, is exactly what an outage produces.

Auto-detach is therefore **permanently rejected** and not deferred again: it would
make the partition, against which ADR-0019 protects the workloads, itself the
trigger of a topology change — the minority side would detach itself while its
containers run. The substitute is **visibility**: the silence becomes a metric, and
detaching is done by a human.

While building, the exhaustive `match` made the permission list even narrower than
the draft had it, and two prohibitions were added **before** acceptance: a policy
changes **no policy** (otherwise it extends its own authority), and it may not
block or detach. With that determination 3 is not merely a rule about the input
but **structurally** enforced — auto-detach cannot be built without touching this
list.

**ADR-0058** is the youngest, and it is the third case of the sort ADR-0044 began
— only the finding here does not point at a missing capability but at a **missing
half**. The node reconciler brings to life what the desired state names; what it
does **not** name it left alone, even if it was running. Measured that means:
`tgctl cluster remove` does not withdraw, a drain does not drain, and `replicas`
downwards leaves the surplus instances standing — with an address, a volume and an
entry in DNS. `OciRuntime::kill` had in production code not a single caller.

Decided is the clearing away as a **second direction of the same level-triggered
comparison**: the actual side delivers the runtime's state directory (measured,
because `youki list -q` prints a table and `crun list -q` does not — a parser would
be runtime-specific, and ADR-0003 foresees the switch). The actual security
question is the third determination: an **empty** desired state clears away only
when it is occupied — otherwise a lost data directory would cost every running
container (ADR-0019). And the list from ADR-0010 section 3 gets a fourth
autonomous entry, with the same rationale as `SelfFence`: it is the safe
direction.

**ADR-0059** is the youngest, and it again belongs to the sort in which a
**finding decides the question**. Sought was where the derived sidecar unit
arises — in the cluster or on the node. The code already had an answer to that, in
two comments in `mesh::build`, and **neither carries**: nothing lands in the log
(the only caller is the identity path), and the inherited placement provides **no**
co-location — the planner works per workload, `api` and `api-proxy` are two of
them and are placed independently. With `spread="rack"` that means pretty surely
different nodes.

Decided is therefore: the **node** derives, from its own slice. Co-location is
thereby a **consequence** and not a rule — there is no constraint a planner could
violate. Two other ways were barred anyway: a leader that computes a log command
from a state is a **policy**, and `UpsertWorkload` does not stand on ADR-0057's
list; a co-location constraint would be a real extension of ADR-0011.

While building, a finding came along that is older than the ADR: the derived
command line had carried only arguments since **phase 8a**, and `<command>`
overrides entrypoint **and** cmd (schema, ADR-0003). It could never have started —
nobody saw it, because nobody started it. Fixed on the sidecar side (the unit now
carries its own `argv[0]`), not at the mapping: making `<command>` into OCI
semantics would be a schema change with a process of its own.

**ADR-0060** is the youngest and closes the last piece of the data plane: since
phase 9b the rule set for an instance's namespace had lain built and checked at the
kernel and was **not applied**, because behind a redirect onto a collector port it
no longer says which peer was meant.

Two findings carry it, and both were surprises. First: **the expectation about the
peer does not exist at all.** `Route.peer` is measured to be used only for the SNI
placeholder; the verifier knows no expected counterpart and checks *whoever
answers — does it stand in the bundle, is there the edge?*. A redirect thereby
changes nothing about the authorization. Second: **the exception in the rule set
would never have worked** — both containers run as 0, and `meta skuid 0` frees the
workload too.

The better expression `socket cgroupv2` proposed by 9b is measured to be
**barred**: `nft` v1.1.6 prints it as JSON and does not take the same line back.
Since ADR-0038 fixed the way over `nft -j -f -`, it stays at `meta skuid` — and the
sidecar container gets an **identifier of its own**. The price stands in the ADR:
the workload API socket goes to `0666`, because a connection there demands write
permission. Defensible, because the permissions there never authorized (ADR-0053
attests every connection individually) and because it is the model of the SPIFFE
specification that ADR-0035 followed.

**ADR-0061** is the youngest, and it closes an open point that had stood open
**since phase 3** — ADR-0009 named it itself and delegated it to the reconciliation
ADR: *"the exact behaviour on restart/backoff and how far cascades may run (damping
against flapping)."* ADR-0010 never took it up; measured, not a single word falls
there about cascades.

The consequence was measured, not presumed: **the whole requirement axis from
ADR-0009 had no effect at runtime.** `cascade_stop` and `may_be_active_together`
were built, checked and had no caller — the eighth time of the same pattern —, and
outside `graph.rs` **nothing** read a requirement edge. What an operator wrote as
`<requires>` or `<bindsTo>` was parsed, carried in the read model, linted and
afterwards discarded.

And underneath lay a second, heavier finding. `from_workloads` demands referential
integrity; the reconciler built the graph over the **locally assigned** workloads
and passed the error on with `?`. An edge across the node boundary — in the cluster
the normal case, because ADR-0011 places independently and ADR-0040 gives a node
only its own definitions — thereby ended the **agent**, and at every restart again.
That is why determination 1 is not a subsidiary provision but the precondition of
the whole ADR: without it there would be no pass in which a condition could be
evaluated.

Decided is the **condition** instead of the event: every pass evaluates anew,
against the outcome of that same pass. With that the damping ADR-0009 worried about
needs no counter — a crash that the same pass repairs does not count as a trigger
in the first place, and a **deferred** target expressly pulls nothing down
(ADR-0019: a quorum loss must not cost a running workload). `Conflicts` is refused
at ingest instead of enforced at runtime: whoever enforces at runtime must choose a
winner, and a winner rule is a policy.

**ADR-0062** is the youngest and arose from a correction: while striking out a
false note in the plan the sentence "a cycle comes to the node's attention" was to
stay — measured, it does not come to its attention but **ends it**. And the cycle
was the smallest case of a family. Measured against a real `tg-agent`, **one**
unreadable entry in the desired-state cache suffices, at startup as in running
operation:

```text
ERROR tg-agent ended: … is unreadable     EXITCODE: 1
```

The exit code turns that into a **crash loop** under any supervisor. The containers
carry on — the agent is not their parent process —, but with it go the workload API
socket (SVIDs carry 15 min with 2 min of grace, ADR-0014), the resolver (ADR-0013),
the session to the control plane (ADR-0040) and the one autonomous action ADR-0010
expressly permits: the restart of a crashed instance. After a good quarter of an
hour every mTLS connection on this node breaks. That is the reversal of the
keystone — workload availability hangs on the well-formedness of **one file**.

Decided is: **a broken entry costs its workload, not the node.** The node view can
no longer fail, it **isolates** — an unreadable document, a doubly declared name, a
self-reference, an ordering cycle — and reconciles with the rest. Isolated means
thereby neither started nor stopped: something is wrong with the definition, but "I
cannot classify you" is not "nobody wants you any more" (ADR-0019).

The security determination is the fourth, and it is compelling: **an incompletely
formed desired state does not clear away.** An unreadable document names no
workload, so its container was missing from the set of what is wanted — and the
clearer from ADR-0058 ended it. A file error must never cost a running workload.
That what should go stays lying is stated as the price in the consequences.

While building, a self-healing path came out that the draft did not have: the slice
clears away anyway what the cluster no longer names, and that decision falls by the
**name** — which the file name carries. The cleanup path therefore asks for file
names instead of content; with that an unreadable document disappears by itself as
soon as the cluster no longer wants it, and is rewritten if it still wants it.
Previously this path itself failed on the file it could have cleared away.

**ADR-0070** is the youngest and answers the largest undecided question this tree
still had: **what happens when an operator changes the declaration of a workload
whose container is running?** Measured against a real container: **nothing**, and
nobody says so — `step` returns immediately at `Running`, in the whole tree no
place compares a running container with its declaration, and the report calls the
instance `untouched`. A new image tag reaches it never, not even as an attempt. And
it was undecided, not merely unbuilt: "rolling" occurs in all ADRs only for the
orchestrator's processes, never for the declaration of a workload.

Decided is the answer ADR-0063 had already given for a single field: **no
autonomous restart** — it takes effect at the next start. To that comes an argument
that became visible only on measuring: there is **no health gate per workload**
(ADR-0015 knows liveness/readiness for the orchestrator's processes), and a rolling
update without this gate is a restart with hope. Instead the deviation is made
**visible** — the same movement as with auto-detach in ADR-0057. The trigger stays
an action and is expressly not part of the decision.

The remaining open points are implementation details that couple to their build
phase:

1. **XSD subset (0008)** — fixed in `schema/README.md` (phase 1, done).
2. ~~**Nonce discipline in FROST signing (0014)**~~ — **done in phase 7b.** The
   uniqueness is structural (`NonceVault`), not left to the caller, and checked
   under concurrency, repetition and a fuzz run. What remains open of ADR-0014 is
   no longer the discipline but its environment — and that is meanwhile
   **completely decided and built**: the TPM sealing of the shares
   (**ADR-0140**), the gRPC path between the signers (**ADR-0097**), the proactive
   refresh (**ADR-0107**) and the seat assignment (**ADR-0097**: it stands in the share, not in a setting,
   **ADR-0108** for the replacement). Of ADR-0014 what remains open is solely the
   **substantiation** of the metrics: soft fail 2 min and agent intermediate 12 h
   against a CP recovery statistic that exists only once the cluster runs.
3. ~~**Capacity report (0034)** — who writes a node's capacity.~~ **Done:
   ADR-0049**, built. The node reports, a policy decides, the leader writes — and
   the report reaches the planner never. **What a policy may read at all is decided
   by ADR-0057.**
4. **Time values of the cluster (0033)** — `heartbeat_interval` and
   `election_timeout_*` follow the measured runtime between the failure domains.
   The rule stands, the measurement comes in phase 5c.
5. **Local PV lifecycle and snapshot/backup DR (0027)** — provisioning, resize and
   the destructive delete; retention couples to 0020.
6. **Various start values/details** in individual ADRs (sharding strategy 0022,
   IPAM 0012, seccomp profile 0017, retention periods 0020, …) — each in the
   corresponding phase.

~~**Open decision without an ADR: egress policy for external endpoints.**~~
**Done: ADR-0041.** The sidecar decides by the name the connection itself names
(SNI), resolves it **itself** and dials it — and expressly does **not** terminate
the TLS session in the process, so that the check against the endpoint's CA stays
with the workload (ADR-0027). With that the S3 part of phase 10 is buildable.

The build plan (`PLAN.md`) is thereby unblocked throughout. Next step: start phase
0 (workspace scaffolding).

## Reference crates (working state, to be verified per ADR)

- Runtime/RPC: `tokio`, `tonic`, `rustls`
- OCI: `youki`, `oci-spec-rs`, OCI distribution client (`oci-client`/`ocipkg`)
- Consensus: `openraft` 0.9.25 (ADR-0032); Raft log on `redb`; DST bus without a
  foreign framework, virtual time via `tokio::time::pause` (ADR-0033)
- Projection: in-process (`tg-model` + `BTreeMap`), no database crate — ADR-0030; if persistence should ever be needed: `redb`
- XSD: `xsd-parser` (codegen, vendored — ADR-0026); candidate to watch `uppsala` (pure Rust, zero dependencies) from 1.0
- Identity/TLS: `spiffe`, `rustls` (custom SAN URI verifier)
- Threshold CA: `frost-core`/`frost-ed25519` (Zcash Foundation, FROST, DKG)
- Syscalls/networking: `rustix`, `nix`, `rtnetlink`, nftables binding
- Observability: `tracing`, `tracing-opentelemetry`, `metrics` + Prometheus exporter
