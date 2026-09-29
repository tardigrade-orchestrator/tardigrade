# Command reference

Every command and every switch of the four programs. **Complete** is the
promise here, and it is guarded: `crates/tgctl/tests/handbook.rs` checks both
directions — this document names nothing that does not exist, and it leaves
nothing out that a binary accepts.

That is the difference from `OPERATIONS.md`. The manual explains **why** and is
deliberately a selection; this page is the list. Whoever looks up what a switch
does in operation finds the reason there, and the ADR behind it in `plans/`.

Every program prints its own overview in three spellings: `tgctl help`,
`tgd help`, `tg-agent help`, `tg-proxy help` — and `-h` and `--help` do the
same.

---

## `tgctl`

The command-line client. It reaches **its** node — over the admin socket in the
data directory, or over the operator port with `--peer` (ADR-0103).

### Global options

| Option | Meaning |
|---|---|
| `--data-dir <path>` | data directory (default: `/var/lib/tardigrade`) |
| `--node-id <n>` | which node in the data directory — needed when several lie there |
| `--peer <host:port>` | over the operator port instead of the socket. Demands `--operator`, `--operator-key` and `--anchors`; without all three it is refused and **not** fallen back to the socket |
| `--operator <name>` | under which name this operator is registered |
| `--operator-key <file>` | their private key (PEM), from `tgctl operator keygen` |
| `--anchors <file>` | the cluster leaves of the `tgd` nodes, concatenated — the same file an agent reads as `identity/control-plane.pem` |
| `--domain <name>` | trust domain of the cluster (default: `cluster.local`) |
| `--ttl <seconds>` | deadline of an invitation (default: 900) |
| `--anchor <hex>` | anchor of the audit chain (default: `GENESIS`) |

### The node-local path

Phase 2, for a node without a cluster. On a node with a session the next slice
undoes it.

| Call | What it does |
|---|---|
| `tgctl apply <file.xml>` | take a definition and start workloads |
| `tgctl list` | show the node's wanted workloads |
| `tgctl remove <name>` | remove a workload from the wanted state |
| `tgctl restore-volume <volume> <generation> --yes` | restore from a snapshot — destructive, node-local, in no log (ADR-0099). Demands an unmounted volume |

### The cluster: reading

| Call | What it does |
|---|---|
| `tgctl cluster show` | workloads in the cluster: wanted and observed |
| `tgctl cluster nodes` | nodes in the cluster: wanted and observed |
| `tgctl cluster get <workload>` | the stored definition, on standard output |
| `tgctl cluster settings` | what holds cluster-wide: address plan, sidecar overhead, capacity and rotation policy |
| `tgctl cluster trust` | who may be a node, with underlay and open invitations |
| `tgctl cluster volumes` | which volumes are deleted, per node |
| `tgctl cluster secrets` | which secrets exist and who may read them — **without** the values |
| `tgctl cluster lint` | the hints about the wanted set (ADR-0048) |
| `tgctl cluster members` | voters and leader (ADR-0005) |
| `tgctl cluster signer` | what this node knows about the signing group: seat, shape, epochs, fingerprint, links (ADR-0097, ADR-0107) |

### The cluster: workloads

| Call | What it does |
|---|---|
| `tgctl cluster apply <file.xml>` | send a definition to the cluster — one `UpsertWorkload` per workload |
| `tgctl cluster remove <name>` | withdraw a workload; edges and egress permissions go with it |
| `tgctl cluster restart <workload> <generation> [--instance <n>]` | make a changed declaration take effect (ADR-0071). Without `--instance` all instances restart; with it the operator rolls themselves |
| `tgctl cluster promote <workload> <instance>` | arm a replica: from now on it carries the active role (ADR-0111). If another node still holds it, it takes effect only after that lease expires |

### The cluster: who may talk to whom

| Call | What it does |
|---|---|
| `tgctl cluster allow <a> <b>` | `a` may call `b` (`may_talk`, ADR-0025). The direction counts |
| `tgctl cluster revoke <a> <b>` | withdraw the edge — existing connections end within the revocation window |
| `tgctl cluster allow-egress <workload> <name:port[/transport]>` | `workload` may go out to `name` (ADR-0041). The port is mandatory; the transport is `tcp` (default), `quic` or `udp` (ADR-0092) and is not guessed |
| `tgctl cluster revoke-egress <workload> <name:port[/transport]>` | withdraw the permission — the transport belongs to the key |

### The cluster: secrets and registries

| Call | What it does |
|---|---|
| `tgctl cluster secret put <name> <file\|->` | store a secret, sealed (ADR-0016, ADR-0095). `-` reads standard input; a value on the command line does not exist — it would stand in the process list |
| `tgctl cluster secret rm <name>` | remove it — refused as long as somebody may still read it |
| `tgctl cluster secret allow <workload> <name>` | who may read it. Deny-by-default |
| `tgctl cluster secret revoke <workload> <name>` | withdraw the permission |
| `tgctl cluster secret rekey` | re-key every value onto the primary data key (ADR-0100) |
| `tgctl cluster registry <host> <secret>` | which secret applies for a registry (ADR-0096). The plaintext is one line: `basic <user>:<password>` or `bearer <token>` |
| `tgctl cluster registry rm <host>` | withdraw the mapping — the pull then runs anonymously |

### The cluster: volumes

| Call | What it does |
|---|---|
| `tgctl cluster delete-volume <volume> <node> --yes` | delete a volume — destructive, demands `--yes` (ADR-0027); cannot be brought back |
| `tgctl cluster snapshot-volume <volume> <node> <generation>` | decree a snapshot (ADR-0099). The node briefly freezes the file system; the snapshot is crash-consistent, not application-consistent |

### The cluster: settings and membership

| Call | What it does |
|---|---|
| `tgctl cluster network <cidr> <prefix>` | set the cluster network — one source for all nodes (ADR-0040, ADR-0069) |
| `tgctl cluster sidecar-overhead --resource <name=number>` | what a sidecar costs; the planner reckons it in per mesh instance (ADR-0067). Without `--resource`: withdraw |
| `tgctl cluster learner <id>` | admit a node as a learner and wait until it has caught up — step 1 of 2 |
| `tgctl cluster voters <id>,<id>,…` | set the voters — step 2 of 2. The **complete** set, not an increment |

### Nodes

| Call | What it does |
|---|---|
| `tgctl node invite <name>` | invite a node (only on the leader, ADR-0037). The token appears on standard output and nowhere else |
| `tgctl node upsert <name> --site <s> --hall <h> --rack <r> [--resource <name=number>] [--reserve <name=number>]` | enter or change a node. The three failure domains are mandatory; `--resource` and `--reserve` are repeatable (ADR-0047) |
| `tgctl node remove <name>` | remove a node — only that frees its ordinal (ADR-0039) |
| `tgctl node revoke-trust <name>` | declare a node's key invalid (ADR-0054); the ordinal stays |
| `tgctl node cordon <name>` | place nothing new there any more |
| `tgctl node drain <name>` | and: what runs there moves away — except what a writable volume nails down (ADR-0027) |
| `tgctl node uncordon <name>` | withdraw both |
| `tgctl node detach <name>` | take a node out of the data plane; ordinal and trust stay (ADR-0054) |
| `tgctl node attach <name>` | and bring it back |
| `tgctl node rotate <name> identity\|underlay <generation>` | decree a key generation; the node follows (ADR-0055) |
| `tgctl node rotation --rotate-every <kind>=<days>` | how often keys are changed; the leader spreads the changes (ADR-0057). Without a setting: off |
| `tgctl node policy [--rule <name:k=v,…>]` | set the capacity policy (ADR-0049). Keys: `subtract`, `percent` (mandatory), `cap`, `reserve`; repeatable. Without `--rule`: withdraw |

### Operators

| Call | What it does |
|---|---|
| `tgctl operator keygen` | produce an operator's key pair (ADR-0103). The private part stays here; the SPKI line is what `enrol` gets |
| `tgctl operator enrol <name> <spki> --class <class>[,…]` | register an operator (ADR-0105). Classes: `read`, `secrets`, `write`, `membership`, `operators` — mandatory, with no default |
| `tgctl operator list` | who is registered and what they may do |
| `tgctl operator revoke <name>` | withdraw the registration; takes effect on the next request |

### Keys, signing group, audit

| Call | What it does |
|---|---|
| `tgctl secret keygen` | produce the cluster-wide data key (ADR-0095). It belongs on **every** `tgd` node under `<data-dir>/identity/secrets.key` and is backup material |
| `tgctl cluster signer-refresh` | renew the signer shares (proactive refresh, ADR-0107). The group key stays the same, so certificates and chains keep applying; the old epoch is discarded once all five have reported the new one. Prints the epoch on standard output |
| `tgctl signer repair <seat> --helper <n>=<url> [--helper …]` | restore a lost share (RTS, ADR-0108). Runs on the node of the **affected** seat and needs no admin socket; at least `t` helpers (default 3) |
| `tgctl audit [<file>] [--anchor <hex>]` | recompute the audit chain, without a cluster (ADR-0020). Without a file the whole chain of all segments |

---

## `tgd` — the control-plane node

```
tgd --id <n> --listen <address> --peer <n>=<url> [...]
```

| Option | Meaning |
|---|---|
| `--id <n>` | own node identifier (default: 1) |
| `--node <name>` | own node name (default: the first label of the hostname, otherwise `node`); stands in the URI SAN of the cluster leaf (ADR-0043) |
| `--listen <ip:port>` | listening address (default: `127.0.0.1:7001`) |
| `--cluster-listen <addr>` | Raft port, mTLS against `<data-dir>/peers/<id>.pem` (default: `127.0.0.1:7002`) |
| `--node-listen <addr>` | node session, mTLS against the trust list from the log (default: `127.0.0.1:7003`) |
| `--operator-listen <addr>` | operator port, mTLS against the registration from the log (ADR-0103). Without it the access stays at the Unix socket |
| `--signer-listen <addr>` | the signing group's port, mTLS against `<data-dir>/signers/<seat>.pem` (ADR-0097). Without it this node does not offer its share |
| `--peer <n>=<url>` | node `n` is reachable at `url`; repeatable, our own node included |
| `--signer <seat>=<url>` | seat `seat` is reachable at `url`; repeatable, **without** our own seat — that comes from the share |
| `--data-dir <path>` | data directory (default: `/var/lib/tardigrade/control-plane`) |
| `--trust-domain <name>` | the SPIFFE server's trust domain (default: `cluster.local`). Without signing material the node runs without a SPIFFE server |
| `--init` | create the membership — exactly once in a cluster's life |
| `--init-voters <n,n,…>` | who is a voter at the creation (default: all `--peer` settings) |
| `--heartbeat-ms <n>` | heartbeat interval (default: 100, ADR-0033) |
| `--election-min-ms <n>` | lower election timeout (default: 500) |
| `--election-max-ms <n>` | upper election timeout (default: 1000) |
| `--snapshot-every <n>` | a snapshot after `n` entries (default: 5000) |
| `--keep-logs <n>` | entries that stay in the log after a snapshot (default: 1000) |
| `--audit-rotate <n>` | records per audit segment (default: 100000, `0` = never rotate). A closed segment can be moved into the WORM archive, an open file cannot (ADR-0020, ADR-0132) |
| `--audit-export` | write a log range as a sealed segment to standard output and end (ADR-0137). Only with the node **stopped** — `redb` lets exactly one process at the log |
| `--audit-from <n>` | first index of the export |
| `--audit-to <n>` | last index of the export |
| `--audit-anchor <hex>` | anchor of the exported chain |

---

## `tg-agent` — the node agent

```
tg-agent                  reconcile loop against the local cache
tg-agent --once           exactly one pass, then exit
```

| Option | Meaning |
|---|---|
| `--data-dir <path>` | data directory (default: `/var/lib/tardigrade`) |
| `--interval <seconds>` | distance between passes (default: 10) |
| `--once` | exactly one pass, then exit |
| `--node <name>` | name of this node (default: first label of the hostname, lower-cased) |
| `--control-plane <address>` | SPIFFE server, e.g. `http://127.0.0.1:7001`. With it the agent fetches its agent intermediate itself and renews it every three hours; without it, it reads what lies under `<data-dir>/identity/` |
| `--node-session <address>` | node session of the control plane, e.g. `http://127.0.0.1:7003` (ADR-0040). **Repeatable** — after a leader change the agent moves on to the next entry (ADR-0077). Without it the node gets no slice |
| `--trust-domain <name>` | trust domain of the SVIDs (default: `cluster.local`) |
| `--no-identity` | do not open the workload API socket |
| `--no-quorum` | treat the control plane as unreachable |
| `--cluster-cidr <cidr>` | address space of all containers (default: `10.42.0.0/16`) |
| `--node-prefix <n>` | prefix length per node (default: 24) |
| `--dns-domain <name>` | zone of the resolver (default: `tardigrade.internal`) |
| `--dns-forward <address>` | upstream for permitted egress names (ADR-0041); without it nothing is forwarded |
| `--underlay-endpoint <address>` | this node's externally reachable UDP endpoint, e.g. `10.0.0.7:51820`. With it the agent announces its WireGuard underlay at every renewal (ADR-0039, ADR-0042) |
| `--proxy-image <ref>` | image of the sidecar (ADR-0007). Without it no sidecars are derived and no identities delegated (ADR-0036) |
| `--pin-sidecar-shards` | pin the sidecars' shards to fixed cores (ADR-0114). Default off |
| `--cdi-dir <path>` | where the CDI specifications lie (ADR-0143). Repeatable; without a setting `/etc/cdi` and `/var/run/cdi` apply |
| `--userns-base <number>` | put containers into a user namespace (ADR-0091): identifier 0 in the container becomes `number` on the node. Demands a runtime that can enter a netns over a path from inside the user namespace — measured, `crun` can and `youki` cannot |
| `--no-seccomp` | leave the seccomp profile out (ADR-0090). It then applies to **all** containers of this node, and the start reports it |
| `--keep-snapshots <n>` | how many snapshot generations stay per volume (ADR-0099, default: 3; `0` means all) |

---

## `tg-proxy` — the mTLS sidecar

Started by the agent, not by hand: its identity comes over the workload API
socket, and that gives nothing to an unattested process. The derived unit
carries these settings (ADR-0059).

```
tg-proxy --workload <name> --upstream-port <n> --socket <path> [...]
```

| Option | Meaning |
|---|---|
| `--workload <name>` | for whom it proxies — **mandatory** |
| `--upstream-port <n>` | where incoming traffic goes on loopback — **mandatory** |
| `--socket <path>` | the workload API socket (ADR-0035) — **mandatory** |
| `--listen <address>` | where incoming mTLS is accepted |
| `--mesh-listen <address>` | where redirected mesh traffic is accepted (ADR-0060). The destination then comes from the kernel (`SO_ORIGINAL_DST`) and not from `--route` |
| `--route <peer>=<address>` | one outgoing route; repeatable |
| `--policy <file>` | `may_talk` edges, one per line: `a -> b`. Without it deny-by-default applies and nothing gets through |
| `--egress-listen <address>` | where outgoing traffic is accepted (ADR-0041). Without it there is no egress — deny-by-default applies to the port itself too |
| `--egress <file>` | egress permissions, one per line: `workload name port`. The agent writes them from the slice (ADR-0040) |
| `--mesh-udp-listen <addr>` | where incoming datagrams are accepted (ADR-0142) |
| `--mesh-udp-upstream <p>` | where incoming datagrams are passed through to — the workload's port from the `udp` attribute of `<mesh>` |
| `--mesh-udp <file>` | the peer mapping for UDP in the mesh, one per line: `workload peer address:port local-port` |
| `--active-role <file>` | the active-role leases, one per line: `workload epoch deadline`. The agent writes them from the slice (ADR-0064) |
| `--single-writer` | this workload is a single writer (ADR-0066). Only then does the sidecar rein it in. The setting stands **here** and not in the file — fail-closed |
| `--trust-domain <name>` | default: `cluster.local` |
| `--shards <n>` | default: as many as there are cores (ADR-0022) |
| `--pin-shards` | pin every shard onto a fixed core (ADR-0114). Default off |

---

## Telemetry — the same four on all three daemons

| Option | Meaning |
|---|---|
| `--telemetry-addr <addr>` | address for `/metrics`, `/livez`, `/readyz`; `off` switches the endpoint off |
| `--otlp-endpoint <url>` | export spans via OTLP (ADR-0015, ADR-0133); without it nothing is exported. **`tg-proxy` refuses the switch** — the sidecar exports no spans, and a switch that does nothing is an assurance that stands out only in the incident |
| `--log-filter <expr>` | like `RUST_LOG` (default: `info`) |
| `--log-format json\|text` | default: `json` |

A telemetry failure never stops a node: a poorly observable node is not a
broken one (ADR-0019).
