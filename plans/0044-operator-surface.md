# ADR-0044: The operator surface — transport and access

- **Status:** accepted
- **Date:** 2026-08-23
- **Deciders:** Core team
- **Technical context:** `tgd` (`admin`), `tgctl`, `tg-identity` (attestation),
  ADR-0018

## Context and Problem Statement

ADR-0043 authenticated the cluster transports and explicitly exempted the admin
port: *"As long as `tgctl` is node-local that is bearable; with the first cluster
client it no longer is."* That was a deferral, and it is the last open point with
security weight.

What lies on this port is not a part of the control but **the whole of it**:

| Call | What it can do |
|---|---|
| `Write` | 36 command kinds — among them `SetClusterNetwork` (renumbers the entire cluster network), `InviteNode` (issues a join invitation), `RevokeTrust` (throws a node out), `DeleteVolume` |
| `Membership` | `AddLearner` and `ChangeMembership` — **the voters of the Raft cluster** |
| `Status`, `Projection` | the complete desired state, in the clear |

`ChangeMembership` is the sharpest: change the membership to a single foreign
node, and the cluster belongs to somebody else. For comparison — ADR-0040 went to
some trouble not to give a **node** the blueprint of the cluster; `Projection`
gives it to anyone who reaches the port.

## The finding that shifts the question

**There is no caller.** `AdminClient` appears in `crates/*/src` exactly once — in
its own definition. It is only looked up by tests. `tgctl` has no `tonic`
dependency and does not talk to `tgd`; it is node-local (`tgctl apply` against the
runtime).

The situation is therefore not "an API needs authentication" but: **a fully
privileged, unauthenticated TCP port without clients.**

Two further measurements belong here:

- **The loopback default does something.** `--listen` binds to `127.0.0.1`, and a
  container does **not** reach the host's loopback: it has its own (phase 9b).
  What reaches it is the bridge address — the resolver listens there, not the
  admin service. The exposure is therefore "every process on the host", not
  "every container".
- **Since ADR-0043 this port no longer has to be reachable.** Raft lies on
  `--cluster-listen`, the node session on `--node-listen`. `--listen` afterwards
  carries only admin and identity; of those two, **identity** needs a routable
  address (the agent calls in), admin does not.

## Decision Drivers

- **No port without a caller.** An attack surface nobody uses is the only one one
  can close at no cost.
- **ADR-0018 stays valid:** `tgctl` as the CLI, gRPC over `tonic`, mutating calls
  through the leader into the log (ADR-0020).
- **Invent nothing nobody needs yet.** An operator identity requires: a role in
  the SPIFFE path (ADR-0036 knows `workload` and `node`), somebody who issues it,
  and an authorization model — ADR-0018 itself carries "RBAC granularity" as an
  open point.
- **Existing material before new.** `SO_PEERCRED` and the cgroup attestation have
  been in place since 7a and are used by the workload API; `tonic` already speaks
  over a Unix socket there.
- **The harness must not become heavier than the thing.** Ten integration tests
  talk to the admin service.

## Options Considered

- **Option A** — SPIFFE mTLS with a new role `operator`, as ADR-0018 sketches it.
  Plus an authorization model per command class.
- **Option B** — the admin service moves to a **Unix socket** in the data
  directory; the TCP port disappears. Access through file permissions, checked
  via `SO_PEERCRED`.
- **Option C** — mTLS on the TCP port with the node's **cluster leaf** as the
  client credential (ADR-0043): whoever holds the node key may administer.
- **Option D** — do nothing until a cluster client exists.

### Why not A

Not wrong, only too early — and expensive in the wrong place. The role would be
the third in the path, its issuance path a ceremony of its own (who vouches for a
human?), and the authorization model the question ADR-0018 carries as open. All
of it for a client that does not exist.

And a gap would remain: mTLS says **who** calls, not **what** they may do.
Without authorization per command class every operator identity would have
`ChangeMembership` — i.e. everything. An auth system with only one level is,
given this command set, barely better than none.

### Why not C

It sounds frugal and is the wrong boundary. The node key is the identity of a
**machine in the cluster** (ADR-0037), not that of a person with operating
rights. Whoever makes it the admin credential is saying: every node may change
the membership. That is exactly the trust boundary ADR-0040 determination 5 drew
so carefully — a compromised node should not be the blueprint of the cluster, let
alone its owner.

### Why not D

Because the deferral has already happened once (ADR-0043) and its justification
was wrong: there it said that `tgctl` also speaks on `--listen`. Measured, that
is not so. A deferral whose justification does not hold is not a deferral but an
oversight with a date.

## Decision

Chosen: **Option B now, option A once there is a client.** The split is the point
itself — the surface shrinks to what is used, and the open question stays open
instead of being half-answered.

### 1. The admin service listens on a Unix socket, not on TCP

`<data-dir>/admin.sock`, mode `0700`, in the data directory `tgd` owns anyway.
The TCP port for admin goes away **outright**; `--listen` afterwards carries only
the identity service, which needs a routable address.

Access thereby becomes a question of file permissions, and the operating system
answers that — not us. That is the core: we build no authorization model, we use
the existing one.

gRPC stays gRPC (ADR-0018): `tonic` over a Unix socket is the same construction
the workload API has run since 7c.

### 2. The file permissions are the gate, `SO_PEERCRED` the cross-check

The service reads the connection's credentials and refuses whoever's UID is
neither its own nor 0. That is **redundant** with mode `0700` and is meant to be:
an access rule hanging on a file mode alone hangs on `umask`, on a copy
operation, and on an operator who once opens the directory wider. Two reasons
that both have to hold survive the loss of one.

The path for it exists: `PeerCredentials` from `tg_identity::workload_api`,
obtained from `SO_PEERCRED` — **not forgeable**, because the kernel writes it and
not the caller.

### 3. Reading does not become easier than writing

`Status` and `Projection` lie behind the same gate. They hand out the complete
desired state, and ADR-0040 justified why that is not a harmless access. A
second, more open read path would be a second boundary to guard.

### 4. What option A will later need is fixed here — not built

So that the next step does not become a matter of principle:

- The role is called **`operator`**, path form
  `spiffe://<domain>/operator/<name>` per ADR-0036. No namespaces, as decided
  there.
- Authorization is **per command class**, not per identity. Three classes, and the
  boundaries lie where the damage jumps: `read` (`Status`, `Projection`) ·
  `write` (the command set) · `membership` (`AddLearner`, `ChangeMembership`).
- The Unix socket **stays** alongside. It is the way an operator gets a cluster
  running again whose identities are broken — the same consideration for which
  ADR-0043 keeps the Raft port's peer list local: a recovery must not presuppose
  what it restores.

### 5. `tgctl` gets the socket, but not in this cut

`tgctl` is node-local today and talks to the runtime. Making it an admin client
is ADR-0018 work and can follow once the socket stands. Until then the only
client is the harness — and that is more honest than a port waiting for nobody.

## Consequences

**Positive**

- The last unauthenticated, fully privileged access disappears, and without a new
  auth system.
- A process not running as the `tgd` user or root can no longer change the
  membership. Before, "somewhere on this host" sufficed.
- `--listen` loses a service; what is left (identity) is the only one that needs a
  routable address.
- The harness does not get heavier: a socket path instead of a port number, and
  the port scarcity of the test runs decreases.

**Negative / Costs**

- **Remote access goes away** — it existed but was unused. Whoever would have
  administered over the network today will in future do it over a session on the
  node. That is a behavioural change and belongs in the operations manual.
- Ten integration tests change transport.
- Two access paths in the end (socket and, later, mTLS) instead of one. The
  reason stands in determination 4; the price is a second place where
  authorization happens.

**Risks & Open Points**

- **Root is root.** Whoever is root on the node may administer — and could read
  the data directory and replace the process anyway. The decision moves the
  boundary to the operating system's; it does not raise it beyond that.
- ~~**No audit of the caller.** The log records *what* happened (ADR-0020), not
  *who* caused it. The connection's UID is known and is not written into the log
  — it would be a node-local statement in a replicated substrate. Whether the
  audit trail needs a caller is an ADR-0020 question and open here.~~ — **done:**
  ADR-0050 — the envelope `{ actor, command }`.
- **The directory's permissions are an operational precondition**, like `nft`
  (ADR-0038) and an unblocked resolver port (phase 9b). A `<data-dir>` opened too
  wide is therefore a privilege escalation — the cross-check from determination 2
  catches it, but it should not arise at all.
- ~~Authorization per command class is **fixed, not built**. As long as only the
  socket exists there is exactly one class: everything.~~ — **done:** ADR-0105.

## Related ADRs

- Refines: ADR-0018 (the transport stays gRPC, access becomes local first),
  ADR-0043 (closes the exception named there)
- Depends on: ADR-0036 (the path form of the future role), ADR-0017 (a privileged
  `tgd`), ADR-0006 (`SO_PEERCRED` attestation)
- Touches: ADR-0020 (whether the caller belongs in the audit trail — open),
  ADR-0040 (`Projection` hands out what was drawn tightly there)
