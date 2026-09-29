# ADR-0051: The original destination port — `SO_ORIGINAL_DST` in egress

- **Status:** accepted
- **Date:** 2026-08-25
- **Deciders:** Core team
- **Technical context:** `tg-proxy` (`egress`), `tg-net` (`nft`), ADR-0041,
  ADR-0012, invariant 2

## Context and Problem Statement

ADR-0041 decided egress: the sidecar reads the SNI, resolves the name **itself**
and dials it. While building phase 10d it became apparent that the port stays
open in this — after the redirect from phase 9b the connection arrives on the
sidecar's port and carries no information about where the container wanted to go.

The answer in 10d was: the port comes from the **allowlist**. If a name is listed
with several ports, it is refused rather than guessed — and there stands the note
that `SO_ORIGINAL_DST` belongs decided and not built in passing.

## The finding

**The situation is worse than "ambiguity is refused".** Measured against
`Egress::port_of`: with **one** listed port, that one is taken, **independently of
what the container chose.**

A workload dialling `s3.example.com:8443` while the permission reads
`s3.example.com:443` is therefore not refused — it is **silently redirected to
443**. It gets a connection it did not ask for, to a service that on another port
can be something else. And because the sidecar does not terminate (ADR-0041,
determination 1), at most the endpoint notices.

The second finding is a pattern this project now shows for the third time: **the
enforcement function already exists.** `Egress::permits(host, port)` checks
exactly that pair — and is called by no line of production code, only by tests.
Like `AdminClient` before ADR-0044 and `generate_token` before the `invite`
subcommand: built, tested, unused.

## Decision Drivers

- **ADR-0041, determination 2:** the sidecar decides by the name and dials it
  itself. What is added must not move that boundary.
- **Invariant 2:** `#![forbid(unsafe_code)]` in every crate except `tg-syscall`.
- **The redirect from 9b is static.** It stands in the netns and does not change
  with the policy; the allowlist, by contrast, comes from the slice (ADR-0040)
  and changes in operation.
- **A redirection the workload did not ask for is worse than a refusal.** A
  refusal is visible.

## Options Considered

- **A — nothing.** Ambiguity stays refused, unambiguity stays redirecting.
- **B — `SO_ORIGINAL_DST`.** Fetch the original destination address from the
  kernel.
- **C — one listener per permitted port.** Then the arrival port carries the
  information, and no socket option is needed.
- **D — enforce one port per name.** `AllowEgress` refuses a second port for the
  same name; then there is no ambiguity.

### Why not C

It sounds clean and moves the cost into the kernel path. The redirect from phase
9b is **static**: it stands in the netns, is written at setup and is not touched
afterwards. One listener per permitted port would mean one redirect per permitted
port — and the allowlist comes from the slice and changes in operation.

That would hang the nftables rule set on the control plane's cadence. A failed
rebuild would be either a hole (the old rule stays) or an outage (the new one is
missing), and both in a path ADR-0012 explicitly wants to keep simple.

### Why not D

It makes ambiguity impossible by forbidding a legitimate case: an endpoint with
an API on 443 and a console on 9000 is no embarrassment but normal. Besides, the
check would have to happen at the command's ingest — and there the missing
statement is not present at all: which port a workload later dials stands in no
log.

### Why not A

The finding itself: the silent redirection. It is not a side effect of ambiguity
but the normal case — every name in the allowlist with exactly one port behaves
this way.

## Decision

Chosen: **Option B**, with four determinations, of which the second is the most
important.

### 1. The port comes from the kernel, the name from the client

`rustix::net::sockopt::ip_original_dst` supplies the original destination address
of the redirected connection. A **safe** wrapper — invariant 2 is untouched, no
`unsafe` is needed and no detour through `tg-syscall`. `rustix` is in the tree
anyway (`tg-syscall`, `tgd`); for `tg-proxy` the `net` feature is added, no new
crate.

The check afterwards uses `Egress::permits(host, port)` — the function that
already exists. `port_of` goes away **outright**: it was the place where guessing
happened.

### 2. The address is discarded, only the port counts

That is the determination this ADR hangs on, and it is easy to get wrong:
`SO_ORIGINAL_DST` gives **IP and port**. The IP is the one the container dialled —
and it comes from a resolution it may have done itself.

Using it would be exactly the construction ADR-0041 rejected: *"a DNS-fed
firewall puts the trust boundary in the wrong place."* The sidecar resolves the
name **itself** (determination 2 there), and nothing about that changes. From the
kernel comes only the **port number** — the statement the container meant and
that needs no resolution.

Put differently: the kernel answers "which port did it want", not "where may it
go".

### 3. No answer, no connection

If the original address cannot be determined, the connection is refused — there
is **no** fallback to the port from the allowlist. A fallback would restore
exactly the behaviour this ADR abolishes and would make strictness depend on
whether a kernel call succeeds.

Plus a measured detail that makes the matter friendlier than expected: without a
NAT entry in conntrack, `SO_ORIGINAL_DST` returns the socket's **local** address,
i.e. the sidecar's egress port. A connection that did not come through the
redirect therefore refuses itself — provided nobody writes the egress port into
the allowlist. That must not happen and belongs in the operations manual; it is
not enforced here, because a special rule for a port number is the kind of
exception one can no longer explain later.

### 4. IPv4 now, IPv6 with the overlay

`ip_original_dst` is the IPv4 variant; `ipv6_original_dst` exists next to it. The
overlay is IPv4 (ADR-0012: `10.42.0.0/16`), so the IPv6 half is code without a
caller today. It comes when the overlay comes — the same rule as in ADR-0044.

## Consequences

**Positive**
- **The silent redirection goes away.** Whoever dials a non-permitted port is
  refused rather than redirected.
- **Several ports per name are expressible** — the case for whose sake the point
  stood open.
- The trust boundary does not move: the name stays the basis of the decision, the
  port is a kernel statement about the container's wish.
- No `unsafe`, no new crate, `port_of` falls away.

**Negative / Costs**
- **A behavioural change**, and one that can hit existing definitions: a workload
  that was silently redirected until now gets a refusal. That is the purpose —
  but it belongs announced, like "no sidecar, no egress" in ADR-0041.
- **Tests have to go through the redirect.** A test dialling the egress port
  directly is refused. That is the more faithful reproduction, but it is work on
  existing tests.
- The binding to the nftables `redirect` becomes explicit: with `TPROXY`
  something else would hold. ADR-0038 fixed `nft` as the way, a change is not on
  the agenda.

**Risks & Open Points**
- ~~**The egress port must never stand in the allowlist.** Operations manual, not
  enforced (determination 3).~~ — **done:** ADR-0051 — its own port is excluded
  under enforcement (`tg_proxy::egress`).
- **`SO_ORIGINAL_DST` says nothing about the intent with several permissions for
  the same port.** Two names on 443 stay distinguished through the SNI, as
  before — that is unchanged and right.
- Whether a workload should learn **why** it was refused is open: today it sees a
  closed connection. Returning a diagnosis would mean blabbing the allowlist to
  it.

## Related ADRs

- Depends on: ADR-0041 (egress by SNI), ADR-0012 (kernel datapath, IPv4),
  ADR-0038 (`nft` as the way), invariant 2
- Affects: ADR-0041 — the open point from phase 10d is thereby answered; from
  here on the sidecar checks name **and** port, as ADR-0025 requires for L4
