# ADR-0094: How a QUIC datagram reaches the sidecar

- **Status:** accepted
- **Date:** 2026-09-06
- **Deciders:** Dana Schlifka
- **Technical context:** `tg-net::rules`, `tg-proxy::egress`, `tg-agent`

## Context and Problem Statement

ADR-0092 determination 2 says what the sidecar **does** with a QUIC initial — read the
SNI, check it against the allowlist, resolve the name itself, splice without
terminating. How the datagram **arrives** at it, it leaves open.

The obvious assumption was that the QUIC path mirrors the TCP path: redirect, and fetch
the original destination port from the kernel (ADR-0051). Measured, it does not hold.

| Path | Measured |
|---|---|
| `SO_ORIGINAL_DST` on a UDP socket | **`ENOPROTOOPT`** — TCP only, on the listening socket as on the reconnected one |
| `IP_RECVORIGDSTADDR` under `redirect to :15003` | `127.0.0.1:15003` — the address **after** the DNAT |
| `tproxy` in the **output** hook | `Operation not supported` |
| **`redirect` without a port** | **`127.0.0.1:443`** — the port stays, the address becomes local |

So the question is no longer whether to copy the TCP path but which of the remaining
paths holds.

## Decision Drivers

- **The port comes from the kernel** (ADR-0051, determination 2). Taking it from the
  allowlist was measured there to be **redirecting**: with exactly one listed port,
  that one was taken, independently of what the container had chosen.
- **No new `unsafe`** (invariant 2). Since ADR-0081 three blocks stand in the tree, all
  in `tg-syscall`.
- **One namespace per instance, the sidecar moves in with it** (9b, ADR-0059). The
  sidecar's way to its workload is loopback, and the exception in the rule set hangs on
  its user id.
- **Fail-closed** (ADR-0041): what the sidecar cannot serve is no egress.
- **Deny by default for UDP stays** (ADR-0074). What arises here is a door for
  **permitted** destinations, not a hole.

## Options Considered

- **Option A — `redirect to :fixed` plus `IP_RECVORIGDSTADDR`.** The TCP path,
  transferred verbatim. **Measured out:** the ancillary data carries the address
  **after** the DNAT, the original destination is lost.
- **Option B — `tproxy`.** It does not rewrite the packet and still delivers it
  locally; `IP_RECVORIGDSTADDR` would then give the true destination. **Measured out:**
  it lives in prerouting, and a container produces its packets **locally** — in the
  output hook it does not exist.
- **Option C — `redirect` without a port, one listener per permitted port.** The port
  is preserved, the address becomes local.
- **Option D — the port comes from the allowlist.** The model before ADR-0051.
- **Option E — the sidecar gets a namespace of its own.** Then the workload's traffic is
  **forwarded**, and prerouting plus `tproxy` becomes available.

## Decision

Chosen: **Option C.**

It is the only measured one that supplies the port from the **kernel**, and it fits
ADR-0051 determination 2 verbatim — *"only the port counts, the address is discarded."*
The host comes from the SNI anyway, and that the address after the redirect reads
`127.0.0.1` is therefore no loss but precisely the statement ADR-0041 does not want: an
address from a resolution the container may have done itself.

**Option D is rejected and not merely inferior.** ADR-0051 measured what it does:
`s3.example.com:8443` dialled, `:443` permitted, and the container got **silently** a
connection it had not asked for — the endpoint noticed, it did not.

**Option E is rejected although it would be the technically cleanest.** It inverts a
determination taken for reasons of its own: if the sidecar lay in a namespace of its
own, its way to the workload would go over the bridge instead of over loopback, the
exception in the rule set could no longer be anchored to the user id (9b), and the
readiness probe would lose its place (ADR-0080: `prerouting` does not fire on loopback —
on that it rests). Rebuilding a data plane to gain a protocol is the wrong trade.

### Determination 1 — the port comes from the kernel, the address is discarded

`redirect` **without** a port, and the sidecar reads the original destination through
`IP_RECVORIGDSTADDR`. Of it **only the port** is taken; after the redirect the address
is `127.0.0.1` anyway and even without it would be the one the container dialled.

The ancillary data is read by `nix`: `rustix` does not know `IP_ORIGDSTADDR`, and a
cmsg parser of our own would be this project's fourth `unsafe` block for something that
exists ready-made — **no new `unsafe`** (invariant 2) is therefore the real gain.

**The price is measured and not zero:** `nix` itself is in the tree through `rtnetlink`,
but its `socket` feature pulls in **one** package — `memoffset` 0.9.1 (MIT), which
`rtnetlink` does not need. It is unavoidable: `recvmsg` lives in exactly that feature.

### Determination 2 — one listener per permitted port

Because the redirect preserves the port, the sidecar has to listen on **the** port the
container chose. Which ones those can be stands in the allowlist it re-reads in
operation anyway (ADR-0041): the set of ports with transport `quic`.

The listeners follow it **level-driven** (ADR-0010): a port added gets one; one removed
loses it. A shout would be lost, a reconciliation would not.

### Determination 3 — the rule set follows the allowlist too

The redirection applies **only** to the permitted ports. A rule over all UDP would
redirect what ADR-0074 drops too — and the counter on the dropping rule, which tells an
operator that something dies there, would count nothing any more.

With that the rule set in the namespace becomes for the first time **dependent on the
desired state** and not only on the topology. It is reconciled like the node's
(`ensure_rules`), from the same source as the listeners.

### Determination 4 — no listener, no egress

If a port does not bind, there is no way out over it. That is fail-closed and the same
direction as ADR-0041: a boundary outward that never existed without a permission.

The case is **named** and not concealed — a destination that stands in the permission and
is nevertheless unreachable would otherwise be a riddle in operations (the same
consideration as with the refused permission on the sidecar's own egress port,
ADR-0051).

### Determination 5 — the per-flow state is bounded

A flow is `(sender, original destination port)`. It carries a `Handshake` (ADR-0092), a
deadline and at most one upstream socket. The number of flows and their lifetime are
bounded: the datagrams come from a **container**, and whoever uses arbitrarily many
source ports must not bind memory.

### Determination 6 — the conflict with a UDP service is measured theoretical

A listener on `0.0.0.0:443` occupies that port in the instance's namespace, and a
workload wanting to offer a UDP service there itself could not.

That costs nothing: since ADR-0074 **inbound** UDP in a mesh member's namespace is
dropped anyway — a UDP service there is reachable by nobody. The conflict stands here
nonetheless, so that it is not rediscovered on the next reading.

## Consequences

**Positive**

- The port comes from the kernel; ADR-0051 holds for QUIC as for TCP, and option D's
  silent redirection does not arise in the first place.
- **No new `unsafe`** — the ancillary data has a safe API in `nix`, and `tg-syscall`
  stays at three blocks.
- The namespace cut from 9b stays untouched, and with it the sidecar's loopback path and
  the probe from ADR-0080.
- The redirection applies only to permitted destinations; ADR-0074 stays in force for
  everything else, counter included.

**Negative / Costs**

- **One more package in the tree** (`memoffset`, MIT) — the price of `nix`'s `socket`
  feature. It is measured, not estimated, and the alternative would have been our own
  `unsafe` cmsg parser.
- **The sidecar binds dynamically.** Its listeners follow a file, and a port newly
  permitted is serviceable only after the next reconciliation — that is a latency the
  TCP path does not have.
- **The rule set in the namespace is reconciled**, not laid once. That is more work per
  pass and one more place at which something can drift.
- A workload cannot bind its own UDP service on a permitted port (determination 6).

**Risks & Open Points**

- **IPv6 is not decided.** `IP_ORIGDSTADDR` has a counterpart in `IPV6_ORIGDSTADDR`; the
  overlay is IPv4 (ADR-0012), and the question arises with it.
- ~~**The limits from determination 5 are starting values.** How many flows a sidecar
  should carry hangs on the data plane and is not measured.~~ — **done: ADR-0121**, and
  the question was posed wrongly. Measured, a limit on the **number** of flows is not
  one on memory: a flow that never decides held 510.1 KiB — eight retained datagrams of
  65,000 bytes each — i.e. 255 MiB at `MAX_FLOWS`, per listener, out of a container and
  without a single file descriptor going out. From ADR-0121 the **bytes** are bounded:
  `MAX_DATAGRAM` becomes 2048 (the size of the link instead of that of UDP), a
  truncation ends the flow instead of silently forwarding it, what is retained gets a
  byte total, and the limit applies to the **sidecar** instead of to the listener.
  Re-measured on the built state: 18.4 KiB per hanging flow, 9.2 MiB at 512 — and the
  65,000 bytes no longer produce a flow at all. The **number** 512 stays and now has a
  calculation that can be held against the memory limit from ADR-0086.
- **Plain UDP by address** (ADR-0092, determination 5) is unaffected by this decision:
  there nftables decides on resolved addresses, and no listener arises.

## Related ADRs

- Depends on: ADR-0092 (the SNI path for QUIC), ADR-0051 (the port comes from the
  kernel), ADR-0074 (deny by default for UDP), ADR-0059 and 9b (one namespace per
  instance)
- Affects: ADR-0093 (the rule set in the namespace gains a redirection that follows the
  desired state), ADR-0041 (the allowlist now also determines listeners and rules)
