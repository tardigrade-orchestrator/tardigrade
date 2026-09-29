# ADR-0102: The HTTP Probe

- **Status:** accepted
- **Date:** 2026-09-06
- **Concerns:** ADR-0080 (readiness), ADR-0015 (probes), ADR-0007
  (mTLS data plane), ADR-0076 (detection latency), ADR-0008 (schema)

## Context and Problem Statement

ADR-0080 decided readiness as a **TCP connect** and rejected HTTP with two
justifications — an effort and a question:

> It requires a client in the agent, a second path in the definition and a
> **decision about TLS** — and that one is not harmless: a foreign image binds
> its port in plaintext because the sidecar terminates (ADR-0007). An HTTP
> probe would therefore have to know whether to speak plaintext or TLS, and
> that depends on whether `<mesh>` is declared.

**The question is measured moot.** ADR-0080 determination 3 lets the probe run
**inside the namespace over loopback**, and `prerouting` does not fire on
loopback (the kernel property that was measured there and on which the
sidecar's path to its workload also rests). The probe therefore **always**
reaches the workload's upstream port — and nothing terminates there: the
workload listens in plaintext, with `<mesh>` or without.

And the effort is smaller than it looks: the probe is **synchronous** and runs
on its own thread (`run_in`, because `setns` applies to a thread). A client
like `hyper` would need a runtime there; a `GET` with `std::io` does not.

What remains is the reason why the probe is needed at all. ADR-0080 names it
itself among the costs:

> A server that listens and answers `500` counts as ready.

That is not the edge case but **the standard pattern**: a service binds its
port at startup and answers `503` until it is finished. For it a TCP connect
says practically nothing — it is "ready" from the bind onwards.

## Decision

### 1. `path` is a second, **optional** setting

`<readiness port="8080" path="/healthz"/>`. Without `path` it stays at the TCP
connect — unchanged, and that is more than backward compatibility: it is the
right probe for a workload that speaks **TLS** on its port (one without
`<mesh>`, with its own mTLS, ADR-0079). A plaintext `GET` would get a TLS
alert there and read it as a failure.

### 2. Plaintext, and no TLS decision

See above: the probe goes over loopback to the upstream. There is no case in
which it would have to speak TLS — and whoever has one leaves `path` out.

No `scheme` attribute, no `insecure` switch. Both would be a setting for a
case this model does not have, and an attribute that can be set is one that
someone sets wrongly.

### 3. Ready is `2xx`

Not `3xx`: a redirect is not readiness, and the probe follows none — that
would be a second call, a loop check and a question about the target. Not
`4xx`/`5xx`.

That is the convention of the ecosystem, and it is the only one that gets by
without further settings.

### 4. No HTTP client — a `GET` and the status line

What is sent is `GET <path> HTTP/1.1`, `Host:`, `Connection: close`. What is
read is the **status line** and nothing else; the body is discarded without
being read.

That is not a parser but a comparison on the first bytes — and expressly
bounded: at most 64 bytes are read before the probe judges. The bytes come
from a workload, that is, from a trust boundary; a full HTTP reader would be
the kind of code here that ADR-0041 rejected for the `ClientHello`, and
`hyper` would be a runtime in a `setns` thread.

**What that cannot do belongs named:** chunked encoding, trailers, redirects,
`HTTP/2`. None of that stands in a status line, and none of it answers "is
this service ready".

### 5. One deadline for the whole probe, not per operation

`probe::TIMEOUT` (250 ms) applies to connect, send and read **together**: the
probe carries the remaining time forward. Set per operation the worst case
would be three times as large — and the ordering condition from ADR-0076
reckons `TIMEOUT` against the floor of the detection latency (one second). At
750 ms a quarter of headroom would remain, and a safety statement should not
hang on a quarter.

## Consequences

**Positive.** The standard pattern of a readiness probe works: a service that
answers `503` until it is finished now counts as unready. With that ADR-0080's
effect — the resolution — really resolves on readiness and not on "binds".
Zero new crates, no runtime in the `setns` thread, and the ordering condition
from ADR-0076 stays unchanged.

**Negative.** A second attribute in the schema, that is, a way to set it
wrongly — a `path` the service does not know makes the instance
**permanently unready** and takes it out of resolution. Visible in
`tg_workload_ready`, but it is one line of XML with a hard consequence.

And the probe is one call more that the workload sees: it now writes
something where it previously only connected. A server that logs every
connection gets one line per pass — that already applied to the connect.

**What `2xx` does not achieve:** a service that answers `200` to everything is
thereby ready, even if its dependencies are missing. What is checked behind
the path is decided by the workload — and that is as it should be: this system
does not know what "ready" means for it.

## Related ADRs

- **ADR-0080** gets its open point answered; determinations 1 through 8 stay
  unchanged, `path` is a refinement of determination 3.
- **ADR-0007** carries the answer to the TLS question: the sidecar terminates,
  so the workload listens in plaintext.
- **ADR-0076** carries the deadline, and it stays at one number.
- **ADR-0008** carries the schema process for the new attribute.
- **ADR-0089** stays untouched: readiness acts through resolution, not through
  the dependency gate — the stricter one too.
