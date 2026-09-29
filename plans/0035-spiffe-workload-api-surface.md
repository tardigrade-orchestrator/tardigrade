# ADR-0035: The surface of the workload API — our own protocol or the SPIFFE standard

- **Status:** accepted
- **Date:** 2026-08-22
- **Deciders:** Core team
- **Technical context:** `tg-identity` (the workload API socket), `tg-proxy`
  (the first consumer), `xtask` (codegen), ADR-0006, ADR-0007, ADR-0018.

## Context and Problem Statement

Phase 7a built the workload API socket through which a container fetches its
SVID and the trust bundle. It speaks **a JSON protocol of our own**. For exactly
this purpose the SPIFFE specification defines a standardized surface — the gRPC
service `SpiffeWorkloadAPI` over a Unix socket — and the ecosystem's client
libraries (`rust-spiffe`, `go-spiffe`, `java-spiffe`, `py-spiffe`) speak
exclusively that.

PLAN.md has kept the question open since 7a and schedules it **before phase 8**.
The reason is concrete, not formal: the sidecar from phase 8 is the **first
consumer** of the socket. Which surface it speaks is decided when it is written
— and it is the component that is most expensive to write twice.

The counterforce lies in phase 5c: there the Raft transport was deliberately
built **without** Protobuf, with its own JSON codec over `tonic`. The rationale
stands verbatim in `crates/tg-consensus/src/net/codec.rs` — and it bounds
itself:

> "For the **public** API from ADR-0018 that is a different question — it may
> speak Protobuf, and this codec does not stop it."

The decision of 5c was therefore never a prohibition but a statement about **a
traffic nobody third-party ever speaks**. The workload API is the opposite case:
it exists exclusively so that someone third-party speaks it.

## Decision Drivers

- **Interop is the purpose of SPIFFE.** ADR-0006 chooses SPIFFE *without* SPIRE
  — i.e. the specification without the reference implementation. What is left of
  that, if the interface is home-grown too, is a private PKI with SPIFFE-shaped
  URIs.
- **Transparency for third-party images** is ADR-0007's load-bearing
  justification for the sidecar in the first place.
- **No second toolchain** (ADR-0023, phase 5c) — the point that speaks against
  Protobuf and that had to be **measured** rather than asserted.
- **Concentration risk and an exit path** (ADR-0023, DORA): a standardized
  interface is an exit path. Whoever speaks it can swap this orchestrator for
  another SPIFFE issuer without touching the workloads.

## The measured part

The objection "a second toolchain" was checked, not estimated. The setup: the
specification's `workload.proto`, `protox` as the compiler, `tonic-prost-build`
as the generator.

| Question | Finding |
|---|---|
| Is `protoc` needed? | **No.** `protox` is a Protobuf compiler in pure Rust. On the machine where this was written no `protoc` is installed, and generation still ran through. |
| Is a build step needed? | **No.** The generator runs as an `xtask`, the result (575 lines) is checked in — the same pattern as `xtask codegen` for the XSD from phase 1. No `build.rs`, no generation at build time. The `spiffe` crate itself does the same: it has no `build.rs` and ships generated code. |
| What enters the tree permanently? | **Three crates:** `prost`, `prost-derive`, `tonic-prost`. Everything else Protobuf would otherwise bring is already in the tree via `tonic`. Measured against today's state: 266 crates → 269. |
| Licences | `prost` Apache-2.0, `prost-derive` Apache-2.0, `tonic-prost` MIT, `protox` MIT OR Apache-2.0 — all in the allowlist from `deny.toml`. |
| Can the `spiffe` crate be used as a server? | **No.** It generates only the client stub, and its `pb` module is `pub(crate)`. As a **client** it is usable, as a server it is not. |

The objection from phase 5c is therefore **not applicable** here. It targets
`protoc` in CI and a codegen step that CI has to check against drift. Both fall
away with a checked-in artefact generated from a file that the specification
freezes anyway.

What it still names correctly is a **second format**: the Raft log is JSON and
readable without our binary (ADR-0020), the workload API would be Protobuf and
is not. That is acceptable because the workload API is **not an audit
substrate** — it transmits no decision but a certificate, which travels in its
own standardized encoding anyway.

## Options Considered

- **A: stay with the JSON protocol.** No new tree, no codegen. The price is that
  the interface stays unusable for any third-party workload and that option C
  from ADR-0007 ("an SDK path for native workloads") is in fact open only to
  workloads that reimplement our home-grown protocol.
- **B: build the standardized surface, the X.509 part.** The service
  `SpiffeWorkloadAPI` with `FetchX509SVID` and `FetchX509Bundles`; the three JWT
  methods answer `UNIMPLEMENTED`. Generated code checked in, tooling in the
  `xtask`.
- **C: the standardized surface in full**, JWT SVID included.
- **D: both in parallel and permanently** — JSON for our own sidecar, Protobuf
  for foreigners.
- **E: defer with a trigger** — stay with JSON until a third-party workload turns
  up.

## Decision

Chosen: **Option B.**

**The service.** `tg-identity` offers the gRPC service `SpiffeWorkloadAPI` over
the Unix socket, with `FetchX509SVID` and `FetchX509Bundles`. Both are
**server-streaming** in the specification, and that is no formality: the stream
*is* the rotation mechanism. A client holds it open and gets the new SVID pushed
before expiry instead of polling. The JSON protocol from 7a cannot do that — it
is request/response — and the difference lands exactly where ADR-0014 chose the
tight profile with 15-minute SVIDs and 7-minute rotation.

**The three JWT methods answer `UNIMPLEMENTED`**, with a message referring to
ADR-0025: JWT SVID is explicitly deferred there as option C, not forgotten. A
method that does not exist should say so; one that does something halfway is
worse than none.

**The JSON protocol goes away.** Not for aesthetics, but because two surfaces
onto the same state are two paths on which an SVID goes out — and therefore two
places where the attestation from ADR-0006 has to be right. That is the kind of
duplicate path one does not want in a security component. The price is a rebuild
in `tg-identity`, and today it is small: the socket has **no** consumer yet,
because `tg-identity` is connected to no binary.

**From phase 8 the sidecar speaks the standard**, as a client through the
`spiffe` crate. That makes our own data plane the first proof that the surface
really is the standardized one — the same dogfooding argument with which
ADR-0018 runs the control plane over its own identity.

**Tooling.** `protox` and `tonic-prost-build` live in the `xtask`, not in the
workspace tree. `cargo xtask proto` generates, the artefact is checked in.
Generated are server **and** client — the latter solely for the tests: a foreign
client always sets the prescribed header and never calls the JWT methods, so it
cannot trigger the two rejection cases at all. The `workload.proto` is vendored
like `xsd-parser` in ADR-0026, with a provenance note.

**Rejected and why:**

- **A and E** confuse "not needed today" with "cheap later". The sidecar is the
  expensive part, and it is being written now. E additionally has a trigger that
  never fires: a third-party workload does not turn up if nothing can serve it.
- **C** builds JWT SVID, which ADR-0025 deferred. One does not repeal an ADR in
  passing.
- **D** keeps the double issuance path open permanently — see above.

## Consequences

**Positive**
- A third-party image with `go-spiffe`, `java-spiffe`, `py-spiffe` or
  `rust-spiffe` gets its identity without a code change. That is the promise on
  which ADR-0007 justified the sidecar, redeemed instead of merely asserted.
- Rotation becomes a **push** instead of polling, fitting the tight profile from
  ADR-0014.
- An exit path in the sense of ADR-0023 emerges: the workloads hang on a
  specification, not on this orchestrator.
- The interop can be **checked** against a foreign implementation, not just
  against our own.

**Negative / Costs**
- Three more crates and a second wire format in the project.
- A generated artefact in the repository that somebody has to maintain if the
  specification moves. It moves rarely; the note belongs on the file anyway.
- `tg-identity` rebuilds the socket, and the tests from 7a that hang on the JSON
  go with it.

**Risks & Open Points**
- ~~**Interop is only evidenced once a foreign client speaks it.** A test against
  our own server implementation proves only self-consistency. The `rust-spiffe`
  client is the nearest counterpart for that — foreign code that read the
  specification independently. That belongs in the acceptance of the cut that
  builds the socket.~~ — **done:** 7c — evidenced against `rust-spiffe`.
- ~~**The specification requires a security header** (`workload.spiffe.io: true`)
  that prevents a browser or a carelessly configured client from talking to the
  service. It is to be enforced, not merely accepted.~~ — **done:** 7c — the
  header is enforced.
- ~~**The attestation stays where it is.** `SO_PEERCRED` and the cgroup path
  (ADR-0006, phase 7a) hang on the socket connection, not on the protocol above
  it. The rebuild must not lose them — that is the only part of the rebuild with
  security weight.~~ — **done:** overtaken: ADR-0053, then ADR-0081 — the cgroup
  read goes away.
- ~~**Where the rebuild belongs** is a planning question.~~ **Decided:** as
  **phase 7c**, before phase 8. It is phase-7 work — it concerns the socket, not
  the data plane — and it belongs before the sidecar, so that the sidecar is
  built against the final surface from the start.

## Related ADRs

- Completes: ADR-0006 (the workload API surface was open there).
- Justified with: ADR-0007 (transparency for third-party images), ADR-0023
  (supply chain, exit path).
- Delimits: the codec decision from phase 5c applies to the Raft transport, not
  to the public surface — as it says there itself.
- Still defers: JWT SVID per ADR-0025 (option C).
- Vendoring pattern: ADR-0026.
