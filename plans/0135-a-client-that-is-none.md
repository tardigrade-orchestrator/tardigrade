# ADR-0135: A Client That Is None

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0134 (the bill of materials and its first finding),
  ADR-0044 (the admin service), ADR-0037 (the same layering question, decided
  correctly there), ADR-0097/0108 (the signer port), ADR-0023 (the crates of a
  delivery)

## Context and Problem Statement

ADR-0134 built the bill of materials, and its first finding read:

> **`tgctl` carries more than `tgd`** — 369 against 311 crates, `openraft` and
> `redb` included. The CLI links `tgd` and `tg-consensus` for `tgd::admin`.

The diagnosis was right and the **cause** was not.

### The measurement after the rebuild

Four relocations later — the command set under consensus, the admin protocol
into a crate of its own, the seat list to identity, the archive's read path to
telemetry — `tgctl` links neither `tgd` nor `tgd::admin`:

```text
tgd 312 · tg-agent 330 · tgctl 368 · tg-proxy 244
```

**368 against 369.** The whole rebuild saved **one** crate.

### Why

Because `tgctl` is not a client but three programs in one:

| What it does | What it costs |
|---|---|
| call the admin service | what `tg-admin` brings along — little |
| `tgctl audit export`: read a **Raft log** | **61 crates** (`openraft`, `redb`, and with them `clap`, `rkyv`, `borsh`, `bitvec`, `rand`, `rust_decimal` …) |
| `tgctl apply`: run a **local pass** (phase 2) | **57 crates** (`tg-runtime`: `oci-client`, `reqwest`, `quinn`, `jsonwebtoken`, `tar`, `flate2` …) |

Without both it would be **243** — in the order of magnitude of the sidecar
(244).

The admin protocol was never the weight. It was the **layer**, and that was
indeed wrong: a client linked a server. That is fixed, and it costs nothing
because the two capabilities beneath it stay.

### What the rebuild was worth nevertheless

- **The rule now applies everywhere.** ADR-0037 wrote it out — "if the client
  lay there, `tg-agent` would depend on the consensus core … not a question of
  size but of layering" — and at four places it was not applied.
- **A client that links a server inherits its rebuild.** Every change to the
  scheduler, to the session or to the SPIFFE server recompiled `tgctl`.
- **The dependency now has a reason per entry**, and it stands in the table
  above. Previously it was a lump sum.

## Decision Drivers

- **A client does not link a server** (ADR-0037).
- **A bill of materials is worth only as much as the question it triggers**
  (ADR-0134) — and the first answer to it was incomplete.
- **A relocation that saves nothing must nevertheless be right**, but it must
  not be booked as a saving.

## Options Considered

- **A — separate only the admin service.** Fixes the most visible violation and
  leaves three more standing.
- **B — all four relocations.** The rule then applies everywhere.
- **C — additionally remove `audit export` and `apply` from `tgctl`.** That
  saves 125 crates — and takes two tools from an operator.

Chosen is **B**. **C** is a product decision and stands as an open point.

### Determination 1 — the command set lies under consensus

`tg_model::command`. It depends only on `serde` and on the domain — measured, it
always did. Whoever **formulates** a command should not link a storage engine
for it.

`tg_consensus::command` stays as a re-export: one source, the paths under which
the consensus core has known it since phase 5a. The same applies to `NodeId`.

**`Sealed` moves along**, as pure data (`tg_model::secrets`): the command set
carries a sealed value, and `tg-identity` knows `tg-model` — the other way round
it would be a circle. The **procedure** stays where `ring` is; the length of the
tag is computed from here by `tg_identity::secrets::SealedExt`, an extension in
the construction of `tg_defs::WorkloadExt`.

### Determination 2 — protocol and client in `tg-admin`, the service in `tgd`

The types, the paths and `AdminClient` lie in the new crate. `AdminService` and
its branches stay in `tgd`: they need Raft and the projection, they **are** the
server.

The access rules stay there too — they interrogate an incoming request, and only
a server does that.

### Determination 3 — the seat list belongs to identity

`Seats` and `Repair` (ADR-0097, ADR-0108) lie in `tg_identity::seats`. The
comment in `tgd` expressly named the reason for the opposite — "`tgctl` calls
it instead of building the path a second time (ADR-0023 counts the crates of a
shipping binary)". The computation was right, the place wrong: the credential on
the signer port is the **node key**, and that belongs there.

Moving with them are `read_leaf` and the placeholder `SNI` of the cluster
transports: three clients name it, and one of them is `tgctl`.

### Determination 4 — the archive's read path lies with the chain

`read`, `verify`, `verify_chain`, `segments`, `footprint` and their errors lie
in `tg_telemetry::audit`, where the chain has lain since phase 11a. A
`tgctl audit` that recomputes a file should not link the consensus core for it.

**Writer and export stay in consensus**: the one hangs on the apply path, the
other needs `openraft` to open the log at all.

### Determination 5 — `tgctl` stays more than a client, and that is named

`audit export` reads a Raft log, `apply` runs a local pass. Those are the two
reasons for 125 of the 368 crates, and both are **capabilities** an operator
has, not layering violations.

Striking them would be a decision about the product and not about the
architecture. It stands as an open point below — with the number it would be
about.

### Determination 6 — no re-export is removed

`tg_consensus::Command`, `tgd::admin::*`, `tgd::signer::Seats` stay valid paths.
They are **one** source under several names; removing them would be a rebuild at
every caller for nothing.

## Consequences

**Positive**

- **No client links a server any more.** The rule from ADR-0037 applies at all
  four places.
- **`tgctl` is no longer recompiled when the scheduler changes.**
- **The finding from ADR-0134 is corrected** — with a measurement, not with an
  opinion.

**Negative / costs**

- **One crate more in the tree** (`tg-admin`); the bill of materials counts 387
  instead of 386.
- **The rebuild saved one crate.** Whoever had sold it as a diet would have been
  refuted; it stands here as what it is.
- **Four re-exports more.** They cost nothing at runtime and one line of
  attention when reading.

**Risks & open points**

- ~~**Whether `tgctl audit export` stays there.**~~ — **decided: ADR-0137.** It
  has become a one-shot mode of `tgd`; the CLI carries 307 instead of 368 crates
  and neither `openraft` nor `redb`. Operationally nothing changes: the
  obligation to stop comes from `redb`, not from the binary. And the confusion
  that stood out in the process stands there: **inspecting** (`tgctl audit`)
  stops nothing — only the export touches the log.
- **Whether `tgctl apply` stays there.** The single-node path from phase 2 is
  built, checked and named in that phase's acceptance. It costs 57 crates, among
  them an HTTP and a QUIC stack.
- **`tg-identity` now links a gRPC client** (`tokio-rustls`, `tower`,
  `hyper-util`) in the shipping path instead of only in the test harness. They
  lay in each of the four binaries anyway; what is new is the **place**, not the
  package.

## Related ADRs

- **Corrects the finding from ADR-0134** and closes the open point it named.
- **Applies:** **ADR-0037** (the layering question, decided correctly there) and
  **ADR-0023** (the crates of a delivery).
- **Touches:** **ADR-0044** (the admin service keeps its server),
  **ADR-0097/0108** (the signer port), **ADR-0020** (the archive's read path).
