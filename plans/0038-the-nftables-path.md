# ADR-0038: The nftables path — resolving the licence collision between ADR-0012 and ADR-0023

- **Status:** accepted
- **Date:** 2026-08-22
- **Deciders:** Core team
- **Technical context:** `tg-net` (the rule set), `tg-agent`, `deny.toml`,
  ADR-0003, ADR-0007, ADR-0012, ADR-0023, ADR-0025.

## Context and Problem Statement

ADR-0012 names as the mechanism for the rule set "the nftables netlink binding
(**C FFI** accepted within narrow bounds, encapsulated)". ADR-0023 fixes a
licence allowlist in `deny.toml` and justifies it verbatim: *"No GPL/AGPL: it
would infect the orchestrator itself."*

While building phase 9 it turns out that these two sentences exclude one
another. **Every** path that reaches nf_tables through netlink is copyleft — in
Rust as in C. The mechanism foreseen by ADR-0012 is not buildable under
ADR-0023's policy.

Per invariant 6 (CLAUDE.md), an `accepted` decision is changed with a new ADR
and not by a commit that picks whichever suits it.

## Decision Drivers

- **ADR-0023, the licence allowlist.** No GPL/AGPL in the dependency tree. That
  is not a preference but the condition under which the orchestrator itself can
  be licensed.
- **ADR-0012, the datapath in the kernel.** No eBPF, no kernel modules, no
  userspace packet copying. The control lies in userspace, the packets do not.
- **Invariant 1.** "Pure Rust" means a Rust codebase without Go, not FFI-free. C
  FFI is permitted within narrow, isolated bounds — so the licence problem does
  not arise from the FFI but from what lies behind it.
- **CLAUDE.md: self-contained, no foreign **daemons**.** A called program is not
  a daemon; ADR-0003 calls youki and crun in exactly that way.
- **The rule set is security-relevant** (deny by default per ADR-0025, the
  sidecar redirect per ADR-0007). Atomicity and verifiability weigh more than
  elegance of the call path.
- **Not on the hot path.** Rules change at the start and end of a container and
  on a policy change — not per packet. The cost of a call is a control-plane
  cost.
- **ADR-0023, exit strategy and concentration risk.** The chosen boundary must
  remain replaceable.

## Options Considered

All figures measured on 2026-08-22 on Fedora 44, `nft` 1.1.6, kernel 7.1.8.

- **Option A — `rustables` 0.8.8**, pure Rust, speaks netlink directly.
- **Option B — `nftnl` 0.9.4 + `mnl` 0.3.1** (Mullvad), Rust wrappers around
  `libnftnl` and `libmnl` — the FFI path foreseen by ADR-0012.
- **Option C — our own nf_tables netlink binding** in `tg-syscall`/`tg-net`.
- **Option D — `nftables` 0.6.3**: a typed Rust structure → JSON → the `nft`
  program as a **separate process**.

### Option A — pure Rust, and barred nonetheless

`rustables` is under **GPL-3.0-or-later**. `cargo deny check` fails, and rightly
so: the alternative would be an exception in `deny.toml`, i.e. deliberately
admitting strong copyleft into our own tree. That is exactly what the comment
there excludes.

The irony is notable and is not an argument: the only pure-Rust path is the one
most impossible in licence terms.

### Option B — the FFI path, and why it is the most dangerous

The Rust wrappers are cleanly licensed (MIT OR Apache-2.0). What they link is
not:

| Library | Licence (rpm) |
|---|---|
| `libnftnl` 1.3.1 | **GPL-2.0-or-later** |
| `libmnl` 1.0.5 | LGPL-2.1-or-later |

That linking actually happens stands in the manifest: `nftnl-sys` 0.6.4 carries
`links = "nftnl"`.

The decisive property of this path is the second one: **`cargo deny check` would
pass.** The tool reads crate metadata and does not know a C library's licence.
The policy from ADR-0023 would be violated, and invisibly so — the run would stay
green, the result would be GPL-2 code in the orchestrator's address space.

A violation the tool confirms is worse than one it reports. Option B is
therefore not merely rejected but the occasion for an open point of its own
further below.

### Option C — write it ourselves

The protocol is not copyrightable; a binding of our own would have no licence
problem. It would have a different one.

The effort lies not in tables and chains but in **encoding the expressions** —
and there a wrong byte becomes a rule that does something other than it says,
with no error message. For a deny-by-default rule set that is the worst
conceivable class of error. On top of that comes maintenance against a kernel
that keeps moving.

ADR-0032 already answered the same question once, when it was about the storage
engine: *"Do not write the storage engine ourselves."* The reason holds here
unchanged.

Option C stays as an **exit path**, not as today's choice.

### Option D — the process as the boundary

`nftables` 0.6.3 is MIT OR Apache-2.0 and creates no machine-code link to GPL
code: it builds a typed structure, serializes it to JSON and hands it to the
program `nft`, which runs as a **separate process**. Evidenced in `helper.rs`:
`Command::new("nft")`, argument `-j`.

That is the same relation ADR-0003 chose for the container runtime — youki and
crun are likewise foreign programs behind a documented interface. `nft`'s GPL-2
stays on its side of the `fork`.

The interface is documented and versioned: `libnftables-json(5)`, with
`json_schema_version` in the `metainfo` object of every output.

## Decision

Chosen: **Option D.** The rule set is built as a typed structure, serialized to
JSON and handed to the program `nft`. That makes the path licence-clean — and,
which counts at least as much, **demonstrably** licence-clean: `cargo deny check`
this time sees everything it has to see, because nothing hidden is linked.

Plus six determinations that make the path operable in the first place.

### 1. JSON, not script text

`nft` also reads its own scripting language. We do not write it.

A rule set that arises by string concatenation is an injection surface as soon
as anything flows into it from a definition — even just a workload name in a
comment. With a serializer that surface does not arise. The price is one more
schema; it is worth it.

### 2. One table of our own, and only that one

The agent owns `table inet tardigrade` and touches no other. **Never
`flush ruleset`** — that would take the host's firewall with it. On the build
host `table inet firewalld` lies next to ours; an orchestrator that locks the
host out while tidying up is an outage, not a bug.

The reconciliation runs as `delete table` + `table { … }` in **one** file, so
that no state without rules lies between deletion and rebuild.

### 3. One transaction per reconciliation, not per container

Measured, an `nft` call costs roughly **12 ms** (100 applications of a small
table in 1.19 s). Called per container that would be 1.2 s of pure `fork`/`exec`
for a hundred containers.

The agent therefore renders the **whole** table and applies it once. `nft -f` is
atomic — all or nothing — and that fits the reconcile model from ADR-0010: the
reconciliation is level-triggered, not event-driven.

### 4. `nft --check` before every application

`nft --check -f` checks without applying. That is a dry run one gets for free,
and it belongs before every application: a rule set `nft` rejects should do so
before the old table is deleted.

### 5. The `owner` flag stays unused — a measured loss

Since Linux 5.19 nf_tables has an `owner` flag: a table belongs to the netlink
socket that created it and is not modifiable by others. For a security-relevant
rule set that would be desirable.

Through a called program it is not available. Measured:

- **`flags owner` alone:** the table dies when `nft` exits — it is gone before
  the next command runs.
- **`flags owner,persist`:** the table survives, but ownership is given up in the
  process. A second process modifies it without complaint (`nft add chain …` →
  exit 0), and the table afterwards carries only `flags persist`.

The rule set is therefore **not** protectable against other writers on the host
along this path. That is the honest price of option D — and at the same time the
first argument that would one day justify option C.

### 6. `nft` is an operational precondition, and the agent says so early

At startup the agent checks that `nft` is present and which `json_schema_version`
it reports; an unknown version is rejected, not guessed. That follows the runtime
search from ADR-0003 and its ordering rule from the wiring: missing tools stand
out at startup, not at the first container.

## Consequences

**Positive**

- Licence-clean and **visibly** licence-clean. No `*-sys` crate with copyleft
  behind it that `cargo deny` cannot see.
- No C in our own address space. Against option B that strengthens invariant 2:
  there is no FFI boundary to be reviewed.
- The interface is documented (`libnftables-json(5)`), versioned and maintained
  by a project older than this one.
- Atomic application and a dry run, both without home-grown code.
- The rule set is readable in exactly the form an operator would type. For
  verifiability per ADR-0020 that is worth more than a byte encoding only a tool
  understands.

**Negative / Costs**

- Roughly **12 ms** and one `fork` per reconciliation. Bearable because it is
  the control plane — but it forbids per-container calls.
- One more **runtime program** in the operational preconditions. Version drift of
  `nft` becomes an operational question.
- **Eight more crates** in the tree, six of them (`schemars`,
  `schemars_derive`, `serde_derive_internals`, `dyn-clone`, `ref-cast`,
  `ref-cast-impl`) solely for a JSON schema generation that never runs.
- The **`owner` flag** is out of reach (see determination 5).

**Risks & Open Points**

- **`cargo deny` sees no C licences.** The finding outlives this decision: every
  future `*-sys` crate can bring copyleft in invisibly. What remains to be
  decided — as a supplement to ADR-0023 — is whether a check for `links` keys
  belongs in the pipeline. That is this ADR's more general lesson and weighs
  more than the nftables question itself.
- **The six dead crates.** Should their weight ever become noticeable, our own
  serde types for the needed subset of the schema are the way out. Not today: a
  maintained model of a security-relevant schema is worth more than six
  build-time crates.
- **Exit path:** option C, should the process boundary become untenable — the
  most likely occasion is the `owner` flag.
- **Rule scaling** stays open as noted in ADR-0012: sets and maps instead of
  individual rules, otherwise the rule set explodes with the number of
  workloads. Belongs in phase 9b.
- ~~Whether `nft` ships in a minimal agent image or comes from the host is a
  packaging question and is to be answered in phase 9b.~~ — **done:** 9b — `nft`
  comes from the host, as noted in the operations manual.

## Related ADRs

- **Supersedes exactly one sentence in ADR-0012:** the mechanism "nftables
  netlink binding (C FFI …)". Everything else about ADR-0012 — kernel datapath,
  veth, bridge, no eBPF, the WireGuard underlay, the redirect to the sidecar —
  stays valid unchanged.
- Depends on: ADR-0023 (licence policy), ADR-0003 (precedent: a foreign program
  as a separate process).
- Affects: ADR-0007 (the redirect), ADR-0025 (deny by default), ADR-0020
  (verifiability of the rule set).
