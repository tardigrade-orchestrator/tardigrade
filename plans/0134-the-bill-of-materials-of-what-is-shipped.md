# ADR-0134: The Bill of Materials of What Is Shipped

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0023 (supply-chain governance: SBOM as a build artifact),
  ADR-0030 (`cargo vet` "not yet set up"), ADR-0026 (vendoring as an answer to a
  finding), ADR-0020 (what an auditor wants to see)

## Context and Problem Statement

ADR-0023 names as its first deliverable **SBOM generation as a build artifact
(CycloneDX)**, and ADR-0030 notes that `cargo vet` is "sensible independently of
this decision and not yet set up".

### The measurement

The gate (`cargo xtask ci`) runs `fmt`, `clippy`, `test`, `doc` and
`cargo deny check`. **No bill of materials, no `cargo vet`, no
`cargo-auditable`** — the three tools are not even installed:

```text
$ which cargo-cyclonedx cargo-vet cargo-auditable
no cargo-cyclonedx … no cargo-vet … no cargo-auditable
```

What exists instead does carry: `cargo deny check` (licences, advisories, bans,
sources) in the gate, `Cargo.lock` checked in, and vendoring where a finding
demanded it (ADR-0026). What is missing is the answer to the one question an
auditor asks first: **what exactly do you ship?**

### And the obvious answer would be wrong

```text
cargo metadata                       493 packages
of those shipped (normal, Linux)     386   [see the correction to determination 3]
   tgd 311 · tg-agent 330 · tgctl 369 · tg-proxy 244
```

`cargo metadata` counts development and build dependencies too, plus packages
for foreign platforms. Whoever reports this number reports **107 packages as
shipped that are not** — among them the test harness. A bill of materials that
names too much is just as wrong as one that names too little; it is merely the
less conspicuous sort.

**And the obvious counter-check is not right either.** `cargo tree -p tgd -e
normal` says **269** instead of 311: it resolves the features for this one
package, while a build of the workspace **unifies** them. What is shipped is
what the workspace build produces; the smaller number would apply only to a
`cargo build -p tgd` on its own. Here too the error goes in the dangerous
direction.

### The first finding the number already delivers

**`tgctl` carries more than `tgd`.** Looked into why:

```text
tgctl -> openraft: yes
tgctl -> redb:     yes
```

369 against 311.

The CLI links `tgd` and `tg-consensus` (for `tgd::admin`) and thereby drags the
consensus core along with the storage engine. This tree has already decided the
same layering question once, and the other way round — `tg_identity::control`
deliberately does **not** lie in `tgd`:

> if the client lay there, `tg-agent` would depend on the consensus core and
> link `openraft` and `redb` in order to fetch a certificate. That is not a
> question of size but of layering.

For `tgctl` the same sentence applies, and there it was never applied. That is
the kind of question a bill of materials poses before a human does.

## Decision Drivers

- **DORA asks about third-party risk**, and the bill of materials is the form in
  which one answers that.
- **No second toolchain** (ADR-0023, and `tg-wire`'s justification against
  protobuf): an artifact whose generation presupposes a tool nobody has
  installed does not come into being.
- **An artifact that never looks the same twice is not read** — the promise from
  11c ("the same seed produces the same report").
- **What does not run in the gate does not run** (the comment about `cargo doc`
  in `xtask::ci`).

## Options Considered

- **A — call `cargo-cyclonedx`.** One tool more as an operational prerequisite,
  for a task that falls out of `cargo metadata` in a hundred lines.
- **B — write it ourselves, from `cargo metadata`**, in the standard format.
- **C — not at all**, and strike ADR-0023's deliverable.
- **D — add `cargo vet`**, that is, an attestation per crate.

Chosen is **B**; `cargo vet` is rejected (determination 6).

### Determination 1 — the bill of materials arises from `cargo metadata`

`cargo xtask sbom` reads `cargo metadata --locked` and writes CycloneDX 1.5 as
JSON. No additional tool, no additional dependency — the same choice and the
same justification as with our own JSON codec (`tg-wire`): for a format we write
and do not read, a generator is a lot of apparatus.

The **format** is nevertheless the ecosystem's. One of our own would be a file
only our tools read — and a bill of materials is read by an auditor.

### Determination 2 — one file, one graph

`docs/sbom.cdx.json`: the **union** of the components over all four shipping
units (`tgd`, `tg-agent`, `tgctl`, `tg-proxy`) — once.

The graph is the **real** one: per component its direct normal dependencies, as
CycloneDX means it. "What is in `tgd`" is thereby a traversal and not a fourth
copy of the same 386 lines.

### Determination 3 — only the **normal** closure, for the platform of delivery

Dev and build dependencies stay out: `xtask`, the test harness and `tests/dst`
are not shipped. The difference goes in the dangerous direction — a list that is
too large looks like diligence.

> **Correction after the build: there are three filters, not two.** This
> determination names edge kind and platform and has thereby not yet described
> the closure. `cargo metadata` also lists in `resolve.nodes[].deps`
> **optional dependencies that no feature activates** — and the bill of
> materials therefore named **28 packages too many** (387 instead of 359):
> `rust_decimal` brought `borsh` and `rkyv` along, `rkyv` then `bitvec` and
> `uuid`, `hashbrown` its `ahash`. None of it is built, none of it linked.
>
> It stood out during the build of **ADR-0142**: `cargo tree` did not show
> `quinn` before the build, the bill of materials had long listed it — via
> `reqwest`'s unactivated HTTP/3 feature. That ADR noted it as a finding
> against this one; here it is fixed.
>
> The third filter holds a package's activated features against its feature
> table: the implicit feature, `dep:<key>` and `<key>/<feature>` switch it on,
> `<key>?/<feature>` expressly not. Cross-checked against
> `cargo tree --edges normal` per shipping unit, on name **and** version:
> **359 against 359, congruent in both directions.** With that the number in
> this determination stands correctly too: 433 platform-filtered against 359
> shipped.
>
> `--check` would never have caught that: it compares the file with what the
> same code produces. A filter that lets too much through agrees with itself.
> The witness against it now names **names** — `borsh`, `rkyv`, `bitvec`,
> `ahash`, `toml_edit` — and the feature logic has eight of its own.

The platform is **explicit** (`x86_64-unknown-linux-gnu`) and not that of the
machine: otherwise the same tree would yield two bills of materials on two
machines, and determination 5 would be a statement about the machine instead of
about the delivery.

The tools that are **called** in operation (`nft`, `losetup`, `cryptsetup`,
youki/crun) do not stand in it: they are not linked but executed (ADR-0038,
ADR-0003). Where they belong is the operations manual, and there they stand.

### Determination 4 — undated and sorted

No `timestamp`, no `serialNumber`, components sorted by name and version. Two
runs yield the same file.

That is the condition for determination 5 to be possible at all — and the same
honesty as with the DST report: a timestamp would turn a missing value into one
that differs every time.

### Determination 5 — checked in, and checked in the gate against drift

`cargo xtask sbom` writes, `cargo xtask sbom --check` compares, and `ci()` runs
the comparison. The same construction as `codegen --check` and `proto --check`,
and for the same reason: a dependency that is added should stand in the **diff**
of a pull request and not in an artifact somebody produces afterwards.

### Determination 6 — `cargo vet` is rejected, not deferred

It is an attestation about **humans**, not about tools: somebody reads a crate's
code and signs. For 386 crates that is a staffing question, and an attestation
nobody carries out is worse than none — it looks like a statement.

What is upheld instead stands in ADR-0023 and is built: `cargo deny` in the gate
(licences, advisories, bans, sources), `Cargo.lock` checked in, vendoring where
a finding demands it (ADR-0026) — and from here the bill of materials. Whoever
wants to **reuse** foreign audits imports them; that is an operations decision
and does not need this ADR.

The note from ADR-0030 is thereby answered instead of passed on.

## Consequences

**Positive**

- **The question "what do you ship" has an answer**, and one per binary.
- **A dependency that is added stands in the diff.** Until now one saw it only
  in `Cargo.lock`, and there stands everything that is never shipped too.
- **The first finding is already here** (`tgctl` carries the consensus core) and
  without the number nobody had noticed it.

**Negative / costs**

- **A file of around 230 KiB in the repo** that changes at every dependency
  change. That is the purpose; sorted and undated, the diff stays readable.
- **A writer of our own for a foreign format.** If CycloneDX changes its
  version, we change with it. The extent we use is small and stable
  (components, licences, `purl`, dependency graph).
- **The gate gets one step longer.**

**Risks & open points**

- ~~**`tgctl` carries `openraft` and `redb`**, because the admin protocol's
  types lie in `tgd`.~~ — **built and re-measured: ADR-0135**, and the
  justification was wrong. The layering violation existed, it is fixed — and it
  cost **one** crate: 369 → 368. The 125 crates it is really about hang on two
  **capabilities** of `tgctl`: `audit export` reads a Raft log (61) and `apply`
  runs a local pass (57). Whether they stay there is a product question.
- **The licence statement comes from the crate's manifest**, not from its
  `LICENSE` file. `cargo deny` checks the same source; whoever wants more needs
  a scanner, and that is option A.
- ~~**Our own crates carry no licence statement** and appear as `NOASSERTION` —
  fourteen of 386. That is honest and nevertheless a gap: which licence this
  product carries is a decision that would have to stand in the workspace
  manifest and stands nowhere.~~ — **decided and built: ADR-0139.** Apache-2.0,
  in the workspace manifest, with the text in the root. Latterly there were
  fifteen; now there are none.
- ~~**Reproducible builds** from ADR-0023 are still not substantiated. The bill
  of materials is the precondition for it and not the proof.~~ — **measured and
  decided: ADR-0138**, and the sentence was too friendly: it was not the proof
  that was missing, it was the property. Source path, target directory and clock
  are without consequence, the **`CARGO_HOME`** is not — 2355 absolute paths of
  the build machine stand in the four binaries. They come from the dependencies;
  our own crates contribute zero.
- **A `cargo-auditable` imprint in the binary** would be the supplement that
  binds a bill of materials to the shipped artifact rather than to the
  repository. One tool more, and not decided.

## Related ADRs

- **Redeems the first deliverable from ADR-0023** (SBOM as a build artifact).
- **Answers the open point from ADR-0030** (`cargo vet`) — with a rejection and
  with what is upheld instead.
- **Follows the same choice as:** `tg-wire` (write a format ourselves instead of
  a second toolchain) and **ADR-0026** (vendoring as an answer to a finding, not
  as a stance).
- **Inherits the promise from phase 11c:** the same artifact at every run.
