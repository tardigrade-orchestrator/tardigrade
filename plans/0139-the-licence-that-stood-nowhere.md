# ADR-0139: The Licence That Stood Nowhere

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0134 (the bill of materials and its second open point),
  ADR-0023 (supply-chain governance), ADR-0038/0003/0039 (called instead of
  linked), ADR-0026 (vendored foreign text)

## Context and Problem Statement

ADR-0134 built the bill of materials, and it delivered two findings. The first
led via ADR-0135 and ADR-0137 to the right layering. The second stood untouched
ever since:

> **Our own crates carry no licence statement** and appear as `NOASSERTION` —
> fourteen of 386. That is honest and nevertheless a gap: which licence this
> product carries is a decision that would have to stand in the workspace
> manifest and stands nowhere.

By now there were **fifteen** (`tg-admin` was added with ADR-0135). An auditor
who wants to see third-party risk under DORA reads the bill of materials first
— and found there fifteen components without a licence that belong to the
manufacturer itself.

### The measurement

The shipping closure, 372 foreign components, 26 distinct expressions:

```text
172  MIT OR Apache-2.0       18  Unicode-3.0      3  ISC
 96  MIT                     18  Apache-2.0       3  BSD-3-Clause
 23  Apache-2.0 OR MIT       10  MIT/Apache-2.0   5  Zlib
      plus 0BSD, BSL-1.0, MIT-0, Unlicense, BSD-2-Clause, LLVM-exception
```

**No GPL, no LGPL, no AGPL — and not even MPL**, although `deny.toml` expressly
permits it. There is no copyleft core against which a choice could chafe; the
question is therefore one of intent and not of compatibility.

Four places at which it could nevertheless have jammed, each looked into:

- **The dual licences** (around 210 components) resolve by themselves: we take
  the Apache-2.0 branch.
- **MIT-only (96)** is no conflict but an obligation to pass the notices on. It
  exists today already.
- **`NOTICE` files:** measured, **none** of the 372 components brings one along.
  Apache-2.0 §4(d) demands passing it on only if there is one.
- **The vendored foreign text fits:** `xsd-parser` and `xsd-parser-types` are
  MIT (ADR-0026), `workload.proto` is Apache-2.0 (SPIFFE, ADR-0035). The stub
  generated from it is therefore a derivation of Apache-2.0 text.

### The GPL programs are processes

`nft`, `losetup`, `mkfs.ext4`, `resize2fs`, `cryptsetup` and `crun` are under
GPL-2 and are **called, not linked** — the boundary ADR-0003, ADR-0038 and
ADR-0039 drew. It holds unchanged under Apache-2.0, and that is exactly why
these programs stand in the operations manual and not in the bill of materials.
`youki` is itself Apache-2.0.

## Decision Drivers

- **A bill of materials that lists the manufacturer as `NOASSERTION` does not
  answer the question it exists for** (ADR-0134).
- **Patent clarity.** For a REMIT/DORA product an explicit patent licence is
  worth more than MIT's silence.
- **No new obligation for consumers.** What embeds this product should not be
  forced into a licence choice by it.
- **The rule must apply by itself.** A licence statement repeated per crate is
  one that is missing at the next crate.

## Options Considered

- **A — Apache-2.0.** Explicit patent licence with a termination clause,
  attribution and modification notices, `NOTICE` passing-on (moot here).
- **B — MIT.** Shorter, silent about patents.
- **C — `MIT OR Apache-2.0`**, the Rust-customary dual licence. Takes the
  question off both sides and is compatible with GPL-2.0-only.
- **D — proprietary / no statement.** Today's state, only said out loud.

Chosen is **A**.

### Determination 1 — Apache-2.0, in the workspace manifest

`license = "Apache-2.0"` stands in `[workspace.package]`, and every member
inherits it with `license.workspace = true` — the same form as `version`,
`edition` and `authors`. **One source, one place** (ADR-0069): a statement per
crate would be the same string seventeen times and forgotten at the eighteenth
crate.

### Determination 2 — the text is included

`LICENSE` in the root, the unabridged Apache-2.0 text. An identifier in the
manifest is not a text; §4(a) demands that every distribution contain a copy of
the licence.

The appendix ("Copyright [yyyy] [name of copyright owner]") stays **unfilled as
in the original** — it is expressly an instruction for whoever applies the
licence to a file, and not part of the licence. Who the rights holder is is not
an architecture question; it stands below as an open point.

### Determination 3 — no `NOTICE`

A `NOTICE` file is optional, and it is **contagious**: once it exists, everyone
who distributes must carry it along. For a product whose 372 foreign components
together bring **not a single one**, that would be an obligation we invent and
pass on to every consumer.

It is added when there is something to say, and not before.

### Determination 4 — the choice is guarded in the artifact, not in the manifest

Two witnesses on the **bill of materials**, because it is the answer that goes
outwards:

- **no component carries `NOASSERTION`** — for foreign crates
  `cargo deny check licenses` covers that anyway, our own only this witness
  sees;
- **`LICENSE` lies in the root and is the whole text** — an abridged version is
  no copy of the licence.

Measured against the defect they catch: take the line from a single crate and
the first goes red and **names the crate's name and the missing line**. Take the
statement from the workspace and `cargo` itself aborts — the stronger case, and
it costs nothing.

### Determination 5 — `deny.toml` stays as it is

`Apache-2.0` has stood in its allow list since phase 0. The choice changes
nothing about the supply-chain policy; it only answers the question that policy
had left open about ourselves.

## Consequences

**Positive**

- **The bill of materials has no blank left.** Zero `NOASSERTION` at 387
  components, measured.
- **Patent clarity**, and in both directions: whoever contributes grants the
  licence along; whoever litigates loses it.
- **The second and last open point from ADR-0134 is answered.**
- One file more in the repo and one line per manifest; otherwise it costs
  nothing.

**Negative / costs**

- **Apache-2.0 is not compatible with GPL-2.0-only** (with GPLv3 it is). For
  this product nothing collides — we link no GPL code — but nobody can take this
  code into a GPLv2-only project. That is a restriction downstream and the price
  of the patent clause.
- **The attribution and modification notices from §4(b)/(c)** apply from here to
  everyone who distributes. Without consequence for us, for a consumer one
  obligation more than with MIT.

**Risks & open points**

- ~~**Who the rights holder is** stands nowhere.~~ — **answered:
  `Copyright 2026 Dana Schlifka`**, and it stands in the **bill of materials**
  (`metadata.component.copyright`, beside the product's own licence). Not in
  the `LICENSE` appendix: that stays unfilled for the reason in determination 2,
  and it would be an instruction posing as a notice. Not as a header in 200
  source files: Apache-2.0 does not demand that, and a notice one maintains per
  file is one that goes stale per file.
  The bill of materials, by contrast, is the answer that goes outwards — and
  until now it answered the question for 372 foreign components and not at all
  for the product itself. In addition the root, where a human looks:
  `COPYRIGHT` and `README.md` **repeat** the statement, and a witness binds them
  verbatim to the bill of materials — three places are otherwise three
  opportunities to diverge (ADR-0069).
- **The licence statement still comes from the manifest**, not from a crate's
  `LICENSE` file (ADR-0134). Whoever wants more needs a scanner.
- **`publish = false` stays.** The choice is a statement about distribution, not
  about crates.io.
- **Option C (`MIT OR Apache-2.0`)** stays the way should the GPL-2.0-only
  incompatibility ever bother anyone. It is additive: a dual licence takes
  nothing from anyone that they already had under Apache-2.0.

## Related ADRs

- **Closes the second open point from ADR-0134** — and thereby its last.
- **Applies:** **ADR-0069** (one derivation, one place) for the inheritance in
  the workspace.
- **Touches:** **ADR-0023** (the allow list stays unchanged),
  **ADR-0026/0035** (vendored foreign text, MIT and Apache-2.0 respectively),
  **ADR-0003/0038/0039** (the GPL programs are processes and not libraries).
