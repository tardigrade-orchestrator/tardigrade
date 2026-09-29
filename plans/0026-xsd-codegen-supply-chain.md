# ADR-0026: XSD Codegen — the supply chain of the definition path

- **Status:** accepted
- **Date:** 2026-08-19
- **Deciders:** Core team
- **Technical context:** `tg-defs`, `xtask codegen`, `schema/`
- **Supersedes:** ADR-0008 (the supply-chain part only; the format decision
  XML+XSD and the codegen approach stand — see "Decision")

## Context and Problem Statement

ADR-0008 chose XML+XSD as the definition format and `xsd-parser` as the codegen.
During the phase 1 implementation `cargo deny` reported two RUSTSEC advisories
on the definition ingest path:

| ID | Content |
|----|---------|
| RUSTSEC-2026-0194 | quadratic runtime in the duplicate-attribute check |
| RUSTSEC-2026-0195 | unbounded namespace allocation in `NsReader` → OOM DoS |

Both are fixed in `quick-xml >= 0.41.0`. The path is unavoidable:
`xsd-parser-types::SliceReader` itself builds on `NsReader`, and
`xsd-parser 1.5.2` (last release 2026-03-25, nothing since) pins
`quick-xml = "0.38"`. 0.41 is semver-incompatible, Cargo cannot resolve that.

The definition of done from `CLAUDE.md` (`cargo deny check` green) therefore
stands against the tool choice from ADR-0008. One of the two has to give way.

## Decision Drivers

- **DORA/REMIT:** an unpatched CVE on the configuration ingest path is not
  tenable without a documented risk acceptance (ADR-0023).
- **The actual purpose of XSD** is schema strictness (ADR-0008). A solution that
  merely documents facets instead of enforcing them throws away the reason for
  XML over YAML.
- **Compile-time type safety** was the core of ADR-0008: definitions should
  arrive typed, not as loose DOM trees.
- **Concentration risk and an exit path** must be named (ADR-0023).
- Pure Rust, no Go.

## Options Considered

- **A: vendor `xsd-parser-types`, lift `quick-xml` to 0.41.** The runtime part of
  the codegen comes under our own control, the generator stays upstream.
- **B: switch to `uppsala` (0.9.0).** Pure Rust, **zero dependencies**,
  BSD-2-Clause, XSD validation at runtime. But it provides no codegen — types
  would have to be hand-written and validated at runtime.
- **C: switch to `xmloxide` (0.5.0).** A pure-Rust reimplementation of libxml2,
  MIT, very active. It replaces the libxml2 FFI fallback considered in ADR-0008
  with pure Rust — but again only validation, no codegen.
- **D: a time-limited waiver in `deny.toml`.** Rationale: definitions come from
  authenticated operators through `tgctl`/SPIFFE mTLS (ADR-0018), not from
  untrusted input.
- **E: wait for upstream.** Blocks phase 1 indefinitely.

## The measurement (instead of an estimate)

Option A was checked empirically before this decision, because its cost was the
contested point. The result:

```diff
--- xsd-parser-types-0.2.1/Cargo.toml
+++ vendored/xsd-parser-types/Cargo.toml
@@ -83 +83 @@
-version = "0.38"
+version = "0.41"
```

`xsd-parser-types` **and** `xsd-parser` build cleanly with that —
**zero source changes**. Both need the change: `xsd-parser` has a direct
`quick-xml` dependency of its own and exchanges `Event` values with
`xsd-parser-types`; if the versions differ, the build breaks with type
conflicts. So two patched manifest lines, and nothing else. The real
`quick-xml` surface of `xsd-parser-types` comprises five symbols (`Error`,
`events::Event`, `name::*`, `NsReader::resolve*`, `Serializer`), which are
unchanged between 0.38 and 0.41.

That makes A not a fork but a version bump that upstream has merely not
published yet — and a trivially upstreamable patch.

## Decision

Chosen: **Option A**, supplemented by an upstream contribution.

1. `xsd-parser-types` is vendored under `third-party/xsd-parser-types/`, with
   the one changed line and a `PATCH.md` recording the occasion, the diff and
   the exit condition. Wired in through `[patch.crates-io]`.
2. `xsd-parser` (the generator) is vendored for the same reason and with the
   same one-line patch. It does **not** inherit `quick-xml` through the patch of
   the types crate but depends on it directly; without the second patch the
   `Event` types collide. It still runs exclusively in `xtask` and enters no
   shipped binary.
3. `tg-defs` lifts its direct `quick-xml` dependency to 0.41.
4. An issue/PR for the bump is filed with Bergmann89/xsd-parser.
5. **Exit:** as soon as upstream publishes a release with `quick-xml >= 0.41`,
   `[patch.crates-io]` goes away and the vendoring is deleted outright.

Justified against the drivers:

- The advisories disappear from the graph — **no waiver**, `cargo deny` stays
  sharp (this rejects D).
- Compile-time type safety and enforced facets are fully preserved; all the work
  from phase 1 (schema, generated code, loader, 19 fixtures) stays valid (this
  rejects B and C).
- B and C are both **0.x** — exactly the maturity objections with which ADR-0008
  rejected `fastxml`. Trading a known CVE fixable in one line for unproven 0.x
  libraries at the source of truth makes the risk worse.
- Phase 1 stays unblocked (this rejects E).

`uppsala` is noted as a **candidate to watch**: zero dependencies and pure Rust
are attractive for ADR-0023. Once it reaches 1.0, an additional runtime
validation pass against the XSD should be considered — as defence in depth, not
as a replacement for the codegen.

## Consequences

**Positive**
- An ingest path with no known vulnerability, and no waiver.
- Vendoring is explicitly foreseen by ADR-0023 and additionally decouples the
  build from registry availability.
- The patch is one line per crate — review and maintenance are negligible.

**Negative / Costs**
- Two vendored third-party crates in the repo (~3.1 MB) that have to be
  re-checked on every upstream release.
- `xsd-parser`'s upstream test suite (51 MB) is thinned out in the process: only
  the ~410 KB that the source pulls into doc comments through `include_str!` are
  kept. The vendored copy is therefore no longer byte-identical with upstream;
  the comparison runs with `--exclude=tests`. Documented in
  `third-party/xsd-parser/PATCH.md`.
- `[patch.crates-io]` applies workspace-wide; that has to be kept in mind when
  adding further XML crates.

**Risks & Open Points**
- `xsd-parser` is a one-person project with no release for five months. That is
  the real concentration risk, not `quick-xml`. The exit path per ADR-0023: the
  generated code is checked in and self-supporting — if the generator dies,
  `tg-defs` keeps working; only regeneration would have to be replaced.
- ~~Whether `quick-xml` 0.41 parses semantically identically is covered by the
  existing fixture suite; if anything stands out, add fixtures.~~ — **done:** the
  fixture suite covers it, nothing stood out.

## Related ADRs

- Supersedes the supply-chain part of: ADR-0008.
- Depends on: ADR-0023 (vendoring, exit strategy), ADR-0018 (the threat model of
  the ingest path).
- Affects: ADR-0004 (schema mapping), ADR-0009 (edges).
