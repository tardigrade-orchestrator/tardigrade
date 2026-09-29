# ADR-0008: Definition Format XML + XSD (via Codegen)

- **Status:** accepted — the codegen approach is decided; the supply-chain part
  is superseded by ADR-0026; the XSD subset is fixed in `schema/README.md`
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

Workloads, dependencies and policies are defined in XML, validated against an
XSD. To be settled: how XSD is validated in a pure-Rust stack and turned into
typed structures, and how those structures map onto SurrealDB (ADR-0004).

## Decision Drivers

- Pure Rust.
- Strong schema validation (that is, after all, the reason for XSD instead of YAML).
- Definitions should arrive in the code type-safe, not as loose DOM trees.

## Options Considered

- **A: build-time codegen with `xsd-parser`.** Generates typed Rust structures
  from the XSD including schema-based validation (facets, pattern anchoring).
  Validation happens type-driven during (de)serialization.
- **B: runtime XSD validation with `fastxml`.** Pure Rust, XPath plus XSD,
  streaming. But v0.x, "not recommended for business-critical systems" — too
  early for the source of truth.
- **C: a `libxml2` binding (the `libxml` crate) for XSD validation.** Mature, but
  C FFI (violates purity) and, per its documentation, untested in a
  multithreaded context.
- **D: loose parsing (`quick-xml`/`serde`) without real XSD semantics.** Discards
  the very purpose of XSD.

## Decision

Chosen: **Option A (codegen with `xsd-parser`)**, complemented by `fastxml` as
an optional extra runtime check once it matures.

_Note after the FFI clarification:_ since C FFI is permitted within narrow
bounds (no Go), `libxml2` would now also be admissible for runtime XSD
validation. Codegen nevertheless stays preferred (compile-time type safety, no
runtime C dependency); libxml only as a deliberately encapsulated fallback
should the required XSD subset exceed `xsd-parser`.

- The XSD lives versioned in the repo (`schema/*.xsd`); codegen in `build.rs`/as
  a vendored module produces the definition structures.
- Reading in: XML → generated structures (validation including facets along the way).
- Persistence: generated structures → SurrealDB records; dependency elements
  become `RELATE` edges (ADR-0009).
- Container start: the same structures → OCI `config.json` (ADR-0003).

## Consequences

**Positive**
- Compile-time safety: invalid definitions fail early and typed.
- No C FFI break; full Rust purity on the definition path.
- XSD changes force code changes → no silent schema drift.

**Negative / Costs**
- A codegen toolchain in the build; XSD constructs that `xsd-parser` does not
  (yet) cover have to be fenced off (fix a "supported XSD subset").
- XML as UX is more verbose than YAML — a deliberate trade-off for schema strictness.

**Risks & Open Points**
- ~~Check `xsd-parser`'s feature coverage against our planned schema before the
  schema is final (e.g. `xs:key`/`xs:keyref`, substitution groups).~~ — **done:**
  phase 1, `schema/README.md`; supply chain in ADR-0026.
- ~~Document the mapping rules XSD types → SurrealDB fields.~~ — **done:** moot
  since ADR-0030 — there are no SurrealDB fields any more.

## Related ADRs

- Feeds: ADR-0004 (schema), ADR-0003 (config.json), ADR-0009 (edges).
- **Partly superseded by: ADR-0026.** The format (XML+XSD) and the codegen
  approach stay; how `xsd-parser` is obtained is re-regulated by ADR-0026 after
  RUSTSEC-2026-0194/-0195 surfaced on the ingest path.
