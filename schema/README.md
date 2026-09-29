# schema/

XSD definitions of the workload format (ADR-0008).

| File | Namespace | Content |
|-------|-----------|--------|
| `workload.xsd` | `urn:tardigrade:workload:v1` | workload, image, command, resources, mesh, readiness, volumes, devices, placement, dependencies |

From the XSD, `cargo xtask codegen` produces the types in
`crates/tg-defs/src/generated.rs`. The product is **checked in**;
`cargo xtask ci` checks with `codegen --check` that it matches the schema, and
aborts otherwise. With that the schema cannot silently diverge from the code —
the demand from ADR-0008.

## Supported XSD subset

This is the open point from ADR-0008 ("fix the supported XSD subset"), decided
here for phase 1. The list is **not** `xsd-parser`'s feature list but what we
have counter-tested with the facets preserved. Extensions belong together with a
fixture in `crates/tg-defs/tests/fixtures/`.

### Permitted

| Construct | Note |
|-----------|-----------|
| `xs:simpleType` with `xs:restriction` | basis for all facets below |
| `xs:sequence` with `maxOccurs="unbounded"` | becomes `Vec<T>`, see `<command><arg>` |
| `xs:pattern` | is **anchored** at codegen (`^(?:…)$`) |
| `xs:minLength`, `xs:maxLength` | |
| `xs:minInclusive`, `xs:maxInclusive` | on numeric base types |
| `xs:enumeration` | becomes a Rust `enum` |
| `xs:complexType` with `xs:sequence` | |
| `xs:choice` with `maxOccurs="unbounded"` | becomes `Vec<Enum>` |
| `xs:attribute` with `use="required"` / optional | |
| `minOccurs="0"` on elements | becomes `Option<T>` |
| `maxOccurs="unbounded"` on elements | becomes `Vec<T>` |
| base types `xs:string`, `xs:unsignedInt`, `xs:unsignedLong` | |

### Do not use

| Construct | Reason |
|-----------|-------|
| `xs:key`, `xs:keyref`, `xs:unique` | not evaluated by the codegen — referential integrity lies in the graph (ADR-0009, phase 3), not in the schema |
| substitution groups | not counter-tested |
| `xs:any`, `xs:anyAttribute` | opens the format; contradicts the purpose of schema strictness |
| `xs:redefine`, `xs:override` | not counter-tested |
| `default`/`fixed` on attributes | the codegen delivers `Option<T>`; default values belong in the domain layer, not in the schema |
| mixed content | without use for configuration |

## Two pitfalls that were expensive

**1. Facets can disappear silently.** `xsd-parser` has
`OptimizerFlags::USE_UNRESTRICTED_BASE_TYPE_SIMPLE` on by default. With that,
`WorkloadName` is flattened to `pub type WorkloadName = String` — pattern and
lengths are then without effect, without an error message.
`xtask/src/codegen.rs` switches the flag off; the fixtures under
`tests/fixtures/invalid/` cover every facet class, so that a relapse comes to
light.

**2. The root namespace is not checked by the product.** The deserializer checks
child elements against `NS_TG`, the root element it does not. Without a
counter-measure a `…:v2` definition would silently be read as v1. `tg-defs`
therefore checks the root itself before deserializing (`check_root`).

## Versioning

The namespace carries the schema version. An **incompatible** change gets a new
namespace (`urn:tardigrade:workload:v2`) and an XSD of its own; old definitions
are then cleanly refused instead of misinterpreted. Backwards-compatible
additions (a new optional element/attribute) stay in v1.

## Start command

`<command>` overrides the image's entrypoint and cmd (ADR-0003). If the element
is missing, the image's own setting applies.

It is a **list of `<arg>`**, not a string. A command line that is split only at
runtime would be an injection surface: there is no shell here that quotes or
expands. Every `<arg>` goes unchanged as one element into `process.args` of the
OCI spec — an argument with a space stays one argument.

The element was added in phase 2: without it the image alone dictates what runs,
and a workload could not be defined ready to start. The addition is additive and
optional, the namespace therefore stays `v1` (see versioning).

## Workload class

`class` answers exactly one question: may there be more than one active instance
cluster-wide? (ADR-0010)

| Value | Meaning |
|------|-----------|
| `replicated` | stateless/idempotent, no single-writer constraint; carries on on both sides of a partition. **Default.** |
| `single-writer` | at most one active instance cluster-wide; governance via a quorum-backed active-role lease with a fencing epoch (from phase 5) |

**Not to be confused with `kind`.** `kind` says *what* the workload is (a
long-running process or a one-off run), `class` says *how often* it may be
active at the same time. The axes are independent: `kind="service"` with
`class="single-writer"` is the normal case for a stateful service.

Single-writer is **opt-in**. If the attribute is missing, `replicated` applies —
the safe default, because it may carry on without quorum. The default
deliberately does **not** stand as `xs:default` in the schema but in the domain
layer (`tg_defs::WorkloadClass`), so that it is maintained in one place only.

## Mesh membership

The element `<mesh port="…"/>` is the opt-in from ADR-0025 — **its presence is
the statement**, there is no `enabled` attribute. A switch one can set to `false`
would be a second way of saying the same thing, and two ways contradict each
other sooner or later.

`@port` says on which port in the container the workload listens (ADR-0007).
`@udp` beside it is the second transport (ADR-0142), optional: without it
ADR-0074 applies unchanged and UDP between two workloads is discarded. What
does **not** stand here is "who may talk to whom" — those are `may_talk` edges
and thereby a relation between two workloads. They belong in the graph and not
in the definition of a single one: a definition that brought its own
permissions along would be one that unlocks itself.

## What is deliberately not validated here

The schema checks **structure and value ranges**. Not checked are:

- whether a `ref` in `<dependencies>` points at an existing workload,
- whether the ordering edges are free of cycles,
- whether `requires` is set without `after` (linter warning).

Those are graph properties over the set of all workloads. Per ADR-0009 they
belong in `tg-model` (phase 3).

The volume rules from ADR-0027 are out for the same reason, and one of them
additionally because XSD 1.0 cannot express it:

- that a writable volume is named by **one** workload and a shared one is
  read-only everywhere — a statement about the set, like the edges above,
- that a workload with a writable volume is node-pinned,
- that `@size` belongs to `readWrite` and `@source` to `readOnly`, each
  mandatory there and forbidden on the other. That is a statement about a
  single document and would fit in a schema — but XSD 1.0 knows no conditional
  attributes, so both stand as optional here and the pairing is checked in
  `tg_model::storage`.

## Changes to the schema

1. Adjust `workload.xsd`.
2. `cargo xtask codegen` — regenerate the product.
3. Add a fixture: for every new facet a valid **and** an invalid case.
4. `cargo xtask ci`.

For incompatible changes additionally: a new namespace, a new XSD, and pull
`NAMESPACE_V1` in `crates/tg-defs/src/lib.rs` along.
