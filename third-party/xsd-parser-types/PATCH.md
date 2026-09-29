# Vendored: `xsd-parser-types` 0.2.1

Upstream: <https://github.com/Bergmann89/xsd-parser> ·
crates.io: `xsd-parser-types` 0.2.1 (2026-03-25) · Licence: unchanged upstream

Brought in via `[patch.crates-io]` in the workspace `Cargo.toml`.

## Occasion

`cargo deny` reported two RUSTSEC advisories on the definition ingest path:

| ID | Content |
|----|---------|
| RUSTSEC-2026-0194 | quadratic run time in the duplicate-attribute check |
| RUSTSEC-2026-0195 | unbounded namespace allocation in `NsReader` → OOM DoS |

Both are fixed in `quick-xml >= 0.41.0`. `xsd-parser-types` 0.2.1 pins
`quick-xml = "0.38"`, and `xsd_parser_types::SliceReader` builds directly on
`NsReader` — the whole deserialization path of `tg-defs` was affected. Since
2026-03-25 there has been no upstream release.

Decision and weighing: **ADR-0026**.

## The patch

Complete. One line, no source change:

```diff
--- Cargo.toml
+++ Cargo.toml
@@ -83 +83 @@
 [dependencies.quick-xml]
-version = "0.38"
+version = "0.41"
```

The `quick-xml` surface used by `xsd-parser-types` comprises five symbols —
`Error`, `events::Event`, `name::*`, `NsReader::resolve*`, `Serializer` — which
are unchanged between 0.38 and 0.41. Crate and generator build without
adaptation.

## Exit condition

As soon as upstream publishes a release with `quick-xml >= 0.41`:

1. remove `[patch.crates-io]` from the workspace `Cargo.toml`,
2. delete `third-party/xsd-parser-types/`,
3. raise the version in `crates/tg-defs/Cargo.toml`,
4. `cargo xtask ci`.

This directory is a bridge, not a fork. It is **not** developed further —
changes to the behaviour belong upstream.

## Check when updating

- Form a diff against the new upstream version; this patch may stay the only
  deviation.
- `cargo xtask ci` — the fixtures in `crates/tg-defs/tests/fixtures/` cover
  every facet class and bite when the parse behaviour changes.
