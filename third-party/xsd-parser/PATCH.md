# Vendored: `xsd-parser` 1.5.2

Upstream: <https://github.com/Bergmann89/xsd-parser> ·
crates.io: `xsd-parser` 1.5.2 (2026-03-25) · Licence: unchanged upstream

Brought in via `[patch.crates-io]` in the workspace `Cargo.toml`.
Used exclusively by `xtask` (codegen driver) and goes into **no** delivery
binary.

## Occasion

See **ADR-0026** and `third-party/xsd-parser-types/PATCH.md`.

In short: the advisories RUSTSEC-2026-0194 and -0195 lie in `quick-xml < 0.41`.
`xsd-parser` has its **own direct** `quick-xml` dependency and exchanges
`Event` values with `xsd-parser-types`. If only the types crate is raised, the
build breaks with type conflicts:

```
error[E0053]: method `read_event` has an incompatible type for trait
  expected `xsd_parser_types::quick_xml::Event<'a>`,
     found `quick_xml::events::Event<'a>`
```

Both crates must therefore see the same `quick-xml` version.

## The patch

Complete. One line, no source change:

```diff
--- Cargo.toml
+++ Cargo.toml
@@ -106 +106 @@
 [dependencies.quick-xml]
-version = "0.38"
+version = "0.41"
```

## Deviation beyond that: thinned-out test data

The upstream test suite comprises 51 MB, predominantly `tests/schema/` (47 MB)
and `tests/feature/` (4.3 MB). That does not belong in this repo. Removed were:

- `tests/schema/`
- `tests/feature/`
- the test drivers directly in `tests/`

**Kept** are `tests/generator/`, `tests/optimizer/` and `tests/renderer/`
(together ~410 KB): the source pulls them into doc comments via `include_str!`;
without them the build fails with 72 errors.

The upstream tests are not run here anyway — behaviour changes are covered by
the fixture suite in `crates/tg-defs/tests/fixtures/`.

## Exit condition

As soon as upstream publishes a release with `quick-xml >= 0.41`:

1. remove both entries under `[patch.crates-io]` from the workspace
   `Cargo.toml`,
2. delete `third-party/`,
3. `cargo xtask ci`.

This directory is a bridge, not a fork. It is **not** developed further.

## Check when updating

```bash
diff -r <upstream-source> third-party/xsd-parser \
  --exclude=tests --exclude=target --exclude=Cargo.lock --exclude=PATCH.md
```

Expected: exactly the one line in `Cargo.toml`.
