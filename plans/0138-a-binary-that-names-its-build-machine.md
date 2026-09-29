# ADR-0138: A Binary That Names Its Build Machine

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0023 (supply-chain governance: "reproducible"), ADR-0134
  (the bill of materials and its open point), ADR-0020 (what may stand in a
  retained log), ADR-0082 (the same profile, a different question)

## Context and Problem Statement

ADR-0023 names **reproducible builds** among its deliverables. ADR-0134 built
the bill of materials and wrote about it:

> **Reproducible builds** from ADR-0023 are still not substantiated. The bill of
> materials is the precondition for it and not the proof.

Measured, the sentence is too friendly: it was not the proof that was missing,
it was the property.

### The measurement

`tg-proxy`, release profile, with exactly **one** thing different each time:

```text
run 1  /root/tardigrade  → /root/tg-r1        42cee6c2…
run 2  different target directory             42cee6c2…   same
run 3  different source path (/root/tg-src2)  42cee6c2…   same
run 5  different CARGO_HOME                   d5e16e0d…   DIFFERENT
```

Source path, target directory and clock are without consequence — that is the
good half, and it was not self-evident. The **home directory of the build
machine** is not.

### Why

The paths of the dependency sources stand in the shipped binary. They are the
`file!()` locations of their `panic!`, `assert!` and `expect` sites:

```text
/root/.cargo/registry/src/index.crates.io-…/openraft-0.9.25/src/config/config.rs
```

Counted over the delivery:

| Binary | absolute paths of the build machine |
|---|---|
| `tgd` | 633 |
| `tg-agent` | 823 |
| `tgctl` | 492 |
| `tg-proxy` | 407 |

**2355 of them.** Our **own** crates contribute **zero** — they are compiled
with relative paths, and that is why run 1 and run 3 are the same. It is not we
who are the error but what we ship along.

`strip = true` (ADR-0082) clears away the debug information and **not these
paths**: they are not debug trimmings but strings in the program text that a
panic prints.

### What that costs beyond reproducibility

A panic from a dependency prints, in operation, the home directory of the
machine on which it was built — into a stream ADR-0020 retains. That is not a
security hole and nevertheless information about the build environment that
nobody wanted to give.

## Decision Drivers

- **DORA asks whether what is shipped corresponds to the source state** — and
  the answer is a second build, not a promise.
- **A reproducibility that hangs on a user account is none.** On a build server
  the directory is called something else than on a developer's machine.
- **No second toolchain** (ADR-0023, ADR-0134).
- **No nightly toolchain.** The rule has stood since 11c: a checking artifact
  that presupposes nightly is one that eventually nobody can produce any more.

## Options Considered

- **A — do nothing** and pass the point on. It has stood since ADR-0023 and has
  survived three ADRs since.
- **B — `profile.release.trim-paths = "all"`**, Cargo's own way. **Measured to
  be barred:** `feature 'trim-paths' is required … not stabilized in this
  version of Cargo (1.97.1)`. Nightly is excluded.
- **C — `--remap-path-prefix` via `RUSTFLAGS`**, computed from `CARGO_HOME`, in
  a named build step.
- **D — C, but as a constant in `.cargo/config.toml`.** The value contains
  **this** machine's home directory; on any other it would match nothing and
  stay without effect — without an error message.

Chosen is **C**. **B** replaces it as soon as it is stable (determination 6).
**D** is rejected, and not as the weaker variant but because it is **silently**
wrong: it would look like diligence and would work only for whoever wrote it.

### Determination 1 — the shipping build is an action with a name

`cargo xtask release` builds the four shipping units in the release profile with
the remap and names their digests.

Whoever runs `cargo build --release` by hand still gets a runnable binary — but
one that names its build machine. That is a development build and not a shipping
artifact, and from here the difference has a name.

### Determination 2 — the prefix is computed, not written

It comes from `CARGO_HOME`, failing that `$HOME/.cargo`. That is exactly the
path `cargo` passes to the compilations of the dependencies; any other would
match nothing.

### Determination 3 — the target is `/cargo`, and the panic stays readable

```text
before:  /root/.cargo/registry/src/index.crates.io-…/openraft-0.9.25/src/…
after:   /cargo/registry/src/index.crates.io-…/openraft-0.9.25/src/…
```

Crate, version, file and line survive — they are the diagnosis. Only the machine
goes. The standard library is already built that way (`/rustc/<commit>`); the
target follows the same form instead of inventing a second one.

### Determination 4 — the run checks its own product

After the build each of the four binaries is searched for the home directory and
for the workspace root. A find is a failure.

Without this counter-check the flag would be a **claim** — and a flag that
silently no longer arrives (a renamed switch, a `RUSTFLAGS` that the environment
overrides) is exactly the kind of error this tree has measured several times.
The check is at the same time the proof that the 2355 paths have fallen to
**zero**.

### Determination 5 — the digests are printed, not checked in

Reproducibility is a statement about **two runs**, not about a number in the
repo. A checked-in digest would hang on the patch version of the toolchain and
on every `Cargo.lock` change and would be red the day after its commit — the
opposite of what ADR-0134 determination 4 achieved for the bill of materials.

What is checked in is the **precondition**, and it already stands:
`rust-toolchain.toml` (pinned, with exactly this justification in its header)
and `Cargo.lock`.

### Determination 6 — `trim-paths` is the later way, and the note says so

As soon as `profile.*.trim-paths` is stable, it replaces `RUSTFLAGS`, and the
flag is dropped. The property stays the same; what changes is only who carries
it. The note stands at the code and not merely here.

### Determination 7 — the list of shipping units has one place

`cargo xtask release` builds **the same** four packages `cargo xtask sbom`
counts — from the same constant. Two lists would be two opportunities for the
bill of materials to describe something other than what was built (ADR-0069: one
derivation, one place).

## Consequences

**Positive**

- **Two runs yield the same binary**, across different source paths, target
  directories, `CARGO_HOME`s and points in time — measured for all four units.
- **Zero paths of the build machine in the shipped product.** No `/root`, no
  `/home`, no `/tmp`.
- **The first deliverable from ADR-0023 that was still open is redeemed** —
  with a run and not with a sentence.
- Incidentally 4 to 8 KiB smaller per binary: the mapped paths are shorter.

**Negative / costs**

- **One more build path an operator must know.** That is exactly why it has a
  name and stands in the manual.
- **The run is not in the gate.** It builds release (about three minutes), and
  the gate already runs the full suite — the same situation as with `bench`.
  What holds it is its own counter-check and a witness that binds usage help and
  manual to it.
- **`RUSTFLAGS` applies to everything**, including build scripts and proc
  macros. Without consequence here; mentioned so that nobody takes it for an
  oversight.

**Risks & open points**

- **The check finds what it looks for: a string.** A path in a compressed
  section would escape it. Today there is none — the transition 2355 → 0 is
  measured.
- **Two different machines were not compared.** What is measured is two source
  paths, two `CARGO_HOME`s, three target directories and four points in time on
  **one** machine. What carries beyond that hangs on the pinned toolchain — and
  that is checked in.
- **Machine properties beyond the paths** (hostname, user, timezone, locale) are
  not excluded, merely have not occurred.
- **`cargo-auditable`** stays open as in ADR-0134: an imprint **in** the binary
  would bind the bill of materials to the artifact instead of to the repository.
  One tool more, and not decided.
- ~~**Our own licence** stays the second open point from ADR-0134: fourteen
  components of the bill of materials stand as `NOASSERTION`, and they are
  ours.~~ — **decided and built: ADR-0139** (Apache-2.0).

## Related ADRs

- **Redeems the last open deliverable from ADR-0023** and closes the
  corresponding open point from **ADR-0134**.
- **Touches ADR-0082** (the same release profile, a different question: `strip`
  clears away the debug information and not these paths).
- **Touches ADR-0020**: what a panic writes into a retained stream.
- **Applies:** **ADR-0069** (one derivation, one place) for the list of shipping
  units.
