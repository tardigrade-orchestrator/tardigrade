# ADR-0023: Supply-Chain Governance

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

DORA demands manageable ICT third-party and concentration risk plus exit
strategies. For a Rust system that means: control and document the crate supply
chain.

## Decision

- **SBOM** generation as a build artefact (CycloneDX).
- **`cargo-deny`** in CI: licence policy, RUSTSEC advisories, permitted sources,
  duplicate/ban rules (already part of the definition of done in `CLAUDE.md`).
- **Pinning/vendoring** of critical crates (consensus, crypto, runtime): exact
  versions, optionally vendored, to make availability independent of registry
  uptime.
- **Exit strategy / concentration risk** documented per critical dependency (e.g.
  `openraft` → `raft-rs`, `frost-ed25519` → an alternative threshold
  implementation, youki → crun): what to do if a dependency dies.
- **Reproducible builds** as a goal (a pinned toolchain, `--locked`).

## Consequences

**Positive**
- Supply-chain transparency and documented exit paths = direct DORA evidence.
- Vendoring decouples builds from registry availability.

**Negative / Costs**
- Maintaining the SBOM, the deny policy and the exit documentation is ongoing effort.

**Risks & Open Points**
- ~~The extent of vendoring (everything vs. only critical crates).~~ — **done:**
  ADR-0026 — only the critical path (`xsd-parser`).
- The degree of reproducibility (bit-for-bit vs. "locked").

## Related ADRs

- Anchored in `CLAUDE.md` (the definition of done). The exit paths reference:
  ADR-0005, ADR-0014, ADR-0003.
