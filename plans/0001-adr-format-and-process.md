# ADR-0001: ADR Format and Process

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

The project starts on a greenfield with many far-reaching, partly opposing
fundamental decisions (pure Rust, SurrealDB, SPIFFE, no eBPF). These decisions
must be documented traceably, versionably and revisably before any code
exists.

## Decision Drivers

- Decisions should live in the repo next to the code (Git history = decision history).
- Readable in under 5 minutes, no heavyweight documentation toolchain.
- Later revision ("superseded by") must be cleanly expressible.

## Options Considered

- **MADR** (Markdown Any Decision Records) — lightweight, option-oriented.
- **Nygard original** — minimalist (Context/Decision/Consequences).
- **RFC process** (long form, review-heavy).

## Decision

Chosen: **MADR variant** (see `0000-template.md`). Files under
`plans/NNNN-kebab-title.md`, numbered consecutively, immutable once
`accepted` (a change means a new ADR that `supersedes` the old one).

Status values: `proposed` → `accepted` | `rejected`, later `deprecated` |
`superseded`.

## Consequences

**Positive**
- Diffable, reviewable through ordinary PRs.
- The options stay documented, not just the outcome.

**Negative / Costs**
- Requires discipline: no silent course corrections without a new ADR.

## Related ADRs

- Foundation for everything that follows.
