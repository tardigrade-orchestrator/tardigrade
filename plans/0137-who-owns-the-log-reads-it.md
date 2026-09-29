# ADR-0137: Whoever Owns the Log Reads It

- **Status:** accepted
- **Date:** 2026-09-14
- **Concerns:** ADR-0135 (the open point), ADR-0134 (the bill of materials),
  ADR-0020 (the export before the compaction), ADR-0044 ("The Operator
  Interface")

## Context and Problem Statement

ADR-0135 named two capabilities of `tgctl` that together carry 125 of the 368
crates, and left both open as a **product question**. One of them is decided
here.

### The measurement

```text
$ tgctl audit                      # while tgd is running
…/audit-1.jsonl
Records: 1
Chain: holds
exit=0                             # and tgd runs on

$ tgctl audit export               # while tgd is running
tgctl: log not openable: … Database already open. Cannot acquire lock.
Hint: `redb` lets exactly one process at the log. Is tgd still running?
```

**Inspecting and exporting are two different things**, and only the second
touches the log:

- `tgctl audit` recomputes the **archive** — an append-only file that arises in
  the apply path (phase 11a). No stop, no cluster, nothing.
- `tgctl audit export` opens the **Raft log** via `redb`, and that lets exactly
  one process at it. So it runs only with the node stopped — the manual has
  always written `systemctl stop tardigrade-tgd` before it.

### What that means for the layering

The export is the **recovery path**: ADR-0020 demands the export before the
compaction, and since phase 11a the archive already writes in the apply, before
`apply` returns — the normal case is thereby covered. What remains is the case
in which the archive is missing or `Archive::open` can no longer continue it.

For that the CLI linked `openraft` and `redb` — a measured **61 crates**, among
them `clap`, `rkyv`, `borsh`, `bitvec`, `rand` and `rust_decimal`. For a command
that runs on the same machine with the service stopped.

## Decision Drivers

- **Whoever owns the storage reads it.** The same layering rule as in ADR-0037
  and ADR-0135.
- **The obligation to stop does not change.** It comes from `redb`, not from
  which binary carries the command — the relocation costs nothing
  operationally.
- **A CLI that brings a consensus core along is supply-chain surface without a
  return** (ADR-0023, ADR-0134).

## Options Considered

- **A — change nothing.** Inspecting works while running, exporting is recovery;
  the 61 crates stay.
- **B — move it:** `tgd --audit-export`. Operationally unchanged, the CLI loses
  the storage engine.
- **C — additionally an export over the admin socket while running.** Would
  remove the obligation to stop for the rare case "archive broken, node
  healthy" — and would cost the first server-streaming call on the admin service
  (a log range can blow the 32 MiB message limit) plus a path that hands out
  **log content** over that socket.

Chosen is **B**. **C** stays open and is named below.

### Determination 1 — the export is a one-shot mode of `tgd`

`tgd --audit-export [--audit-from n] [--audit-to n] [--audit-anchor hex]`
writes the segment to **stdout** and ends. It runs **before** the service: the
same log `run` would open in a moment, and `redb` lets only one at it.

Everything accompanying goes to **stderr** — otherwise it would stand in the
file an operator redirects into, and that would then be no segment.

### Determination 2 — `tgctl audit export` is dropped without replacement

No alias, no forwarding. A subcommand that only names another invocation is a
second name for the same thing — and this tree has already struck one for that
reason once (`tgctl evidence`, after ADR-0044).

What `tgctl audit` **can** do stays untouched: recompute the chain, with and
without a file, while running. That is the command an auditor uses.

### Determination 3 — what moves along, so that the CLI loses the core

Three small things still hung on the consensus core, and all three belong
elsewhere:

- **`generate_token` / `token_digest`** → `tg_identity::join`. They belong to
  the credential path (ADR-0037): `tgctl node invite` creates the token, `tgd`
  checks it against the digest in the log.
- **`Event`** → `tg_model::command::AuditEvent`. It names a command, an outcome
  and an actor; all three have lain there since ADR-0135.
- **The archive's read path** is taken in `tgctl` directly from `tg-telemetry`
  instead of via the consensus core's re-export.

All three stay reachable under their old path (re-export) — one source under
several names.

### Determination 4 — in the test harness the core stays permitted

`tg-consensus` becomes a **dev dependency** of `tgctl`: the witnesses build
their archives with the **real** writer instead of reproducing its output. What
is shipped is untouched by that — the bill of materials does not count dev and
build dependencies (ADR-0134, determination 3), and that is exactly what it
demonstrates here.

The two witnesses of the export move to `tgd`. The decisive one stays what it
was: the exported segment is checked with **the same** function `tgctl audit`
calls — a witness that checked its own reproduction would prove nothing (11c).

## Consequences

**Positive**

- **`tgctl` carries 307 instead of 368 crates** and neither `openraft` nor
  `redb`.

  > **The second half of the sentence holds, the first had to be re-measured.**
  > `openraft` and `redb` are gone, and a witness records it. The *number*
  > stood on a bill of materials that counted 28 unshipped packages
  > (correction to ADR-0134); filtered correctly, `tgctl` carries **294**
  > against 276 for `tgd`, and `cargo tree` independently says 293 against 270.
  >
  > With that the assurance this ADR reversed was false too: the CLI **still
  > carries more** than the control plane. The reason has changed — it was the
  > consensus core, today it is `tg-runtime`, that is, ADR-0135's **second**
  > capability (reconcile locally) together with the image puller, `zstd`,
  > `tar` and `aws-lc-rs`. This ADR removed only the first and claimed only
  > that for itself; the assurance was the over-interpretation, not the
  > decision.
  Measured, against the bill of materials.
- **The layering is right here too:** no client links a storage it can only read
  under an exclusive lock.
- **The separation becomes visible:** inspecting is `tgctl`, recovering is
  `tgd`.

**Negative / costs**

- **An operator types a different binary for the export.** That is muscle memory
  and manual work; the procedure (stop the service, pull a range, check) does
  not change.
- **`tgd` has a mode that is not a service.** It stands before the start and
  ends; `--init` was the first of this kind.
- **The flag names carry a prefix** (`--audit-from` instead of `--from`),
  because they stand in a binary that already has two dozen.

**Risks & open points**

- **Option C stays open**: an export while running over the admin socket. It
  would remove the obligation to stop for "archive broken, node healthy" — and
  demands a streaming call as well as a decision that this socket hands out log
  content (ADR-0044: whoever reaches it may do anything).
- **`tgctl apply` stays as it is** (ADR-0135, second open point): the 57 crates
  of `tg-runtime` hang on the single-node path from phase 2, and that is a
  different question.
- **The export stays without outcomes** (ADR-0045): the log carries commands,
  not results. The note about it stands on stderr so that nobody takes it for a
  repair.

## Related ADRs

- **Decides** the first of the two open points from **ADR-0135**.
- **Demonstrates** the promise from **ADR-0134**: the bill of materials counts
  what is shipped — and it shows the difference.
- **Applies:** **ADR-0037** (whoever owns the storage reads it) and **ADR-0020**
  (the export before the compaction).
