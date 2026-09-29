# ADR-0124: A Star That Permits Nothing

- **Status:** accepted
- **Date:** 2026-09-13
- **Concerns:** ADR-0041 (the egress allowlist), ADR-0092 (the UDP transport),
  ADR-0025 (the care with selectors), ADR-0013 (forwarding in the resolver),
  ADR-0112 (what a changed ingest means for an old log)

## Context and Problem Statement

ADR-0041 built the allowlist and left an open point:

> **Wildcards in the allowlist** (`*.s3.example.com`): necessary for some
> providers, dangerous as a habit. Whether and how they are permitted is to be
> decided — with the same care as the prefix selectors in ADR-0025.

Measured, the situation is not "not yet decided" but **accepted and without
effect**.

### The measurement

```text
parsed: [("*.s3.example.com", 443, Tcp), ("s3.example.com", 443, Tcp)]
  permits(mybucket.s3.example.com) = false
  permits(a.b.s3.example.com)      = false
  hosts(): ["*.s3.example.com", "s3.example.com"]
```

**Nobody rejects them.** `AllowEgress` does not check `host` at all — no test
for a DNS name, nothing. The command goes into the log, which is
retention-bound (ADR-0020), travels along in the slice, lands in the file the
sidecar reads, and appears in `hosts()`. The operator gets `Applied`.

**And it has no effect anywhere.** `permits` compares exactly — rightly so:
that is the finding from 10d, `evil-s3.example.com` ends with `s3.example.com`
and is a different target. The permitted target is thereby forbidden.

**It is silent twice, not once.** `Forwarding::allows` in the node-local
resolver compares exactly as well (ADR-0041, determination 6). The container
therefore gets **no** TLS error but a DNS error — the diagnosis points at the
wrong place, and whoever follows it looks at the resolver instead of at the
permission.

**With `udp` it is worse than ineffective.** There the **agent** resolves the
name itself and lays down an nftables rule per address (ADR-0092,
determination 5). A wildcard does not resolve, and an unresolved target leaves
the rule set as it is — fail-static (ADR-0019). A single star in a `udp` line
thereby freezes **every further rule change of this workload**.

### A refuted hypothesis

The obvious suspicion was a hole: `permits("*.s3.example.com")` is `true`, so a
container that literally sends this SNI would get free passage to everything
the name points at. Measured against a real `ClientHello` whose SNI was
swapped for an **equally long** name with a star, `rustls` rejects it:

```text
  peek(real) = Named("x.s3.example.com")
  peek(star) = NotTls
```

The entry is dead weight, not a way in. That changes nothing about the finding
and belongs here so that nobody suspects it anew.

### What the exact comparison costs

With virtual-hosted-style S3 the bucket stands **in the name**. Every bucket
therefore needs its own `AllowEgress` — a cluster-wide log entry, for an action
that is otherwise one line in a form. That is the need ADR-0041 meant with
"necessary for some providers".

## Decision Drivers

- **What cannot take effect must not be called `Applied`.** A permission that
  is accepted and permits nothing is the worst information an operating system
  can give — and it then lies in the audit trail.
- **The care from ADR-0025 is one about boundaries**, not about characters: the
  finding there is "a prefix is not a name" (`api-test` does not get what `api`
  is permitted). The counterpart in DNS is the **label boundary** — the same
  finding as with our own zone in phase 9a.
- **A wildcard does not shift the trust boundary but widens the set.** Where
  `s3.example.com` points is said by DNS anyway; ADR-0041 rejected the address
  list for exactly that reason. What is new is not whom we trust but how many
  names the permission covers.
- **One comparison, two places.** What the sidecar permits and what the
  resolver forwards must answer the same question the same way. The measured
  state is what happens when they do not.

## Options Considered

- **A — forbid wildcards permanently**, and reject at ingest. Safe and honest;
  leaves "necessary for some providers" unanswered and makes the creation of a
  bucket a consensus write.
- **B — wildcards as a suffix comparison** (`ends_with`). Rejected, and on the
  finding that has already cost money twice: `evil-s3.example.com` ends with
  `s3.example.com`.
- **C — wildcards in the form the ecosystem knows** (RFC 6125): exactly one
  `*`, as the **whole** leftmost label, and it covers **exactly one** label.
- **D — arbitrary patterns** (glob, regular expression). Rejected: a perimeter
  boundary whose reach one learns only by trial is none.

Chosen is **C**, together with the ingest check from **A** for everything that
does not fit this form.

## Decision

### Determination 1 — `AllowEgress` checks the name, and a rejection names the reason

The state machine rejects a name that is not a DNS name and not a wildcard per
determination 2. What cannot take effect does not reach the state.

The check happens at **ingest** and not at the access point: the attempt
belongs in the audit trail (11a), and provenance must not be part of the
decision (ADR-0050/0105) — the same construction as with ADR-0112.

### Determination 2 — a wildcard is a whole label, leftmost, and covers exactly one

Permitted is exactly the form `*.<rest>`, with:

- **exactly one** `*`, and it is the **complete** leftmost label — no
  `ab*.s3.example.com`, no `*ab.s3.example.com`;
- at least **two** further labels behind it, so never `*.com` and never `*`;
- and it covers **exactly one** label: `mybucket.s3.example.com` yes,
  `a.b.s3.example.com` **no**.

That is the form from RFC 6125 that every TLS certificate in the world uses —
hence the one about whose reach nobody is mistaken. And it is the translation
of ADR-0025's care into DNS: the boundary lies at a label, not at a character.

### Determination 3 — it does not cover the name itself

`*.s3.example.com` does **not** permit `s3.example.com`. Whoever means both
writes both.

That too is RFC 6125, and it is the safe direction: the name without a label in
front is often something different from its children — with S3 the account
administration instead of a bucket.

### Determination 4 — for `udp` it stays forbidden

There the agent resolves the name itself (ADR-0092, determination 5), and a
wildcard does not resolve. Measured, that costs not only this one rule: an
unresolved target leaves the rule set standing (fail-static, ADR-0019), so it
freezes every further change of this workload.

The rejection says so — "for `udp` there is no wildcard, because the node must
resolve the name".

### Determination 5 — one comparison, at both places

`EgressPolicy::permits` and `Forwarding::allows` use **the same** function. A
wildcard that applies at only one of the two is the measured state in another
shape — permitted and not resolvable, or resolvable and not permitted.

The function therefore lies where both can reach it, and has its own tests: it
is pure logic, and a comparison that can only be checked in the end-to-end
setup is one whose rejection paths nobody has ever seen.

### Determination 6 — otherwise the comparison stays as it is

Without a star, comparison is still **exact**, lowercased. No `ends_with`, no
`starts_with`. The star is the only relaxation, and it is expressly written
down.

## Consequences

**Positive**

- **A permission that permits nothing no longer exists.** The operator learns
  it on issuing and not weeks later from a DNS error in a container.
- **The way to S3 is walkable**, without every bucket costing a consensus
  write.
- **The reach is the one everyone knows.** Whoever has ever read a certificate
  knows what `*.s3.example.com` covers and what it does not.
- **The `udp` pitfall is closed**, and at the place at which it arises.

**Negative / costs**

- **A wildcard is a larger permission**, and it becomes a habit once one has
  it. The ADR makes it narrow and not convenient; a determination cannot do
  more.
- **An old log replicates differently** — the same as with ADR-0112: what used
  to be `Applied` is rejected. The difference here is **provably ineffective**:
  a rejected entry is exactly one that never permitted a connection. It belongs
  nevertheless in the same coordinated window as a format change.
- **The check is a second place at which a name is judged** — beside the
  resolver, which resolves it. It judges the **form**, however, and not the
  existence; whether the name exists is still said only by DNS.

**Risks & open points**

- **Whoever permits `*.s3.example.com` permits every bucket of that provider**
  — foreign ones too. That is the property, not an error: with virtual-hosted
  style addressing the bucket name is a label, and this boundary does not get
  finer than a label. Whoever means individual buckets writes individual lines.
- **A second star stays forbidden**, and with it cases like `*.*.example.com`.
  Whether there is ever a need for that is not measured; what is decided is the
  narrow form.
- **Encrypted Client Hello** stays open as in ADR-0041: if the SNI disappears,
  this whole axis loses its pivot — wildcard or not.

## Related ADRs

- **Redeems:** **ADR-0041**, open point *"Wildcards in the allowlist"* — and
  the finding was that they have long been accepted and do nothing.
- **Applies:** **ADR-0025** (the care with selectors, here at the label
  boundary instead of the character), **ADR-0013** (the resolver forwards what
  is permitted — now with the same function), **ADR-0019** (fail-static is the
  reason why an unresolvable `udp` target is so expensive).
- **Bounds:** **ADR-0092**, determination 5 — for `udp` there is no wildcard.
- **Shares the price with:** **ADR-0112** — a stricter ingest means that an old
  log replicates differently.
