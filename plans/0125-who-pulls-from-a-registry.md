# ADR-0125: Who Pulls From a Registry

- **Status:** accepted
- **Date:** 2026-09-13
- **Concerns:** ADR-0096 (registry credentials), ADR-0048 (the path of a
  warning), ADR-0041/0124 (the same letter-case trap one floor lower),
  ADR-0061 (the cascade), ADR-0003 (the puller)

## Context and Problem Statement

ADR-0096 left an open point:

> **`ClearRegistryCredential` does not check** whether a workload still pulls
> from this registry — unlike `RemoveSecret`.

Measured, the finding holds, and beside it lies a second one that weighs more.

### The measurement

```text
mappings before:  [("registry.example.com", "reg")]
clear yields:     Applied
mappings after:   []
api still declares: ["api"]
```

The next pull runs `RegistryAuth::Anonymous`, fails with `401`, ends up in
`report.failed` — and per ADR-0061 a `failed` drags **every dependent** with
it. The damage does not fall at the moment of issuing but at the next pull:
with `pullPolicy="always"` at the next start, otherwise only when the image is
no longer stored locally. To an operator it looks as if the registry were
broken.

### The second finding: the letter case

```text
set with capitals: Applied
stored as:         [("REGISTRY.example.com", "reg")]
```

`oci_client::Reference::registry()` returns the reference's letter case
**unchanged** (measured: `REGISTRY.example.com/api:1` →
`"REGISTRY.example.com"`), and `Registries::for_registry` looks up exactly in a
`BTreeMap`. A capital letter on either of the two sides therefore means:
**anonymous, and silently.**

That is verbatim the finding ADR-0041 already has for the SNI — *"whoever
compared letter by letter could be bypassed with a capital letter"* — and
`AllowEgress` therefore lowercases the name. `SetRegistryCredential` does not.
A registry host is a DNS name; DNS is case-insensitive.

### And a symmetry that is none

The note from ADR-0096 says "unlike `RemoveSecret`". Thinking the check
through, it turns out the two are **not** the same situation:

- `RemoveSecret` rejects because otherwise a **dangling reference** would arise
  — a mapping onto a secret that does not exist. That is provably wrong, there
  is no valid reading.
- `ClearRegistryCredential` leaves a **valid** state: "this registry is pulled
  from anonymously." That is the normal case for every public registry.

The state machine cannot know whether a registry needs a login. A prohibition
"as long as someone still pulls from it" would mean: a registry that has become
public can no longer be released until every workload is gone.

## Decision Drivers

- **A rejection needs certainty**, a hint only relevance. The certainty is
  missing here.
- **The intent is known only at the moment of the command.** Afterwards the
  state is indistinguishable from a legitimate one — a *standing* hint "this
  registry has no login" would be permanently true for `docker.io` and every
  other public one, so it would be noise. And an alert one cannot silence is
  one that gets switched off (ADR-0088).
- **The path for it is decided and built.** ADR-0048: the hint belongs in the
  **answer** of the admin service and not in the log — `WriteResult::Applied`
  already carries a `lints` field, with exactly this justification ("in five
  years an auditor would read warnings that were long since fixed").
- **The letter case is not a trade-off.** It is wrong.

## Options Considered

- **A — reject like `RemoveSecret`.** Consistent in wording, wrong in
  substance: the state afterwards is valid, and the prohibition would take away
  a legitimate path.
- **B — a standing lint.** It cannot express the situation: after the deletion
  it is indistinguishable from "public registry".
- **C — a hint in the answer to exactly this command** (ADR-0048).
- **D — do nothing and only fix the letter case.** Would leave the measured
  case standing.

Chosen is **C**, together with the normalization.

## Decision

### Determination 1 — the registry host is lowercased

`SetRegistryCredential` and `ClearRegistryCredential` normalize the host at
**ingest**, as `AllowEgress` does for the name. Lookup is lowercased likewise.

A registry host is a DNS name. Whoever compares letter by letter builds a login
that silently fails on a capital letter.

### Determination 2 — which registry a reference names is said by **one** place

The rule moves into `tg_model::egress::registry_of` — the same movement as the
address plan in ADR-0069 and the name comparison in ADR-0124, and for the same
reason: `tg-consensus` needs it for determination 3, `tg-runtime` for the pull,
and two versions would be two opportunities to disagree about the registry.

The rule is measured and not invented: the first component is the registry
exactly when it contains `.` or `:` or is called `localhost` — otherwise
`docker.io`. A **differential witness** in `tg-runtime` holds it against
`oci_client::Reference::registry()`, for the same library performs the pull
afterwards; if the two diverged, we would log in to a different registry than
the one we speak to.

### Determination 3 — the deletion is answered, not rejected

`ClearRegistryCredential` stays `Applied` and the answer names **who pulls
anonymously from now on** — the workloads whose image reference names this
registry.

The place is `WriteResult::Applied.lints` (ADR-0048): not in the `Outcome`, so
not in the log, for that is retained (ADR-0020) and a hint is a transient
statement. And not as a standing query, because the situation afterwards is
indistinguishable from a legitimate one.

If nobody pulls from this registry, nothing is stated. The hint is the answer to
a question the operator has just asked.

### Determination 4 — no standing lint for "registry without login"

Expressly **not** built, and the reason belongs written down so that nobody
takes it for a gap: it would be permanently true for every public registry. A
hint that always stands there is none.

### Determination 5 — the rejection from `RemoveSecret` stays as it is

The two cases are **not** symmetric, even if the note from ADR-0096 suggests
it: there a dangling reference arises, here a valid state. The wording "unlike
`RemoveSecret`" describes a difference that is correct.

## Consequences

**Positive**

- **A login no longer fails on a capital letter.** That is the part that can
  do damage today without anyone deleting anything.
- **Whoever removes a login learns what they are doing with it** — in the same
  breath, instead of weeks later from a `401` that looks like a registry
  outage.
- **The legitimate path stays open**: a registry that has become public can be
  released.
- **ADR-0048's first half gets its first user** beyond the graph lints — the
  field was there, only `lints_of` filled it.
- One rule, one place: `registry_of` replaces the second derivation before it
  exists.

**Negative / costs**

- **An old log replicates differently** (ADR-0112, ADR-0124): a
  `SetRegistryCredential` with capitals stores a different key from here on.
  The direction is the intended one — a mapping that silently never took effect
  now does — and it belongs nevertheless in the same coordinated window.
- **The hint is a statement about what the command effects**, not about the
  resulting set. `Applied.lints` therefore carries two sorts from here on; the
  field's documentation says so.
- **`registry_of` is our rule**, pinned by a witness over a table. A reference
  form that does not appear there and that `oci_client` reads differently would
  only stand out in operation.

**Risks & open points**

- **The hint reaches only whoever issues the command.** Whoever discards it in
  a script does not see it. Demanding a confirmation would be ADR-0027's
  `Confirmation`, and that lies expressly **not** in the log.
- **A workload that pulls its image from a different registry than the one its
  declaration names** does not exist — but a mirror or a redirect on the
  registry side would shift the mapping, and the cluster knows nothing of that.
- **The rotation of a credential** stays as ADR-0096 describes it: it takes
  effect at the next pull, not immediately.
- **No witness against a real private registry** — unchanged, the open point
  from ADR-0096.

## Related ADRs

- **Redeems:** **ADR-0096**, open point *"`ClearRegistryCredential` does not
  check"* — with a different means than presumed there, and with a second
  finding that weighs more than the first.
- **Applies:** **ADR-0048** (the path of a warning: into the answer, not into
  the log), **ADR-0069/0124** (one computation, one place), **ADR-0041** (the
  same letter-case trap), **ADR-0088** (a hint one cannot silence gets switched
  off).
- **Touches:** **ADR-0061** (the cascade is the reason why a failed pull is
  expensive), **ADR-0003** (the puller), **ADR-0112** (a stricter ingest means
  that an old log replicates differently).
